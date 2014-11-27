/************************************************************************
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
 * 
 * Copyright 2008 Sun Microsystems, Inc. All rights reserved.
 * Copyright 2009 IBM. All rights reserved.
 * 
 * Use is subject to license terms.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0. You can also
 * obtain a copy of the License at http://odftoolkit.org/docs/license.txt
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ************************************************************************/
package org.odftoolkit.odfdom.doc;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.JarURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.Source;
import javax.xml.transform.TransformerException;
import javax.xml.transform.URIResolver;
import javax.xml.transform.stream.StreamSource;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.odftoolkit.odfdom.OdfAttribute;
import org.odftoolkit.odfdom.OdfElement;
import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.OdfNamespace;
import org.odftoolkit.odfdom.doc.draw.OdfDrawFrame;
import org.odftoolkit.odfdom.doc.draw.OdfDrawImage;
import org.odftoolkit.odfdom.doc.office.OdfOfficeBody;
import org.odftoolkit.odfdom.doc.office.OdfOfficeMasterStyles;
import org.odftoolkit.odfdom.doc.office.OdfOfficeStyles;
import org.odftoolkit.odfdom.dom.attribute.office.OfficeVersionAttribute;
import org.odftoolkit.odfdom.dom.attribute.text.TextAnchorTypeAttribute;
import org.odftoolkit.odfdom.dom.element.draw.DrawPageElement;
import org.odftoolkit.odfdom.dom.element.table.TableTableCellElement;
import org.odftoolkit.odfdom.dom.element.text.TextPElement;
import org.odftoolkit.odfdom.pkg.OdfPackage;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;
import org.xml.sax.Attributes;
import org.xml.sax.ContentHandler;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

public abstract class OdfDocument {
	// Static parts of file references

	private static final String TWO_DOTS = "..";
	private static final String SLASH = "/";
	private static final String COLON = ":";
	private static final String EMPTY_STRING = "";
	private String mDocumentPathInPackage = EMPTY_STRING;

	/**
	 * This enum contains all possible standardized XML ODF files of the OpenDocument document.
	 */
	public enum OdfXMLFile {

		CONTENT("content.xml"),
		META("meta.xml"),
		SETTINGS("settings.xml"),
		STYLES("styles.xml");
		private final String mFileName;

		/**
		 * @return the file name of xml files contained in odf packages.
		 */
		public String getFileName() {
			return mFileName;
		}

		OdfXMLFile(String fileName) {
			this.mFileName = fileName;
		}
	}

	/**
	 * This enum contains all possible media types of OpenDocument documents.
	 */
	public enum OdfMediaType {

		CHART("application/vnd.oasis.opendocument.chart", "odc"),
		//        CHART_TEMPLATE("application/vnd.oasis.opendocument.chart-template", "otc"),
		//        FORMULA("application/vnd.oasis.opendocument.formula", "odf"),
		//        FORMULA_TEMPLATE("application/vnd.oasis.opendocument.formula-template", "otf"),
		GRAPHICS("application/vnd.oasis.opendocument.graphics", "odg"),
		//        GRAPHICS_TEMPLATE("application/vnd.oasis.opendocument.graphics-template", "otg"),
		//        IMAGE("application/vnd.oasis.opendocument.image", "odi"),
		//        IMAGE_TEMPLATE("application/vnd.oasis.opendocument.image-template", "oti"),
		PRESENTATION("application/vnd.oasis.opendocument.presentation", "odp"),
		//        PRESENTATION_TEMPLATE("application/vnd.oasis.opendocument.presentation-template", "otp"),
		SPREADSHEET("application/vnd.oasis.opendocument.spreadsheet", "ods"),
		//        SPREADSHEET_TEMPLATE("application/vnd.oasis.opendocument.spreadsheet-template", "ots"),
		TEXT("application/vnd.oasis.opendocument.text", "odt");
		//        TEXT_MASTER("application/vnd.oasis.opendocument.text-master", "odm"),
		//        TEXT_TEMPLATE("application/vnd.oasis.opendocument.text-template", "ott"),
		//        TEXT_WEB("application/vnd.oasis.opendocument.text-web", "oth");
		private final String mMediaType;
		private final String mSuffix;

		OdfMediaType(String mediaType, String suffix) {
			this.mMediaType = mediaType;
			this.mSuffix = suffix;
		}

		public String getName() {
			return mMediaType;
		}

		public String getSuffix() {
			return mSuffix;
		}

		public static OdfMediaType getOdfMediaType(String mediaType) {
			String mediaTypeShort = mediaType.substring(mediaType.lastIndexOf(".") + 1, mediaType.length());
			mediaTypeShort = mediaTypeShort.replace('-', '_').toUpperCase();
			OdfMediaType odfMediaType = OdfMediaType.valueOf(mediaTypeShort);
			if (odfMediaType == null) {
				throw new IllegalArgumentException("Given mediaType '" + mediaType + "' is not an ODF mediatype!");
			}
			return odfMediaType;
		}

		@Override
		public String toString() {
			return mMediaType;
		}
	}

	/**
	 * Creates one of the ODF documents based a given mediatype.
	 *
	 * @param odfMediaType The ODF Mediatype of the ODF document to be created.
	 * @return The ODF document, which mediatype dependends on the parameter
	 */
	private static OdfDocument newDocument(OdfMediaType odfMediaType, OdfPackage pkg) {
		OdfDocument newDoc = null;
		if (odfMediaType.equals(OdfMediaType.TEXT)) {
			newDoc = new OdfTextDocument();
		} else if (odfMediaType.equals(OdfMediaType.SPREADSHEET)) {
			newDoc = new OdfSpreadsheetDocument();
		} else if (odfMediaType.equals(OdfMediaType.PRESENTATION)) {
			newDoc = new OdfPresentationDocument();
		} else if (odfMediaType.equals(OdfMediaType.GRAPHICS)) {
			newDoc = new OdfGraphicsDocument();
		} else if (odfMediaType.equals(OdfMediaType.CHART)) {
			newDoc = new OdfChartDocument();
		}
		newDoc.setMediaType(odfMediaType);
		newDoc.setPackage(pkg);
		return newDoc;
	}
	private OdfMediaType mMediaType;
	private OdfPackage mPackage;
	private OdfOfficeStyles mDocumentStyles;
	private OdfFileDom mContentDom;
	private OdfFileDom mStylesDom;
	private StringBuilder mCharsForTextNode = new StringBuilder();
//    private OdfFileDom mSettingsDom;
//    private OdfFileDom mMetaDom;
	private XPath mXPath;
	private Map<String, OdfDocument> mCachedDocuments = new HashMap<String, OdfDocument>();
	private OdfDocument mRootDocument;

	static protected class Resource {

		private String name;

		public Resource(String name) {
			this.name = name;
		}

		public InputStream createInputStream() {
			InputStream in = OdfDocument.class.getResourceAsStream(this.name);
			if (in == null) {
				Logger.getLogger(OdfDocument.class.getName()).log(Level.SEVERE,
						"Could not find resource: " + this.name);
			}
			return in;
		}
	}

	/**
	 * Loads an OpenDocument from the given resource
	 * @param res a resource containing the document
	 * @return the OpenDocument document
	 * @throws java.lang.Exception - if the document could not be created.
	 */
	static protected OdfDocument loadTemplate(Resource res) throws Exception {
		InputStream in = res.createInputStream();
		OdfPackage pkg = null;
		try {
			pkg = OdfPackage.loadPackage(in);
		} finally {
			in.close();
		}
		OdfMediaType odfMediaType = OdfMediaType.getOdfMediaType(pkg.getMediaType());
		if (odfMediaType == null) {
			throw new IllegalArgumentException("Document contains incorrect ODF Mediatype '" + pkg.getMediaType() + "'");
		}
		return newDocument(odfMediaType, pkg);
	}

	/**
	 * Loads an OdfDocument from the provided path.
	 *
	 * <p>OdfDocument relies on the file being available for read access over
	 * the whole lifecycle of OdfDocument. Please refer to the documentation
	 * of the save methods to decide whether overwriting the input file
	 * is allowed.</p>
	 *
	 * @param path - the path from where the document can be loaded
	 * @return the OpenDocument from the given path
	 * @throws java.lang.Exception - if the document could not be created.
	 */
	public static OdfDocument loadDocument(String path) throws Exception {
		OdfPackage pkg = OdfPackage.loadPackage(path);
		OdfMediaType odfMediaType = OdfMediaType.getOdfMediaType(pkg.getMediaType());
		if (odfMediaType == null) {
			throw new IllegalArgumentException("Document contains incorrect ODF Mediatype '" + pkg.getMediaType() + "'");
		}
		return newDocument(odfMediaType, pkg);
	}

	/**
	 * Creates an OdfDocument from the OpenDocument provided by a resource Stream.
	 *
	 * <p>Since an InputStream does not provide the arbitrary (non sequentiell)
	 * read access needed by OdfDocument, the InputStream is cached. This usually
	 * takes more time compared to the other loadDocument methods.
	 * An advantage of caching is that there are no problems overwriting
	 * an input file.</p>
	 *
	 * @param inStream - the InputStream of the ODF document.
	 * @return the document created from the given InputStream
	 * @throws java.lang.Exception - if the document could not be created.
	 */
	public static OdfDocument loadDocument(InputStream inStream) throws Exception {
		return loadDocument(OdfPackage.loadPackage(inStream));
	}

	/**
	 * Creates an OdfDocument from the OpenDocument provided by a File.
	 *
	 * <p>OdfDocument relies on the file being available for read access over
	 * the whole lifecycle of OdfDocument. Please refer to the documentation
	 * of the save methods to decide whether overwriting the input file
	 * is allowed.</p>
	 *
	 * @param file - a file representing the ODF document.
	 * @return the document created from the given File
	 * @throws java.lang.Exception - if the document could not be created.
	 */
	public static OdfDocument loadDocument(File file) throws Exception {
		return loadDocument(OdfPackage.loadPackage(file));
	}

	/**
	 * Creates an OdfDocument from the OpenDocument provided by an ODF package.
	 * @param odfPackage - the ODF package containing the ODF document.
	 * @return the root document of the given OdfPackage
	 * @throws java.lang.Exception - if the ODF document could not be created.
	 */
	public static OdfDocument loadDocument(OdfPackage odfPackage) throws Exception {
		OdfMediaType odfMediaType = OdfMediaType.getOdfMediaType(odfPackage.getMediaType());
		if (odfMediaType == null) {
			throw new IllegalArgumentException("Document contains incorrect ODF Mediatype '" + odfPackage.getMediaType() + "'");
		}
		OdfDocument odfDocument = newDocument(odfMediaType, odfPackage);
		odfDocument.setRootDocument(odfDocument);
		return odfDocument;
	}

	/**
	 * Returns an OdfDocument from an embedded OdfDocument referenced by an internal path.
	 * @param containerDocument the OdfDocument which contains the embedded OdfDocument.
	 * @param pkgPathToChildDocument the path to the directory of the embedded ODF document (relative to ODF package root).
	 * @throws java.lang.Exception - if the document could not be created
	 */
	private static OdfDocument loadDocument(OdfDocument parentDocument, String pkgPathToChildDocument, String mediaType) throws Exception {
		OdfMediaType odfMediaType = OdfMediaType.getOdfMediaType(mediaType);
		OdfDocument newDoc = null;
		if (odfMediaType.equals(OdfMediaType.TEXT)) {
			newDoc = OdfTextDocument.newTextDocument();
		} else if (odfMediaType.equals(OdfMediaType.SPREADSHEET)) {
			newDoc = OdfSpreadsheetDocument.newSpreadsheetDocument();
		} else if (odfMediaType.equals(OdfMediaType.PRESENTATION)) {
			newDoc = OdfPresentationDocument.newPresentationDocument();
		} else if (odfMediaType.equals(OdfMediaType.GRAPHICS)) {
			newDoc = OdfGraphicsDocument.newGraphicsDocument();
		} else if (odfMediaType.equals(OdfMediaType.CHART)) {
			newDoc = OdfChartDocument.newChartDocument();
		}
		newDoc.setDocumentPathInPackage(pkgPathToChildDocument);
		if (newDoc.isRootDocument()) {
			newDoc.setRootDocument(newDoc);
		} else {
			newDoc.setRootDocument(parentDocument);
		}
		newDoc.setPackage(parentDocument.getPackage());
		return newDoc;
	}

	/**
	 * Sets the root OdfDocument that determines the mediatype of the package.
	 *
	 * @param root the OdfDocument that has its file on the root level of the package
	 */
	protected void setRootDocument(OdfDocument root) {
		mRootDocument = root;
	}

	/**
	 * Retreives the root OdfDocument that determines the mediatype of the package.
	 *
	 * @return the OdfDocument that has its file on the root level of the package
	 */
	protected OdfDocument getRootDocument() {
		return mRootDocument;
	}

	/**
	 * Sets the OdfPackage that contains this OdfDocument.
	 *
	 * @param pkg the OdfPackage that contains this OdfDocument
	 */
	protected void setPackage(OdfPackage pkg) {
		mPackage = pkg;
	}

	/**
	 * Retreives the OdfPackage for this OdfDocument.
	 *
	 * @return the OdfPackage that contains this OdfDocument.
	 */
	public OdfPackage getPackage() {
		return mPackage;
	}

	/**
	 * Sets the media type of the OdfDocument
	 * @param odfMediaType media type to be set
	 */
	protected void setMediaType(OdfMediaType odfMediaType) {
		mMediaType = odfMediaType;
	}

	/**
	 * Set the relative path for an embedded ODF document.
	 * @param path to directory of the embedded ODF document (relative to ODF package root).
	 */
	private void setDocumentPathInPackage(String path) {
		mDocumentPathInPackage = ensureValidPackagePath(path);
	}

	/**
	 * Get the relative path for an embedded ODF document.
	 * @return path to the directory of the embedded ODF document (relative to ODF package root).
	 */
	public String getDocumentPackagePath() {
		return mDocumentPathInPackage;
	}

	/**
	 * Get the relative path for an embedded ODF document including its file name.
	 * @param file represents one of the standardized XML ODF files.
	 * @return path to embedded ODF XML file relative to ODF package root.
	 */
	protected String getXMLFilePath(OdfXMLFile file) {
		return getDocumentPackagePath() + file.mFileName;
	}

	/**
	 * Add an OdfDocument as an embedded OdfDocument to the current OdfDocument
	 * @param pkgPathToChildDocument path to the directory of the embedded ODF document (always relative to ODF package root).
	 * @param newOdfDocument the OdfDocument to be embedded
	 */
	public void embedDocument(String pkgPathToChildDocument, OdfDocument newOdfDocument) throws Exception {
		newOdfDocument.insertDOMsToPkg();
		// insert to package and add it to the Manifest
		pkgPathToChildDocument = ensureValidPackagePath(pkgPathToChildDocument);
		newOdfDocument.setDocumentPathInPackage(pkgPathToChildDocument);
		if (isRootDocument()) {
			newOdfDocument.mRootDocument = this;
		} else {
			newOdfDocument.mRootDocument = this.mRootDocument;
		}
		for (OdfXMLFile odfFile : OdfXMLFile.values()) {
			try {
				if (newOdfDocument.mPackage.getInputStream(odfFile.mFileName) != null) {
					mPackage.insert(newOdfDocument.mPackage.getInputStream(odfFile.mFileName), newOdfDocument.getXMLFilePath(odfFile), newOdfDocument.mPackage.getMediaType());
				}
			} catch (Exception ex) {
				Logger.getLogger(OdfDocument.class.getName()).log(Level.SEVERE, null, ex);
			}
		}
	}

	/**
	 * Gets the ODF content.xml file as stream.
	 * @return - a stream of the ODF content 'content.xml' file
	 * @throws java.lang.Exception - if the stream can not be extracted
	 */
	public InputStream getContentStream() throws Exception {
		String path = getXMLFilePath(OdfXMLFile.CONTENT);
		return mPackage.getInputStream(path);
	}

	/**
	 * Gets the ODF style.xml file as stream.
	 *
	 * @return - a stream of the ODF style 'styles.xml' file
	 * @throws java.lang.Exception - if the stream can not be extracted
	 */
	public InputStream getStylesStream() throws Exception {
		return mPackage.getInputStream(getXMLFilePath(OdfXMLFile.STYLES));
	}

	/**
	 * Gets the ODF settings.xml file as stream.
	 *
	 * @return - a stream of the ODF metadata 'setting.xml' file
	 * @throws java.lang.Exception - if the stream can not be extracted
	 */
	public InputStream getSettingsStream() throws Exception {
		return mPackage.getInputStream(getXMLFilePath(OdfXMLFile.SETTINGS));
	}

	/**
	 * Gets the ODF metadata.xml file as stream.
	 *
	 * @return - a stream of the ODF metadata 'meta.xml' file
	 * @throws java.lang.Exception - if the stream can not be extracted
	 */
	public InputStream getMetaStream() throws Exception {
		return mPackage.getInputStream(getXMLFilePath(OdfXMLFile.META));
	}

	/**
	 * Get the URI, where this ODF document is stored.
	 * @return the URI to the ODF document. Returns null if document is not stored yet.
	 */
	public String getBaseURI() {
		return mPackage.getBaseURI();
	}

	/**
	 * Returns an embedded OdfDocument of the current OdfDocument matching to the internal package path
	 * given as an parameter. Once loaded embedded OdfDocuments are cached for later use.
	 *
	 * @param pathToObject path to the directory of the embedded ODF document (relative to ODF package root).
	 * @return an embedded OdfDocument
	 */
	public OdfDocument getEmbeddedDocument(String pathToObject) {
		OdfDocument cachedDocument;
		pathToObject = ensureValidPackagePath(pathToObject);
		try {
			String mediaTypeOfEmbeddedDoc = mPackage.getFileEntry(pathToObject).getMediaType();
			if (mediaTypeOfEmbeddedDoc != null) {
				// look if OdfDocument was already created, if so return reference, otherwise create OdfDocument.OdfDocument
				if ((cachedDocument = lookupDocumentCache(pathToObject)) != null) {
					return cachedDocument;
				} else {
					OdfDocument newDoc = OdfDocument.loadDocument(this, pathToObject, mediaTypeOfEmbeddedDoc);
					addToCache(newDoc.getDocumentPackagePath(), newDoc);
					return newDoc;
				}
			}
		} catch (Exception ex) {
			Logger.getLogger(OdfDocument.class.getName()).log(Level.SEVERE, null, ex);
		}
		return null;
	}

	/**
	 * Method returns all embedded OdfDocuments of the current OdfDocument matching the
	 * according MediaType. This is done by matching the subfolder entries of the
	 * manifest file with the given OdfMediaType.
	 * @param mediaType media type which is used as a filter
	 * @return embedded documents of the current OdfDocument matching the given media type
	 */
	public List<OdfDocument> getEmbeddedDocuments(OdfMediaType mediaType) {
		Set<String> manifestEntries = this.getPackage().getFileEntries();
		List<OdfDocument> embeddedObjects = new ArrayList<OdfDocument>();
		// check manifest for current embedded OdfDocuments
		for (String entry : manifestEntries) {
			if (entry.length() > 1 && entry.endsWith(SLASH)) {
				String entryMediaType = getPackage().getFileEntry(entry).getMediaType();
				if (entryMediaType.equals(mediaType.toString())) {
					embeddedObjects.add(getEmbeddedDocument(entry));
				}
			}
		}
		return embeddedObjects;
	}

	/**
	 * Method returns all embedded OdfDocuments, which match a valid OdfMediaType,
	 * of the current OdfDocument.
	 * @return a list with all embedded documents of the current odfDocument
	 */
	public List<OdfDocument> getEmbeddedDocuments() {
		List<OdfDocument> embeddedObjects = new ArrayList<OdfDocument>();
		for (OdfMediaType mediaType : OdfMediaType.values()) {
			embeddedObjects.addAll(getEmbeddedDocuments(mediaType));
		}
		return embeddedObjects;
	}

	private OdfDocument lookupDocumentCache(String pathToObject) {
		Map<String, OdfDocument> documentCache;
		if (isRootDocument()) {
			documentCache = mCachedDocuments;
		} else {
			documentCache = mRootDocument.mCachedDocuments;
		}
		if (documentCache != null && documentCache.containsKey(pathToObject)) {
			return documentCache.get(pathToObject);
		}
		return null;
	}

	private void addToCache(String pathToObject, OdfDocument document) {
		if (isRootDocument()) {
			mCachedDocuments.put(pathToObject, document);
		} else {
			mRootDocument.mCachedDocuments.put(pathToObject, document);
		}
	}

	private boolean isRootDocument() {
		if (getDocumentPackagePath().equals(EMPTY_STRING)) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 *
	 * @return the office:styles element from the styles dom or null if there
	 *         is no such element.
	 */
	public OdfOfficeStyles getDocumentStyles() {
		if (mDocumentStyles == null) {
			try {
				OdfFileDom stylesDom = getStylesDom();
				if (stylesDom != null) {
					mDocumentStyles = OdfElement.findFirstChildNode(OdfOfficeStyles.class, stylesDom.getFirstChild());
				} else {
					return null;
				}
			} catch (Exception ex) {
				Logger.getLogger(OdfDocument.class.getName()).log(Level.SEVERE, null, ex);
			}
		}
		return mDocumentStyles;
	}

	/**
	 *
	 * @return the office:styles element from the styles dom. If there is not
	 *         yet such an element, it is created.
	 */
	public OdfOfficeStyles getOrCreateDocumentStyles() {
		if (mDocumentStyles == null) {
			try {
				OdfFileDom stylesDom = getStylesDom();
				Node parent = stylesDom != null ? stylesDom.getFirstChild() : null;

				if (parent != null) {
					mDocumentStyles = OdfElement.findFirstChildNode(OdfOfficeStyles.class, parent);

					if (mDocumentStyles == null) {
						mDocumentStyles = stylesDom.newOdfElement(OdfOfficeStyles.class);
						parent.insertBefore(mDocumentStyles, parent.getFirstChild());
					}
				}
			} catch (Exception ex) {
				Logger.getLogger(OdfDocument.class.getName()).log(Level.SEVERE, null, ex);
			}
		}
		return mDocumentStyles;
	}

	/**
	 * Create an XPath instance to select one or more nodes from an ODF document.
	 * Therefore the namespace context is set to the OdfNamespace
	 * @return an XPath instance with namespace context set to include the standard
	 * ODFDOM prefixes.
	 */
	public XPath getXPath() {
		if (mXPath == null) {
			mXPath = XPathFactory.newInstance().newXPath();
			mXPath.setNamespaceContext(new OdfNamespace());
		}
		return mXPath;
	}

	/**
	 * Return the ODF type-based content DOM of the current OdfDocument
	 * @return ODF type-based content DOM
	 * @throws Exception if content DOM could not be initialized
	 */
	public OdfFileDom getContentDom() throws Exception {
		if (mContentDom == null) {
			mContentDom = getFileDom(OdfXMLFile.CONTENT);
		}
		return mContentDom;
	}

	/**
	 * Return the ODF type-based content DOM of the current OdfDocument
	 * @return ODF type-based styles DOM
	 * @throws Exception if styles DOM could not be initialized
	 */
	public OdfFileDom getStylesDom() throws Exception {
		if (mStylesDom == null) {
			mStylesDom = getFileDom(OdfXMLFile.STYLES);
		}
		return mStylesDom;
	}

	/**
	 * Get the media type from document
	 *
	 * @return the mMediaType string of this package
	 */
	public String getMediaType() {
		return mMediaType.getName();
	}

	/**
	 * Save the document to given path. Delegate to the root document
	 * and save possible embedded OdfDocuments.
	 *
	 * <p>If the input file has been cached (this is the case when loading from an
	 * InputStream), the input file can be overwritten.</p>
	 *
	 * <p>Otherwise it's allowed to overwrite the input file as long as
	 * the same path name is used that was used for loading (no symbolic link
	 * foo2.odt pointing to the loaded file foo1.odt, no network path X:\foo.odt
	 * pointing to the loaded file D:\foo.odt).</p>
	 *
	 * @param path - the path to the file
	 * @throws java.lang.Exception  if the document could not be saved
	 */
	public void save(String path) throws Exception {
		this.optimize();
		if (!isRootDocument() && mRootDocument != null) {
			mRootDocument.save(path);
		} else {
			if (!mCachedDocuments.isEmpty()) {
				for (String odfDocPath : mCachedDocuments.keySet()) {
					mCachedDocuments.get(odfDocPath).saveEmbeddedDoc();
				}
			}
			insertDOMsToPkg();
			mPackage.save(path);
		}
	}

	/**
	 * Save the document to given file. Delegate to the root document
	 * and save possible embedded OdfDocuments.
	 *
	 * <p>If the input file has been cached (this is the case when loading from an
	 * InputStream), the input file can be overwritten.</p>
	 *
	 * <p>Otherwise it's allowed to overwrite the input file as long as
	 * the same path name is used that was used for loading (no symbolic link
	 * foo2.odt pointing to the loaded file foo1.odt, no network path X:\foo.odt
	 * pointing to the loaded file D:\foo.odt).</p>
	 *
	 * @param file - the file to save the document
	 * @throws java.lang.Exception  if the document could not be saved
	 */
	public void save(File file) throws Exception {
		this.optimize();
		if (!isRootDocument() && mRootDocument != null) {
			mRootDocument.save(file);
		} else {
			if (!mCachedDocuments.isEmpty()) {
				for (String odfDocPath : mCachedDocuments.keySet()) {
					mCachedDocuments.get(odfDocPath).saveEmbeddedDoc();
				}
			}
			insertDOMsToPkg();
			mPackage.save(file);
		}
	}

	/**
	 * Save the document to an OutputStream. Delegate to the root document
	 * and save possible embedded OdfDocuments.
	 *
	 * <p>If the input file has been cached (this is the case when loading from an
	 * InputStream), the input file can be overwritten.</p>
	 *
	 * <p>If not, the OutputStream may not point to the input file! Otherwise
	 * this will result in unwanted behaviour and broken files.</p>
	 *
	 * @param out - the OutputStream to write the file to
	 * @throws java.lang.Exception  if the document could not be saved
	 */
	public void save(OutputStream out) throws Exception {
		this.optimize();
		if (!isRootDocument() && mRootDocument != null) {
			mRootDocument.save(out);
		} else {
			if (!mCachedDocuments.isEmpty()) {
				for (String odfDocPath : mCachedDocuments.keySet()) {
					mCachedDocuments.get(odfDocPath).saveEmbeddedDoc();
				}
			}
			insertDOMsToPkg();
			mPackage.save(out);
		}
	}

	// TODO: add save function for all DOMs
	private void saveEmbeddedDoc() throws Exception {
		this.optimize();
		if (mContentDom == null) {
			mPackage.insert(getContentStream(), getXMLFilePath(OdfXMLFile.CONTENT), getMediaType());
		} else {
			mPackage.insert(getContentDom(), getXMLFilePath(OdfXMLFile.CONTENT), null);
		}
		if (mStylesDom == null) {
			mPackage.insert(getStylesStream(), getXMLFilePath(OdfXMLFile.STYLES), getMediaType());
		} else {
			mPackage.insert(getStylesDom(), getXMLFilePath(OdfXMLFile.STYLES), null);
		}
	}

	/**
	 * Close the OdfPackage and release all temporary created data.
	 * Acter execution of this method, this class is no longer usable.
	 * Do this as the last action to free resources.
	 * Closing an already closed document has no effect.
	 * Note that this will not close any cached documents.
	 */
	public void close() {
		mPackage.close();
	}

	/**
	 * Optimize the styles of this document: unused styles and doubled styles
	 * are removed.
	 */
	// currently commented because of bug 51:
	// https://odftoolkit.org/bugzilla/show_bug.cgi?id=51
	private void optimize() {
//        try {
//            OdfFileDom dom = this.getStylesDom();
//            if (dom != null) {
//                OdfOfficeAutomaticStyles auto_styles = dom.getAutomaticStyles();
//                if (auto_styles != null) {
//                    auto_styles.optimize();
//                }
//            }
//            dom = this.getContentDom();
//            if (dom != null) {
//                OdfOfficeAutomaticStyles auto_styles = dom.getAutomaticStyles();
//                if (auto_styles != null) {
//                    auto_styles.optimize();
//                }
//            }
//        } catch (Exception ex) {
//            Logger.getLogger(OdfDocument.class.getName()).log(Level.SEVERE, null, ex);
//        }
	}

	private void insertDOMsToPkg() throws Exception {
			if (getContentStream() != null) {
				mPackage.insert(getContentDom(), getXMLFilePath(OdfXMLFile.CONTENT), null);
			}
			if (getStylesStream() != null) {
				mPackage.insert(getStylesDom(), getXMLFilePath(OdfXMLFile.STYLES), null);
			}
	}
	private Resolver mResolver;

	/**
	 * get EntityResolver to be used in XML Parsers
	 * which can resolve content inside the OdfPackage
	 */
	EntityResolver getEntityResolver() {
		if (mResolver == null) {
			mResolver = new Resolver();
		}
		return mResolver;
	}

	/**
	 * get URIResolver to be used in XSL Transformations
	 * which can resolve content inside the OdfPackage
	 */
	URIResolver getURIResolver() {
		if (mResolver == null) {
			mResolver = new Resolver();
		}
		return mResolver;
	}

	/**
	 * @return the office:body element of this document
	 */
	public OdfOfficeBody getOfficeBody() {
		try {
			if (getContentDom() != null) {
				return OdfElement.findFirstChildNode(OdfOfficeBody.class, getContentDom().getFirstChild());
			}
		} catch (Exception ex) {
			Logger.getLogger(OdfDocument.class.getName()).log(Level.SEVERE, null, ex);
		}
		return null;
	}

	/**
	 * Get the content root of a document.
	 *
	 * You may prefer to use the getContentRoot methods of subclasses of
	 * OdfDocument. Their return parameters are already casted to
	 * respective subclasses of OdfElement.
	 *
	 * @param the type of the content root, depend on the document type
	 * @return the child element of office:body, e.g. office:text for text docs
	 * @throws Exception if the file DOM could not be created.
	 */
    @SuppressWarnings("unchecked") // XXX: If possible this should be fixed. Suppressing for now to not hide warnings from other files.
	<T extends OdfElement> T getContentRoot(Class<T> clazz) throws Exception {
		OdfElement contentRoot = getContentDom().getRootElement();
		OdfOfficeBody contentBody = OdfElement.findFirstChildNode(OdfOfficeBody.class, contentRoot);
		NodeList childs = contentBody.getChildNodes();
		for (int i = 0; i < childs.getLength(); i++) {
			Node cur = childs.item(i);
			if ((cur != null) && clazz.isInstance(cur)) {
				return (T) cur;
			}
		}
		return null;
	}

	/**
	 * return the office:master-styles element of this document.
	 * @return the office:master-styles element
	 */
	public OdfOfficeMasterStyles getOfficeMasterStyles() {
		try {
			OdfFileDom fileDom = getStylesDom();
			if (fileDom != null) {
				return OdfElement.findFirstChildNode(OdfOfficeMasterStyles.class, fileDom.getFirstChild());
			}
		} catch (Exception ex) {
			Logger.getLogger(OdfDocument.class.getName()).log(Level.SEVERE, null, ex);
		}
		return null;
	}

	/**
	 * resolve external entities
	 */
	private class Resolver implements EntityResolver, URIResolver {

		/**
		 * Resolver constructor.
		 */
		public Resolver() {
		}

		/**
		 * Allow the application to resolve external entities.
		 *
		 * The Parser will call this method before opening any external entity except
		 * the top-level document entity (including the external DTD subset,
		 * external entities referenced within the DTD, and external entities referenced
		 * within the document element): the application may request that the parser
		 * resolve the entity itself, that it use an alternative URI,
		 * or that it use an entirely different input source.
		 */
		public InputSource resolveEntity(String publicId, String systemId)
				throws SAXException, IOException {
			// this deactivates the attempt to loadPackage the Math DTD
			if (publicId != null && publicId.startsWith("-//OpenOffice.org//DTD Modified W3C MathML")) {
				return new InputSource(new ByteArrayInputStream("<?xml version='1.0' encoding='UTF-8'?>".getBytes()));
			}
			if (systemId != null) {
				if ((mPackage.getBaseURI() != null) && systemId.startsWith(mPackage.getBaseURI())) {
					if (systemId.equals(mPackage.getBaseURI())) {
						InputStream in = null;
						try {
							in = mPackage.getInputStream();
						} catch (Exception e) {
							throw new SAXException(e);
						}
						InputSource ins;
						ins = new InputSource(in);

						if (ins == null) {
							return null;
						}
						ins.setSystemId(systemId);
						return ins;
					} else {
						if (systemId.length() > mPackage.getBaseURI().length() + 1) {
							InputStream in = null;
							try {
								String path = systemId.substring(mPackage.getBaseURI().length() + 1);
								in = mPackage.getInputStream(path);
								InputSource ins = new InputSource(in);
								ins.setSystemId(systemId);
								return ins;
							} catch (Exception ex) {
								Logger.getLogger(OdfDocument.class.getName()).log(Level.SEVERE, null, ex);
							} finally {
								try {
									in.close();
								} catch (IOException ex) {
									Logger.getLogger(OdfDocument.class.getName()).log(Level.SEVERE, null, ex);
								}
							}
						}
						return null;
					}
				} else if (systemId.startsWith("resource:/")) {
					int i = systemId.indexOf('/');
					if ((i > 0) && systemId.length() > i + 1) {
						String res = systemId.substring(i + 1);
						ClassLoader cl = OdfPackage.class.getClassLoader();
						InputStream in = cl.getResourceAsStream(res);
						if (in != null) {
							InputSource ins = new InputSource(in);
							ins.setSystemId(systemId);
							return ins;
						}
					}
					return null;
				} else if (systemId.startsWith("jar:")) {
					try {
						URL url = new URL(systemId);
						JarURLConnection jarConn = (JarURLConnection) url.openConnection();
						InputSource ins = new InputSource(jarConn.getInputStream());
						ins.setSystemId(systemId);
						return ins;
					} catch (MalformedURLException me) {
						throw new SAXException(me); // Incorrect URL format used

					}
				}
			}
			return null;
		}

		public Source resolve(String href, String base)
				throws TransformerException {
			try {
				URI uri = null;
				if (base != null) {
					URI baseuri = new URI(base);
					uri = baseuri.resolve(href);
				} else {
					uri = new URI(href);
				}

				InputSource ins = null;
				try {
					ins = resolveEntity(null, uri.toString());
				} catch (Exception e) {
					throw new TransformerException(e);
				}
				if (ins == null) {
					return null;
				}
				InputStream in = ins.getByteStream();
				StreamSource src = new StreamSource(in);
				return src;
			} catch (URISyntaxException use) {
				return null;
			}
		}
	}

	private OdfFileDom getFileDom(OdfXMLFile file) throws Exception {
		// create sax parser
		SAXParserFactory saxFactory = SAXParserFactory.newInstance();
		saxFactory.setNamespaceAware(true);
		saxFactory.setValidating(false);

                saxFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
                saxFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                saxFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

                SAXParser parser = saxFactory.newSAXParser();
		XMLReader xmlReader = parser.getXMLReader();
		// More details at http://xerces.apache.org/xerces2-j/features.html#namespaces
		xmlReader.setFeature("http://xml.org/sax/features/namespaces", true);
		// More details at http://xerces.apache.org/xerces2-j/features.html#namespace-prefixes
		xmlReader.setFeature("http://xml.org/sax/features/namespace-prefixes", true);
		// More details at http://xerces.apache.org/xerces2-j/features.html#xmlns-uris
		xmlReader.setFeature("http://xml.org/sax/features/xmlns-uris", true);

                xmlReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

		// initialize the input source's content.xml
		OdfFileDom fileDom = new OdfFileDom(this, this.getXMLFilePath(file));

		String path = getXMLFilePath(file);
		InputStream fileStream = mPackage.getInputStream(path);
		if (fileStream != null) {
			Handler handler = new Handler(fileDom);
			xmlReader.setContentHandler(handler);
			InputSource contentSource = new InputSource(fileStream);
			xmlReader.parse(contentSource);
		}
		return fileDom;
	}

	// TODO possible refactor - similar method in OdfPackage
	private String ensureValidPackagePath(String filePath) {
		if (filePath == null) {
			String errMsg = "The path given by parameter is NULL!";
			Logger.getLogger(OdfDocument.class.getName()).log(Level.SEVERE, null, errMsg);
			throw new IllegalArgumentException(errMsg);
		} else if (filePath.equals(EMPTY_STRING)) {
			String errMsg = "The path given by parameter is an empty string!";
			Logger.getLogger(OdfDocument.class.getName()).log(Level.SEVERE, null, errMsg);
			throw new IllegalArgumentException(errMsg);
		} else {
			if (filePath.indexOf('\\') != -1) {
				filePath = filePath.replace('\\', '/');
			}
			if (filePath.indexOf("//") != -1) {
				filePath = filePath.replace("//", "/");
			}
			if (!filePath.endsWith("/")) {
				filePath = filePath + "/";
			}
			if (isExternalReference(filePath)) {
				String errMsg = "The path given by parameter '" + filePath + "' is not an internal ODF package path!";
				Logger.getLogger(OdfDocument.class.getName()).log(Level.SEVERE, null, errMsg);
				throw new IllegalArgumentException(errMsg);
			}
		}
		return filePath;
	}

	/** Checks if the given reference is a reference, which points outside the ODF package
	 * @param ref the file reference to be checked
	 * @return true if the reference is an package external reference
	 */
	private static boolean isExternalReference(String ref) {
		boolean isExternalReference = false;
		// if the reference is a external relative filePath..
		if (ref.startsWith(TWO_DOTS) ||
				// or absolute filePath
				ref.startsWith(SLASH) ||
				// or absolute IRI
				ref.contains(COLON)) {
			isExternalReference = true;
		}
		return isExternalReference;
	}

	private class Handler extends DefaultHandler {
		// the empty document to which nodes will be added

		private OdfFileDom mDocument;
		private Node m_root;
		// the context node
		private Node mNode;        // a stack of sub handlers. handlers will be pushed on the stack whenever
		// they are required and must pop themselves from the stack when done
		private Stack<ContentHandler> mHandlerStack = new Stack<ContentHandler>();

		Handler(Node root) {
			m_root = root;
			if (m_root instanceof OdfFileDom) {
				mDocument = (OdfFileDom) m_root;
			} else {
				mDocument = (OdfFileDom) m_root.getOwnerDocument();
			}
			mNode = m_root;
		}

		@Override
		public void startDocument() throws SAXException {
		}

		@Override
		public void endDocument() throws SAXException {
		}

		@Override
		public void endElement(String uri, String localName, String qName) throws SAXException {
			flushTextNode();
			// pop to the parent node
			mNode = mNode.getParentNode();
		}

		@Override
		public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
			flushTextNode();
			// if there is a specilized handler on the stack, dispatch the event
			Element element = mDocument.createElementNS(uri, qName);
			for (int i = 0; i < attributes.getLength(); i++) {
				OdfAttribute attr = mDocument.createAttributeNS(attributes.getURI(i), attributes.getQName(i));
				element.setAttributeNodeNS(attr);
				if (attr instanceof OfficeVersionAttribute) {
					// write out not the original value, but the version of this odf version
					attr.setValue(OfficeVersionAttribute.Value._1_2.toString());
				} else {
					// don't exit because of invalid attribute values
					try {
						attr.setValue(attributes.getValue(i));
					} // if we detect an attribute with invalid value: remove attribute node
					catch (IllegalArgumentException e) {
						element.removeAttributeNode(attr);
					}
				}
			}
			// add the new element as a child of the current context node
			mNode.appendChild(element);
			// push the new element as the context node...
			mNode = element;
		}

		/**
		 * http://xerces.apache.org/xerces2-j/faq-sax.html#faq-2 :
		 * SAX may deliver contiguous text as multiple calls to characters,
		 * for reasons having to do with parser efficiency and input buffering.
		 * It is the programmer's responsibility to deal with that appropriately,
		 * e.g. by accumulating text until the next non-characters event.
		 */
		private void flushTextNode() {
			if (mCharsForTextNode.length() > 0) {
				Text text = mDocument.createTextNode(mCharsForTextNode.toString());
				mNode.appendChild(text);
				mCharsForTextNode.setLength(0);
			}
		}

		@Override
		public void characters(char[] ch, int start, int length) throws SAXException {
			if (!mHandlerStack.empty()) {
				mHandlerStack.peek().characters(ch, start, length);
			} else {
				mCharsForTextNode.append(ch, start, length);
			}
		}

		@Override
		public InputSource resolveEntity(String publicId, String systemId) throws IOException, SAXException {
			return super.resolveEntity(publicId, systemId);
		}
	}
	private static final String TO_STRING_METHOD_TOKEN = "\nID: ";

	@Override
	public String toString() {
		return TO_STRING_METHOD_TOKEN + this.hashCode() + " " + mPackage.getBaseURI();
	}
	private XPath xpath;

	/**
	 * Insert an Image from the specified uri to the end of the OdfDocument.
	 * @param imageUri The URI of the image that will be added to the document,
	 * 				   add image stream to the package,
	 *                 in the 'Pictures/' graphic directory with the same image file name as in the URI.
	 *                 If the imageURI is relative first the user.dir is taken to make it absolute.
	 * @return         Returns the internal package path of the image, which was created based on the given URI.
	 * */
	public String newImage(URI imageUri) {
		if (xpath == null) {
			xpath = XPathFactory.newInstance().newXPath();
			xpath.setNamespaceContext(new OdfNamespace());
		}
		try {
			OdfDrawFrame drawFrame = this.getContentDom().newOdfElement(OdfDrawFrame.class);

			if (this instanceof OdfSpreadsheetDocument) {
				TableTableCellElement lastCell = (TableTableCellElement) xpath.evaluate("//table:table-cell[last()]", this.getContentDom(), XPathConstants.NODE);
				lastCell.appendChild(drawFrame);
				drawFrame.removeAttribute("text:anchor-type");

			} else if (this instanceof OdfTextDocument) {
				TextPElement lastPara = (TextPElement) xpath.evaluate("//text:p[last()]", this.getContentDom(), XPathConstants.NODE);
				if (lastPara == null) {
					lastPara = ((OdfTextDocument) this).newParagraph();
				}
				lastPara.appendChild(drawFrame);
				drawFrame.setTextAnchorTypeAttribute(TextAnchorTypeAttribute.Value.PARAGRAPH.toString());
			} else if (this instanceof OdfPresentationDocument) {
				DrawPageElement lastPage = (DrawPageElement) xpath.evaluate("//draw:page[last()]", this.getContentDom(), XPathConstants.NODE);
				lastPage.appendChild(drawFrame);
			}
			OdfDrawImage image = (OdfDrawImage) drawFrame.newDrawImageElement();
			String imagePath = image.newImage(imageUri);

			return imagePath;
		} catch (Exception ex) {
			ex.printStackTrace();
			Logger.getLogger(OdfDocument.class.getName()).log(Level.SEVERE, null, ex);

		}
		return null;

	}
	
	/**
	 * remove an embedded Document from the current OdfDocument
	 * @param pathToObject path to the directory of the embedded ODF document (always relative to ODF package root).
	 */
	public void RemoveEmbedDocument(String pathToObject) {
		try {
			// remove it from package and  Manifest
			pathToObject = ensureValidPackagePath(pathToObject);
			OdfDocument embedDocument = getEmbeddedDocument(pathToObject);
			/*if (embedDocument.getContentStream() != null) {
			mPackage.remove(embedDocument.getXMLFilePath(OdfXMLFile.CONTENT));
			}
			if (embedDocument.getStylesStream() != null) {
			mPackage.remove(embedDocument.getXMLFilePath(OdfXMLFile.STYLES));
			}*/

			for (OdfXMLFile odfFile : OdfXMLFile.values()) {
				mPackage.remove(embedDocument.getXMLFilePath(odfFile));
			}
			mPackage.remove(pathToObject);
			//remove this embed document from cache
			deleteCache(pathToObject);
		} catch (Exception ex) {
			Logger.getLogger(OdfDocument.class.getName()).log(Level.SEVERE, null, ex);
		}
	}

	private void deleteCache(String pathToObject) {
		if (isRootDocument()) {
			mCachedDocuments.remove(pathToObject);
		} else {
			mRootDocument.mCachedDocuments.remove(pathToObject);
		}
	}

}
