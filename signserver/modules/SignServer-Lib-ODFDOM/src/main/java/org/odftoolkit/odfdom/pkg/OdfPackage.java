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
package org.odftoolkit.odfdom.pkg;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.JarURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.Source;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.URIResolver;
import javax.xml.transform.stream.StreamSource;

import org.apache.xerces.dom.DOMXSImplementationSourceImpl;
import org.odftoolkit.odfdom.doc.OdfDocument;
import org.odftoolkit.odfdom.pkg.manifest.Algorithm;
import org.odftoolkit.odfdom.pkg.manifest.EncryptionData;
import org.odftoolkit.odfdom.pkg.manifest.KeyDerivation;
import org.odftoolkit.odfdom.pkg.manifest.OdfFileEntry;
import org.w3c.dom.Document;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.Attributes;
import org.xml.sax.ContentHandler;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.Locator;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

/**
 * OdfPackage represents the package view to an OpenDocument document.
 * The OdfPackage will be created from an ODF document and represents a copy of 
 * the loaded document, where files can be inserted and deleted.
 * The changes take effect, when the OdfPackage is being made persistend by save().
 */
public class OdfPackage {

    /**
     * This class solely exists to clean up after a package object has been
     * removed by garbage collector. Finalizable classes are said to have
     * slow garbage collection, so we don't make the whole OdfPackage
     * finalizable.
     */
    static private class OdfFinalizablePackage {
        File mTempDirForDeletion;

        OdfFinalizablePackage(File tempDir) {
            mTempDirForDeletion = tempDir;
        }

        @Override
        protected void finalize() {
            if (mTempDirForDeletion != null) {
                TempDir.deleteTempOdfDirectory(mTempDirForDeletion);
            }
        }
    }

    private Logger mLog = Logger.getLogger(OdfPackage.class.getName());

    public enum OdfFile {

        IMAGE_DIRECTORY("Pictures"),
        MANIFEST("META-INF/manifest.xml"),
        MEDIA_TYPE("mimetype");
        private final String packagePath;

        OdfFile(String packagePath) {
            this.packagePath = packagePath;
        }

        public String getPath() {
            return packagePath;
        }
    }
    // Static parts of file references
    private static final String TWO_DOTS = "..";
    private static final String SLASH = "/";
    private static final String COLON = ":";
    private static final String EMPTY_STRING = "";   
    private static final String XML_MEDIA_TYPE = "text/xml";

    // temp Dir for this ODFpackage (2DO: temp dir handling will be removed most likely)
    private File mTempDirParent;
    private File mTempDir;
    private OdfFinalizablePackage mFinalize;

    // some well known streams inside ODF packages    
    private String mMediaType;
    private List<String> mPackageEntries;
    private ZipFile mZipFile;
    private HashMap<String, ZipEntry> mZipEntries;
    private HashMap<String, Document> mContentDoms;
    private HashMap<String, byte[]> mContentStreams;
    private HashMap<String, File> mTempFiles;

    private List<String> mManifestList;
    private HashMap<String, OdfFileEntry> mManifestEntries;

    private String mBaseURI;
    private Resolver mResolver;

    /**
     * This basically creates the ODFPackage as an empty Package.
     * For setting a specific temp directory, set the System variable
     * org.odftoolkit.odfdom.tmpdir:<br>
     * <code>System.setProperty("org.odftoolkit.odfdom.tmpdir");</code>
     */
    private OdfPackage() {
        mMediaType = null;
        mResolver = null;
        mTempDir = null;
        mTempDirParent = null;
        mPackageEntries = new LinkedList<String>();
        mZipEntries = new HashMap<String, ZipEntry>();
        mContentDoms = new HashMap<String, Document>();
        mContentStreams = new HashMap<String, byte[]>();
        mTempFiles = new HashMap<String, File>();
        mManifestList = new LinkedList<String>();

        // get a temp directory for everything
        String userPropDir = System.getProperty("org.odftoolkit.odfdom.tmpdir");
        if (userPropDir != null) {
            mTempDirParent = new File(userPropDir);
        }
    }

    /**
     * Creates an OdfPackage from the OpenDocument provided by a filePath.
     *
     * <p>OdfPackage relies on the file being available for read access over
     * the whole lifecycle of OdfPackage. Please refer to the documentation
     * of the save methods to decide whether overwriting the input file
     * is allowed.</p>
     *
     * @param odfPath - the path to the ODF document.
     * @throws java.lang.Exception - if the package could not be created
     */
    private OdfPackage(String odfPath) throws Exception {
        this();
        initialize(new File(odfPath));
    }

    /**
     * Creates an OdfPackage from the OpenDocument provided by a File.    
     *
     * <p>OdfPackage relies on the file being available for read access over
     * the whole lifecycle of OdfPackage. Please refer to the documentation
     * of the save methods to decide whether overwriting the input file
     * is allowed.</p>
     *
     * @param odfFile - a file representing the ODF document
     * @throws java.lang.Exception - if the package could not be created
     */
    private OdfPackage(File odfFile) throws Exception {
        this();
        initialize(odfFile);
    }

    /**
     * Creates an OdfPackage from the OpenDocument provided by a InputStream.
     *
     * <p>Since an InputStream does not provide the arbitrary (non sequentiell)
     * read access needed by OdfPackage, the InputStream is cached. This usually
     * takes more time compared to the other constructors.
     * An advantage of caching is that there are no problems overwriting
     * an input file.</p>
     *
     * @param odfStream - an inputStream representing the ODF package
     * @throws java.lang.Exception - if the package could not be created
     */
    private OdfPackage(InputStream odfStream) throws Exception {
        this();
        //File tempFile = TempDir.saveStreamToTempDir(odfStream, getTempDir());
        //initialize(tempFile,true);
        // quite like the idea above... why is this commented? Let's keep it:
        File tempFile = newTempSourceFile(odfStream);
        initialize(tempFile);
    }

    /**
     * Loads an OdfPackage from the given filePath.
     *
     * <p>OdfPackage relies on the file being available for read access over
     * the whole lifecycle of OdfPackage. Please refer to the documentation
     * of the save methods to decide whether overwriting the input file
     * is allowed.</p>
     *
     * @param odfPath - the filePath to the ODF package
     * @return the OpenDocument document represented as an OdfPackage
     * @throws java.lang.Exception - if the package could not be loaded
     */
    public static OdfPackage loadPackage(String odfPath) throws Exception {
        return new OdfPackage(odfPath);
    }

    /**
     * Loads an OdfPackage from the OpenDocument provided by a File.
     *
     * <p>OdfPackage relies on the file being available for read access over
     * the whole lifecycle of OdfPackage. Please refer to the documentation
     * of the save methods to decide whether overwriting the input file
     * is allowed.</p>
     *
     * @param odfFile - a File to loadPackage content from
     * @return the OpenDocument document represented as an OdfPackage
     * @throws java.lang.Exception - if the package could not be loaded
     */
    public static OdfPackage loadPackage(File odfFile) throws Exception {
        return new OdfPackage(odfFile);
    }

    /**
     * Creates an OdfPackage from the OpenDocument provided by a InputStream.
     *
     * <p>Since an InputStream does not provide the arbitrary (non sequentiell)
     * read access needed by OdfPackage, the InputStream is cached. This usually
     * takes more time compared to the other loadPackage methods.
     * An advantage of caching is that there are no problems overwriting
     * an input file.</p>
     *
     * @param odfStream - an inputStream representing the ODF package
     * @return the OpenDocument document represented as an OdfPackage
     * @throws java.lang.Exception - if the package could not be loaded
     */
    public static OdfPackage loadPackage(InputStream odfStream) throws Exception {
        return new OdfPackage(odfStream);
    }

    private void initialize(File odfFile) throws Exception {
        mBaseURI = getBaseURIFromFile(odfFile);

        if (mTempDirParent == null) {
            // getParentFile() returns already java.io.tmpdir when package is an odfStream
            mTempDirParent = odfFile.getAbsoluteFile().getParentFile();
            if (!mTempDirParent.canWrite()) {
                mTempDirParent = null;  // java.io.tmpdir will be used implicitly
            }
        }

        mZipFile = new ZipFile(odfFile);
        Enumeration<? extends ZipEntry> entries = mZipFile.entries();

        while (entries.hasMoreElements()) {
            ZipEntry zipEntry = entries.nextElement();
            mZipEntries.put(zipEntry.getName(), zipEntry);
            // TODO: think about if the additional list mPackageEntries is necessary -
            // shouldn't everything be part of one of the other lists?
            // mabe keep this as "master", rename it?
            mPackageEntries.add(zipEntry.getName());
            if (zipEntry.getName().equals(OdfPackage.OdfFile.MEDIA_TYPE.getPath())) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                StreamHelper.stream(mZipFile.getInputStream(zipEntry), out);
                try {
                    mMediaType = new String(out.toByteArray(), 0, out.size(), "UTF-8");
                } catch (UnsupportedEncodingException ex) {
                    mLog.log(Level.SEVERE, null, ex);
                }
            }
        }
    }

    private File newTempSourceFile(InputStream odfStream) throws Exception {
        // no idea yet what type of file this will be, so we take .tmp
        File odfFile = new File(getTempDir(), "theFile.tmp");  
        // copy stream to temp file
        FileOutputStream os = new FileOutputStream(odfFile);
        StreamHelper.stream(odfStream, os);
        os.close();
        return odfFile;
    }
    
    /**
     * Set the baseURI for this ODF package. NOTE: Should only be set during saving the package.
     */
    void setBaseURI(String baseURI) {
        mBaseURI = baseURI;
    }

    /**
     * Get the URI, where this ODF package is stored. 
     * @return the URI to the ODF package. Returns null if package is not stored yet.
     */
    public String getBaseURI() {
        return mBaseURI;
    }

    /**
     * Get the media type of the ODF package (equal to media type of ODF root document)
     * 
     * @return the mediaType string of this ODF package
     */
    public String getMediaType() {
        return mMediaType;
    }

    /**
     * Set the media type of the ODF package (equal to media type of ODF root document)
     * 
     * @param mediaType string of this ODF package
     */
    public void setMediaType(String mediaType) {
        mMediaType = mediaType;
        mPackageEntries.remove(OdfPackage.OdfFile.MEDIA_TYPE.getPath());
        if (mMediaType != null) {
            mPackageEntries.add(0, OdfPackage.OdfFile.MEDIA_TYPE.getPath());
        }
    }

    /**
     * 
     * Get an OdfFileEntry for the packagePath
     * NOTE: This method should be better moved to a DOM inherited Manifest class
     * 
     * @param packagePath The relative package path within the ODF package
     * @return The manifest file entry will be returned.
     */
    public OdfFileEntry getFileEntry(String packagePath) {
        packagePath = ensureValidPackagePath(packagePath);
        if (mManifestEntries == null) {
            try {
                parseManifest();
            } catch (Exception ex) {
                mLog.log(Level.SEVERE, null, ex);
            }
        }
        return mManifestEntries.get(packagePath);
    }

    /**
     * Get a OdfFileEntries from the manifest file (i.e. /META/manifest.xml")
     * @return The manifest file entries will be returned.
     */
    public Set<String> getFileEntries() {
        if (mManifestEntries == null) {
            try {
                parseManifest();
            } catch (Exception ex) {
                mLog.log(Level.SEVERE, null, ex);
            }
        }
        return mManifestEntries.keySet();
    }

    /**
     * 
     * Check existence of a file in the package. 
     * 
     * @param packagePath The relative package filePath within the ODF package
     * @return True if there is an entry and a file for the given filePath
     */
    public boolean contains(String packagePath) {
        packagePath = ensureValidPackagePath(packagePath);
        return mPackageEntries.contains(packagePath);
        // TODO: return true for later added stuff
//        return (mPackageEntries.contains(packagePath) && (mTempFiles.get(packagePath) != null || mContentStreams.get(packagePath)!=null) && getFileEntry(packagePath) != null);
    }

    /**
     * Save the package to given filePath.
     *
     * <p>If the input file has been cached (this is the case when loading from an
     * InputStream), the input file can be overwritten.</p>
     *
     * <p>Otherwise it's allowed to overwrite the input file as long as
     * the same path name is used that was used for loading (no symbolic link
     * foo2.odt pointing to the loaded file foo1.odt, no network path X:\foo.odt
     * pointing to the loaded file D:\foo.odt).</p>
     *
     * @param odfPath - the path to the ODF package destination
     * @throws java.lang.Exception - if the package could not be saved
     */
    public void save(String odfPath) throws Exception {
        File f = new File(odfPath);
        save(f);
    }

    /**
     * Save package to a given File.
     *
     * <p>If the input file has been cached (this is the case when loading from an
     * InputStream), the input file can be overwritten.</p>
     *
     * <p>Otherwise it's allowed to overwrite the input file as long as
     * the same path name is used that was used for loading (no symbolic link
     * foo2.odt pointing to the loaded file foo1.odt, no network path X:\foo.odt
     * pointing to the loaded file D:\foo.odt).</p>
     *
     * @param odfFile - the File to save the ODF package to
     * @throws java.lang.Exception - if the package could not be saved
     */
    public void save(File odfFile) throws Exception {

        String baseURI = odfFile.getCanonicalFile().toURI().toString();
        if (File.separatorChar == '\\') {
            baseURI = baseURI.replaceAll("\\\\", SLASH);
        }
        if (baseURI.equals(mBaseURI)) {
            // save to the same file: cache everything first
            // TODO: maybe it's better to write to a new file and copy that
            // to the original one - would be less memory footprint
            cacheContent();
        }
        FileOutputStream fos = new FileOutputStream(odfFile);
        save(fos, baseURI);
        if (baseURI.equals(mBaseURI)) {
            mZipFile.close();
            this.initialize(odfFile);
        }
    }

    /**
     * Save an ODF document to the OutputStream.
     *
     * <p>If the input file has been cached (this is the case when loading from an
     * InputStream), the input file can be overwritten.</p>
     *
     * <p>If not, the OutputStream may not point to the input file! Otherwise
     * this will result in unwanted behaviour and broken files.</p>
     *
     * @param odfStream - the OutputStream to insert content to
     * @throws java.lang.Exception - if the package could not be saved
     */
    public void save(OutputStream odfStream) throws Exception {
        save(odfStream, null);
    }

    private void save(OutputStream odfStream, String baseURI) throws Exception {

        mBaseURI = baseURI;

        if (mManifestEntries == null) {
            try {
                parseManifest();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        OdfFileEntry rootEntry = mManifestEntries.get(SLASH);
        if (rootEntry == null) {
            rootEntry = new OdfFileEntry(SLASH, mMediaType);
            mManifestList.add(0, rootEntry.getPath());

        } else {
            rootEntry.setMediaType(mMediaType);
        }

        ZipOutputStream zos = new ZipOutputStream(odfStream);
        long modTime = (new java.util.Date()).getTime();

        // move manifest to first place to ensure it is written first
        // into the package zip file
        if (mPackageEntries.contains(OdfFile.MEDIA_TYPE.getPath())) {
            mPackageEntries.remove(OdfFile.MEDIA_TYPE.getPath());
            mPackageEntries.add(0, OdfFile.MEDIA_TYPE.getPath());
        }

        Iterator<String> it = mPackageEntries.iterator();
        while (it.hasNext()) {
            String key = it.next();
            byte[] data = getBytes(key);

            ZipEntry ze = mZipEntries.get(key);
            if (ze == null) {
                ze = new ZipEntry(key);
            }
            ze.setTime(modTime);
            // 2DO Svante: No dependency to layer above!
            if (key.equals(OdfPackage.OdfFile.MEDIA_TYPE.getPath()) || key.equals(OdfDocument.OdfXMLFile.META.getFileName())) {
                ze.setMethod(ZipEntry.STORED);
            } else {
                ze.setMethod(ZipEntry.DEFLATED);
            }

            CRC32 crc = new CRC32();
            if (data != null) {
                crc.update(data);
                ze.setSize(data.length);
            } else {
                ze.setMethod(ZipEntry.STORED);
                ze.setSize(0);
            }
            ze.setCrc(crc.getValue());
            ze.setCompressedSize(-1);
            zos.putNextEntry(ze);
            if (data != null) {
                zos.write(data, 0, data.length);
            }
            zos.closeEntry();

            mZipEntries.put(key, ze);
        }
        zos.close();
        odfStream.flush();
    }

    /**
     * If this file is saved to itself, we have to cache it. It is not possible
     * to read and write from the same zip file at the same time, so the content
     * must be read and stored in memory.
     */
    private void cacheContent() throws Exception {
        // read all entries
        // parse manifest first to make sure this won't happen later
        if (mManifestEntries == null) {
            parseManifest();
        }
        // open all entries once so the data is cached
        Iterator<String> entries = mZipEntries.keySet().iterator();
        while(entries.hasNext()) {
            ZipEntry nextElement = mZipEntries.get(entries.next());
            String entryPath = nextElement.getName();
            getBytes(entryPath);
        }
    }

    /**
     * Close the OdfPackage and release all temporary created data.
     * Acter execution of this method, this class is no longer usable.
     * Do this as the last action to free resources.
     * Closing an already closed document has no effect.
     */
    public void close() {
        if (mTempDir != null) {
            TempDir.deleteTempOdfDirectory(mTempDir);
        }
        if (mZipFile != null) {
            try {
                mZipFile.close();
            } catch (IOException ex) {
                // log exception and continue
                Logger.getLogger(OdfPackage.class.getName()).log(Level.INFO, null, ex);
            }
        }
        // release all stuff - this class is impossible to use afterwards
        mZipFile = null;
        mTempDirParent = null;
        mTempDir = null;
        mMediaType = null;
        mPackageEntries = null;
        mZipEntries = null;
        mContentDoms = null;
        mContentStreams = null;
        mTempFiles = null;
        mManifestList = null;
        mManifestEntries = null;
        mBaseURI = null;
        mResolver = null;
    }

    /*
    public DocumentProperties getDocumentProperties() {
    return new DocumentProperties(this);
    }
    //     */
//    /**
//     * get ODFDOM Document for document in this package
//     */
//    OdfDocument getOdfDocument() throws SAXException, Exception {
//        OdfDocumentFactory builder = OdfDocumentFactory.newInstance();
//        OdfDocument doc = builder.parse(this);
//        // the OdfDocument reads content and styles, so those need to be detached
//        // from the package
//        if (doc != null) {
//            mContentDoms.put(STREAMNAME_CONTENT, doc);
//            mContentDoms.put(STREAMNAME_STYLES, doc);
//            mContentStreams.remove(STREAMNAME_CONTENT);
//            mContentStreams.remove(STREAMNAME_STYLES);
//        }
//        return doc;
//    }
//    /**
//     * get Stream for XML Subcontent
//     *
//     * @throws IllegalArgumentException
//     * if filetype of subcontent is not text/xmlo
//     */
//    public InputStream getXMLInputStream(String filePath)
//            throws Exception {
//
//        if (filePath.equals(OdfPackage.OdfXMLFile.MANIFEST.filePath)) {
//            if (mContentStreams.get(filePath) == null) {
//                throw new Exception(mBaseURI + ": " + filePath + " not found in package");
//            }
//        } else {
//            if (mManifestEntries == null) {
//                try {
//                    parseManifest();
//                } catch (Exception ex) {
//                    mLog.log(Level.SEVERE, null, ex);
//                }
//            }
//            OdfFileEntry fileEntry = (OdfFileEntry) mManifestEntries.get(filePath);
//            if (fileEntry == null) {
//                throw new Exception(mBaseURI + ": " + filePath + " not found in package");
//            }
//            if (!XML_MEDIA_TYPE.equals(fileEntry.getMediaType())) {
//                throw new IllegalArgumentException(mBaseURI + ": " + filePath + " is not of type text/xml");
//            }
//        }
//        InputStream is = getInputStream(filePath);
//        if (is == null) {
//            throw new Exception(mBaseURI + ": " + filePath + " not found in package");
//        }
//        return is;
//    }
    /**
     * Data was updated, update mZipEntry and OdfFileEntry as well
     */
    private void entryUpdate(String packagePath)
            throws Exception, SAXException,
            TransformerConfigurationException, TransformerException,
            ParserConfigurationException {

        byte[] data = getBytes(packagePath);
        int size = 0;
        if (data == null) {
            size = 0;
        } else {
            size = data.length;
        }
        if (mManifestEntries == null) {
            parseManifest();
        }
        OdfFileEntry fileEntry = mManifestEntries.get(packagePath);
        ZipEntry zipEntry = mZipEntries.get(packagePath);
        if (zipEntry == null) {
            return;
        }
        if (fileEntry != null) {
            if (XML_MEDIA_TYPE.equals(fileEntry.getMediaType())) {
                fileEntry.setSize(-1);
            } else {
                fileEntry.setSize(size);
            }
        }
        zipEntry.setSize(size);
        CRC32 crc = new CRC32();
        if ((data != null) && size > 0) {
            crc.update(data);
        }
        zipEntry.setCrc(crc.getValue());
        zipEntry.setCompressedSize(-1);
        long modTime = (new java.util.Date()).getTime();
        zipEntry.setTime(modTime);

    }

    /**
     * Parse the Manifest file
     */
    void parseManifest() throws Exception {

        InputStream is = getInputStream(OdfPackage.OdfFile.MANIFEST.packagePath);
        if (is == null) {
            mManifestList = null;
            mManifestEntries = null;
            return;
        }

        mManifestList = new LinkedList<String>();

        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setValidating(false);

        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        try {
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        } catch (Exception ex) {
            mLog.log(Level.SEVERE, null, ex);
        }

        SAXParser parser = factory.newSAXParser();
        XMLReader xmlReader = parser.getXMLReader();
        // More details at http://xerces.apache.org/xerces2-j/features.html#namespaces
        xmlReader.setFeature("http://xml.org/sax/features/namespaces", true);
        // More details at http://xerces.apache.org/xerces2-j/features.html#namespace-prefixes
        xmlReader.setFeature("http://xml.org/sax/features/namespace-prefixes", true);
        // More details at http://xerces.apache.org/xerces2-j/features.html#xmlns-uris
        xmlReader.setFeature("http://xml.org/sax/features/xmlns-uris", true);

        xmlReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

        String uri = mBaseURI + OdfPackage.OdfFile.MANIFEST.packagePath;
        xmlReader.setEntityResolver(getEntityResolver());
        xmlReader.setContentHandler(new ManifestContentHandler());

        InputSource ins = new InputSource(is);
        ins.setSystemId(uri);

        xmlReader.parse(ins);

        mContentStreams.remove(OdfPackage.OdfFile.MANIFEST.packagePath);
        entryUpdate(OdfPackage.OdfFile.MANIFEST.packagePath);
    }

    /** Checks if packagePath is not null nor empty and not an external reference */
    private String ensureValidPackagePath(String packagePath) {
        if (packagePath == null) {
            String errMsg = "The packagePath given by parameter is NULL!";
            mLog.severe(errMsg);
            throw new IllegalArgumentException(errMsg);
        } else if (packagePath.equals(EMPTY_STRING)) {
            String errMsg = "The packagePath given by parameter is an empty string!";
            mLog.severe(errMsg);
            throw new IllegalArgumentException(errMsg);
        } else {
            if (packagePath.indexOf('\\') != -1) {
                packagePath = packagePath.replace('\\', '/');
            }
            if (isExternalReference(packagePath)) {
                String errMsg = "The packagePath given by parameter '" + packagePath + "' is not an internal ODF package path!";
                mLog.severe(errMsg);
                throw new IllegalArgumentException(errMsg);
            }
        }
        return packagePath;
    }

    /**
     * add a directory to the OdfPackage
     */
    private void addDirectory(String packagePath) throws Exception {
        packagePath = ensureValidPackagePath(packagePath);

        if ((packagePath.length() < 1) || (packagePath.charAt(packagePath.length() - 1) != '/')) {
            packagePath = packagePath + SLASH;
        }
        insert((byte[]) null, packagePath, null);

    }
    
 
    
    
    /**
     * Insert DOM tree into OdfPackage. An existing file will be replaced.
     * @param fileDOM - XML DOM tree to be inserted as file
     * @param packagePath - relative filePath where the DOM tree should be inserted as XML file
     * @param mediaType - media type of stream. Set to null if unknown
     * @throws java.lang.Exception when the DOM tree could not be inserted
     */
    public void insert(Document fileDOM, String packagePath, String mediaType) throws Exception {    
        packagePath = ensureValidPackagePath(packagePath);

        if (mManifestEntries == null) {
            try {
                parseManifest();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        if(mediaType == null) {
            mediaType = XML_MEDIA_TYPE;
        }
        String d = EMPTY_STRING;
        StringTokenizer tok = new StringTokenizer(packagePath, SLASH);
        {
            while (tok.hasMoreTokens()) {
                String s = tok.nextToken();
                if (EMPTY_STRING.equals(d)) {
                    d = s + SLASH;
                } else {
                    d = d + s + SLASH;
                }
                if (tok.hasMoreTokens()) {
                    if (!mPackageEntries.contains(d)) {
                        addDirectory(d);
                    }
                }
            }
        }

        mContentStreams.remove(packagePath);
        if (fileDOM == null) {
            mContentDoms.remove(packagePath);
        } else {
            mContentDoms.put(packagePath, fileDOM);
        }

        if (!mPackageEntries.contains(packagePath)) {
            mPackageEntries.add(packagePath);
        }

        try {
            if (!OdfPackage.OdfFile.MANIFEST.packagePath.equals(packagePath)) {
                if (mManifestEntries != null && mManifestEntries.get(packagePath) == null) {
                    OdfFileEntry fileEntry = new OdfFileEntry(packagePath, mediaType);
                    mManifestEntries.put(packagePath, fileEntry);
                    mManifestList.add(packagePath);
                }
            } else {
                parseManifest();
            }

            ZipEntry ze = mZipEntries.get(packagePath);
            if (ze != null) {
                ze = new ZipEntry(packagePath);
                ze.setMethod(ZipEntry.DEFLATED);
                mZipEntries.put(packagePath, ze);
            }
            // 2DO Svante: No dependency to layer above!            
            if (packagePath.equals(OdfPackage.OdfFile.MEDIA_TYPE.getPath()) || packagePath.equals(OdfDocument.OdfXMLFile.META.getFileName())) {
                ze.setMethod(ZipEntry.STORED);
            }

            entryUpdate(packagePath);
        } catch (SAXException se) {
            throw new Exception("SAXException:" + se.getMessage());
        } catch (ParserConfigurationException pce) {
            throw new Exception("ParserConfigurationException:" + pce.getMessage());
        } catch (TransformerConfigurationException tce) {
            throw new Exception("TransformerConfigurationException:" + tce.getMessage());
        } catch (TransformerException te) {
            throw new Exception("TransformerException:" + te.getMessage());
        }
    }

    /**
     * returns true if a DOM tree has been requested
     * for given sub-content of OdfPackage
     * @param packagePath - a path inside the OdfPackage eg to a content.xml stream
     * @return - wether the package class internally has a DOM representation for the given path
     */
    public boolean hasDom(String packagePath) {
        return (mContentDoms.get(packagePath) != null);
    }

    /**
     * Gets org.w3c.dom.Document for XML file contained in package.
     * @param packagePath - a path inside the OdfPackage eg to a content.xml stream
     * @return an org.w3c.dom.Document
     * @throws SAXException
     * @throws ParserConfigurationException
     * @throws Exception
     * @throws IllegalArgumentException 
     * @throws TransformerConfigurationException
     * @throws TransformerException
     */
    public Document getDom(String packagePath)
            throws SAXException, ParserConfigurationException,
            Exception, IllegalArgumentException,
            TransformerConfigurationException, TransformerException {

        Document doc = mContentDoms.get(packagePath);
        if (doc != null) {
            return doc;
        }

        InputStream is = getInputStream(packagePath);

        // We depend on Xerces. So we just go ahead and create a Xerces DBF, without
        // forcing everything else to do so.
        DocumentBuilderFactory factory = new org.apache.xerces.jaxp.DocumentBuilderFactoryImpl();
        factory.setNamespaceAware(true);
        factory.setValidating(false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.setEntityResolver(getEntityResolver());

        String uri = getBaseURI() + packagePath;

//        if (mErrorHandler != null) {
//            builder.setErrorHandler(mErrorHandler);
//        }

        InputSource ins = new InputSource(is);
        ins.setSystemId(uri);

        doc = builder.parse(ins);

        if (doc != null) {
            mContentDoms.put(packagePath, doc);
//            mContentStreams.remove(packagePath);
        }
        return doc;
    }

    /**
     * Inserts InputStream into an OdfPackage. An existing file will be replaced.
     * @param sourceURI - the source URI to the file to be inserted into the package.
     * @param mediaType - media type of stream. Set to null if unknown
     * @param packagePath - relative filePath where the tree should be inserted as XML file          
     * @throws java.lang.Exception In case the file could not be saved
     */
    public void insert(URI sourceURI, String packagePath, String mediaType) throws Exception {
        InputStream is = null;
        if (sourceURI.isAbsolute()) {
            // if the URI is absolute it can be converted to URL
            is = sourceURI.toURL().openStream();
        } else {
            // otherwise create a file class to open the stream
            is = new FileInputStream(sourceURI.toString());
            // TODO: error handling in this case! -> allow method insert(URI, ppath, mtype)?
        }
        insert(is, packagePath, mediaType);
    }
    
    /**
     * Inserts InputStream into an OdfPackage. An existing file will be replaced.
     * @param fileStream - the stream of the file to be inserted into the ODF package.
     * @param mediaType - media type of stream. Set to null if unknown
     * @param packagePath - relative filePath where the tree should be inserted as XML file          
     * @throws java.lang.Exception In case the file could not be saved
     */
    public void insert(InputStream fileStream, String packagePath, String mediaType)
            throws Exception {
        packagePath = ensureValidPackagePath(packagePath);

        if (fileStream == null) {
            insert((byte[]) null, packagePath, mediaType);
        } else {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            BufferedInputStream bis = new BufferedInputStream(fileStream);
            StreamHelper.stream(bis, baos);
            byte[] data = baos.toByteArray();
            insert(data, packagePath, mediaType);
            // image should not be stored in memory but on disc
            if ((!packagePath.endsWith(".xml")) && (!packagePath.equals(OdfPackage.OdfFile.MEDIA_TYPE.getPath()))) {
                // insertOutputStream to filesystem
                File tempFile = new File(getTempDir(), packagePath);
                File parent = tempFile.getParentFile();
                parent.mkdirs();
                OutputStream fos = new BufferedOutputStream(new FileOutputStream(tempFile));
                fos.write(data);
                fos.close();
                mTempFiles.put(packagePath, tempFile);
                mContentStreams.remove(packagePath);
            }

        }
    }
    
    /**
     * Insert byte array into OdfPackage. An existing file will be replaced.
     * @param fileBytes - data of the file stream to be stored in package
     * @param mediaType - media type of stream. Set to null if unknown
     * @param packagePath - relative filePath where the DOM tree should be inserted as XML file
     * @throws java.lang.Exception when the DOM tree could not be inserted
     */
    public void insert(byte[] fileBytes, String packagePath, String mediaType) throws Exception {
        packagePath = ensureValidPackagePath(packagePath);

        String d = EMPTY_STRING;
        //2DO: Test tokenizer for whitespaces..
        StringTokenizer tok = new StringTokenizer(packagePath, SLASH);
        {
            while (tok.hasMoreTokens()) {
                String s = tok.nextToken();
                if (EMPTY_STRING.equals(d)) {
                    d = s + SLASH;
                } else {
                    d = d + s + SLASH;
                }
                if (tok.hasMoreTokens()) {
                    if (!mPackageEntries.contains(d)) {
                        addDirectory(d);
                        // add manifest entry for folder if not already existing
                        // media type for folder has to be set for embedded objects
                        if (!OdfPackage.OdfFile.MANIFEST.packagePath.equals(d)) {
                            if (mediaType != null) {
                                if (mManifestEntries.get(d) == null) {
                                    OdfFileEntry fileEntry = new OdfFileEntry(d, mediaType);
                                    mManifestEntries.put(d, fileEntry);
                                    if (!mManifestList.contains(d)) {
                                        mManifestList.add(d);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        try {
            if (OdfPackage.OdfFile.MEDIA_TYPE.getPath().equals(packagePath)) {
                try {
                    setMediaType(new String(fileBytes, "UTF-8"));
                } catch (UnsupportedEncodingException useEx) {
                    mLog.log(Level.WARNING, "ODF file could not be created as string!", useEx);
                }
                return;
            }
            if (fileBytes == null) {
                mContentStreams.remove(packagePath);
            } else {
                mContentStreams.put(packagePath, fileBytes);
            }
            if (!mPackageEntries.contains(packagePath)) {
                mPackageEntries.add(packagePath);
            }
            if (!OdfPackage.OdfFile.MANIFEST.packagePath.equals(packagePath)) {
                if (mediaType != null) {
                    if (mManifestEntries.get(packagePath) == null) {
                        OdfFileEntry fileEntry = new OdfFileEntry(packagePath, mediaType);
                        mManifestEntries.put(packagePath, fileEntry);
                        if (!mManifestList.contains(packagePath)) {
                            mManifestList.add(packagePath);
                        }
                    }
                }
            } else {
                parseManifest();
            }
            ZipEntry ze = mZipEntries.get(packagePath);
            if (ze != null) {
                ze = new ZipEntry(packagePath);
                ze.setMethod(ZipEntry.DEFLATED);
                mZipEntries.put(packagePath, ze);
            }
            // 2DO Svante: No dependency to layer above!
            if (packagePath.equals(OdfPackage.OdfFile.MEDIA_TYPE.getPath()) || packagePath.equals(OdfDocument.OdfXMLFile.META.getFileName())) {
                ze.setMethod(ZipEntry.STORED);
            }
            entryUpdate(packagePath);
        } catch (SAXException se) {
            throw new Exception("SAXException:" + se.getMessage());
        } catch (ParserConfigurationException pce) {
            throw new Exception("ParserConfigurationException:" + pce.getMessage());
        } catch (TransformerConfigurationException tce) {
            throw new Exception("TransformerConfigurationException:" + tce.getMessage());
        } catch (TransformerException te) {
            throw new Exception("TransformerException:" + te.getMessage());
        }
    }

    private void insert(ZipEntry zipe, byte[] content) {
        if (content != null) {
            if (zipe.getName().equals(OdfPackage.OdfFile.MEDIA_TYPE.getPath())) {
                try {
                    mMediaType = new String(content, 0, content.length, "UTF-8");
                } catch (UnsupportedEncodingException ex) {
                    mLog.log(Level.SEVERE, null, ex);
                }
            } else {
                mContentStreams.put(zipe.getName(), content);
            }
        }
        if (!mPackageEntries.contains(zipe.getName())) {
            mPackageEntries.add(zipe.getName());
        }
        mZipEntries.put(zipe.getName(), zipe);
    }

    private void insert(ZipEntry zipe, File file) {
        if (file != null) {
            mTempFiles.put(zipe.getName(), file);
        }
        if (!mPackageEntries.contains(zipe.getName())) {
            mPackageEntries.add(zipe.getName());
        }
        mZipEntries.put(zipe.getName(), zipe);
    }

    /**
     * Get Manifest as String
     * NOTE: This functionality should better be moved to a DOM based Manifest class
     */
    String getManifestAsString() {
        if (mManifestEntries == null) {
            try {
                parseManifest();
                if (mManifestEntries == null) {
                    return null;
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        StringBuffer buf = new StringBuffer();

        buf.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        buf.append("<manifest:manifest xmlns:manifest=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\">\n");

        Iterator<String> it = mManifestList.iterator();
        while (it.hasNext()) {
            String key = it.next();
            String s = null;
            OdfFileEntry fileEntry = mManifestEntries.get(key);
            if (fileEntry != null) {
                buf.append(" <manifest:file-entry");
                s = fileEntry.getMediaType();
                if (s == null) {
                    s = EMPTY_STRING;
                }
                buf.append(" manifest:media-type=\"");
                buf.append(encodeXMLAttributes(s));
                buf.append("\"");
                s = fileEntry.getPath();

                if (s == null) {
                    s = EMPTY_STRING;
                }
                buf.append(" manifest:full-path=\"");
                buf.append(encodeXMLAttributes(s));
                buf.append("\"");
                int i = fileEntry.getSize();
                if (i > 0) {
                    buf.append(" manifest:size=\"");
                    buf.append(i);
                    buf.append("\"");
                }
                EncryptionData enc = fileEntry.getEncryptionData();

                if (enc != null) {
                    buf.append(">\n");
                    buf.append("  <manifest:encryption-data>\n");
                    Algorithm alg = enc.getAlgorithm();
                    if (alg != null) {
                        buf.append("   <manifest:algorithm");
                        s = alg.getName();
                        if (s == null) {
                            s = EMPTY_STRING;
                        }
                        buf.append(" manifest:algorithm-name=\"");
                        buf.append(encodeXMLAttributes(s));
                        buf.append("\"");
                        s = alg.getInitializationVector();
                        if (s == null) {
                            s = EMPTY_STRING;
                        }
                        buf.append(" manifest:initialization-vector=\"");
                        buf.append(encodeXMLAttributes(s));
                        buf.append("\"/>\n");
                    }
                    KeyDerivation keyDerivation = enc.getKeyDerivation();
                    if (keyDerivation != null) {
                        buf.append("   <manifest:key-derivation");
                        s = keyDerivation.getName();
                        if (s == null) {
                            s = EMPTY_STRING;
                        }
                        buf.append(" manifest:key-derivation-name=\"");
                        buf.append(encodeXMLAttributes(s));
                        buf.append("\"");
                        s = keyDerivation.getSalt();
                        if (s == null) {
                            s = EMPTY_STRING;
                        }
                        buf.append(" manifest:salt=\"");
                        buf.append(encodeXMLAttributes(s));
                        buf.append("\"");

                        buf.append(" manifest:iteration-count=\"");
                        buf.append(keyDerivation.getIterationCount());
                        buf.append("\"/>\n");
                    }
                    buf.append("  </manifest:encryption-data>\n");
                    buf.append(" </<manifest:file-entry>\n");
                } else {
                    buf.append("/>\n");
                }
            }
        }
        buf.append("</manifest:manifest>");

        return buf.toString();
    }

    /**
     * Get package (sub-) content as byte array
     * 
     * @param packagePath relative filePath to the package content
     * @return the unzipped package content as byte array
     * @throws java.lang.Exception
     */
    public byte[] getBytes(String packagePath)
            throws Exception {
        packagePath = ensureValidPackagePath(packagePath);
        byte[] data = null;

        if (packagePath == null || packagePath.equals(EMPTY_STRING)) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            save(baos, mBaseURI);
            return baos.toByteArray();
        }
        if (packagePath.equals(OdfPackage.OdfFile.MEDIA_TYPE.getPath())) {
            if (mMediaType == null) {
                return null;
            }
            try {
                data = mMediaType.getBytes("UTF-8");
            } catch (UnsupportedEncodingException use) {
                mLog.log(Level.SEVERE, null, use);
                return null;
            }
        } else if (mPackageEntries.contains(packagePath) && mContentDoms.get(packagePath) != null) {
            {
                Document doc = mContentDoms.get(packagePath);
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                
                DOMXSImplementationSourceImpl dis = new org.apache.xerces.dom.DOMXSImplementationSourceImpl();
                DOMImplementationLS impl = (DOMImplementationLS) dis.getDOMImplementation("LS");
                LSSerializer writer = impl.createLSSerializer();

                LSOutput output = impl.createLSOutput();
                output.setByteStream(baos);

                writer.write(doc, output);
                data = baos.toByteArray();
            }
        } else if (mPackageEntries.contains(packagePath) && mTempFiles.get(packagePath) != null) {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            InputStream is = new BufferedInputStream(new FileInputStream(mTempFiles.get(packagePath)));
            StreamHelper.stream(is, os);
            is.close();
            os.close();
            data = os.toByteArray();
        } else if (mPackageEntries.contains(packagePath) && mContentStreams.get(packagePath) != null) {
            data = mContentStreams.get(packagePath);
        } else if (packagePath.equals(OdfPackage.OdfFile.MANIFEST.packagePath)) {
            if (mManifestEntries == null) {
                // manifest was not present
                return null;
            }
            String s = getManifestAsString();
            if (s == null) {
                return null;
            } else {
                data = s.getBytes("UTF-8");
            }
        }

        if (data == null) { // not yet stored data; retrieve it.
            ZipEntry entry = null;
            if ((entry = mZipEntries.get(packagePath)) != null) {
                InputStream inputStream = mZipFile.getInputStream(entry);
                if (inputStream != null) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    StreamHelper.stream(inputStream, out);
                    data = out.toByteArray();
                    // store for further usage; do not care about manifest: that is handled exclusively
                    mContentStreams.put(packagePath, data);
                    if (!mPackageEntries.contains(packagePath))
                        mPackageEntries.add(packagePath);
                }
            }
        }

        return data;
    }

    /**
     * Get subcontent as InputStream
     * @param packagePath of the desired stream.
     * @return Inputstream of the ODF file within the package for the given path.
     * @throws Exception 
     */
    public InputStream getInputStream(String packagePath)
            throws Exception {

        packagePath = ensureValidPackagePath(packagePath);
        ZipEntry entry = null;
        if ((entry = mZipEntries.get(packagePath)) != null) {
            return mZipFile.getInputStream(entry);
        }
        if (mPackageEntries.contains(packagePath) && mTempFiles.get(packagePath) != null) {
            return new BufferedInputStream(new FileInputStream(mTempFiles.get(packagePath)));
        }

        byte[] data = getBytes(packagePath);
        if (data != null && data.length != 0) {
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            return bais;
        }
        return null;
    }

    /**
     * Gets the InputStream containing whole OdfPackage.
     * 
     * @return the ODF package as input stream
     * @throws java.lang.Exception - if the package could not be read
     */
    public InputStream getInputStream() throws Exception {
        final PipedOutputStream os = new PipedOutputStream();
        final PipedInputStream is = new PipedInputStream();

        is.connect(os);

        Thread thread1 = new Thread() {

            @Override
            public void run() {
                try {
                    save(os, mBaseURI);
                } catch (Exception e) {
                }
            }
        };

        Thread thread2 = new Thread() {

            @Override
            public void run() {
                try {
                    BufferedInputStream bis = new BufferedInputStream(is, StreamHelper.PAGE_SIZE);
                    BufferedOutputStream bos = new BufferedOutputStream(os, StreamHelper.PAGE_SIZE);
                    StreamHelper.stream(bis, bos);
                    is.close();
                    os.close();
                } catch (Exception ie) {
                }
            }
        };

        thread1.start();
        thread2.start();

        return is;
    }

    /**
     * Insert the OutputStream for into OdfPackage. An existing file will be replaced.
     * @param packagePath - relative filePath where the DOM tree should be inserted as XML file     
     * @return outputstream for the data of the file to be stored in package
     * @throws java.lang.Exception when the DOM tree could not be inserted
     */
    public OutputStream insertOutputStream(String packagePath) throws Exception {
        return insertOutputStream(packagePath, null);
    }

    /**
     * Insert the OutputStream - to be filled after method - when stream is closed into OdfPackage. 
     * An existing file will be replaced.   
     * @param packagePath - relative filePath where the DOM tree should be inserted as XML file     
     * @param mediaType - media type of stream
     * @return outputstream for the data of the file to be stored in package
     * @throws java.lang.Exception when the DOM tree could not be inserted
     */
    public OutputStream insertOutputStream(String packagePath, String mediaType) throws Exception {
        packagePath = ensureValidPackagePath(packagePath);
        final String fPath = packagePath;
        final OdfFileEntry fFileEntry = getFileEntry(packagePath);
        final String fMediaType = mediaType;

        ByteArrayOutputStream baos = new ByteArrayOutputStream() {

            @Override
            public void close() {
                try {
                    byte[] data = this.toByteArray();
                    if (fMediaType == null || fMediaType.length() == 0) {
                        insert(data, fPath, fFileEntry == null ? null : fFileEntry.getMediaType());
                    } else {
                        insert(data, fPath, fMediaType);
                    }
                    super.close();
                } catch (Exception ex) {
                    mLog.log(Level.SEVERE, null, ex);
                }
            }
        };
        return baos;
    }

//    /**
//     * get an InputStream with a specific filePath from the package.
//     *
//     * @throws IllegalArgumentException if sub-content is not XML
//     */
//    public InputStream getInputStream(String filePath) throws Exception {
//        return mZipFile.getInputStream(mZipFile.getEntry(filePath));
////        OdfPackageStream stream = new OdfPackageStream(this, filePath);
////        return stream;
//    }
    public void remove(String packagePath) {
        if (mManifestList != null && mManifestList.contains(packagePath)) {
            mManifestList.remove(packagePath);
        }
        if (mManifestEntries != null && mManifestEntries.containsKey(packagePath)) {
            mManifestEntries.remove(packagePath);
        }
        if (mZipEntries != null && mZipEntries.containsKey(packagePath)) {
            mZipEntries.remove(packagePath);
        }
        if (mTempFiles != null && mTempFiles.containsKey(packagePath)) {
            File file = mTempFiles.remove(packagePath);
            file.delete();
        }
        if (mPackageEntries != null && mPackageEntries.contains(packagePath)) {
            mPackageEntries.remove(packagePath);
        }
    }

    /** Checks if the given reference is a reference, which points outside the ODF package
     * @param fileRef the file reference to be checked
     * @return true if the reference is an package external reference
     */
    public static boolean isExternalReference(String fileRef) {
        boolean isExternalReference = false;
        // if the fileReference is a external relative filePath..
        if (fileRef.startsWith(TWO_DOTS) ||
                // or absolute filePath 
                fileRef.startsWith(SLASH) ||
                // or absolute IRI
                fileRef.contains(COLON)) {
            isExternalReference = true;
        }
        return isExternalReference;
    }

    /**
     * get Temp Directory. Create new temp directory on demand and register it
     * for removal by garbage collector
     */
    private File getTempDir() throws Exception {
        if (mTempDir == null) {
            mTempDir = TempDir.newTempOdfDirectory("ODF", mTempDirParent);
            mFinalize = new OdfFinalizablePackage(mTempDir);
        }
        return mTempDir;
    }

    /**
     * encoded XML Attributes
     */
    private String encodeXMLAttributes(String s) {
        String r = s.replaceAll("\"", "&quot;");
        r = r.replaceAll("'", "&apos;");
        return r;
    }

    private class ManifestContentHandler implements ContentHandler {

        private OdfFileEntry _currentFileEntry;
        private EncryptionData _currentEncryptionData;

        /**
         * Receive an object for locating the origin of SAX document events.
         */
        public void setDocumentLocator(Locator locator) {
        }

        /**
         * Receive notification of the beginning of a document.
         */
        public void startDocument() throws SAXException {
            mManifestList = new LinkedList<String>();
            mManifestEntries = new HashMap<String, OdfFileEntry>();
        }

        /**
         * Receive notification of the end of a document.
         */
        public void endDocument() throws SAXException {
        }

        /**
         * Begin the scope of a prefix-URI Namespace mapping.
         */
        public void startPrefixMapping(String prefix, String uri)
                throws SAXException {
        }

        /**
         * End the scope of a prefix-URI mapping.
         */
        public void endPrefixMapping(String prefix)
                throws SAXException {
        }

        /**
         * Receive notification of the beginning of an element.
         */
        public void startElement(String namespaceURI, String localName, String qName, Attributes atts)
                throws SAXException {

            if (localName.equals("file-entry")) {
                _currentFileEntry = new OdfFileEntry();
                _currentFileEntry.setPath(atts.getValue("manifest:full-path"));
                _currentFileEntry.setMediaType(atts.getValue("manifest:media-type"));
                if (atts.getValue("manifest:size") != null) {
                    try {
                        _currentFileEntry.setSize(Integer.parseInt(atts.getValue("manifest:size")));
                    } catch (NumberFormatException nfe) {
                        throw new SAXException("not a number: " + atts.getValue("manifest:size"));
                    }
                }
            } else if (localName.equals("encryption-data")) {
                _currentEncryptionData = new EncryptionData();
                if (_currentFileEntry != null) {
                    _currentEncryptionData.setChecksumType(atts.getValue("manifest:checksum-type"));
                    _currentEncryptionData.setChecksum(atts.getValue("manifest:checksum"));
                    _currentFileEntry.setEncryptionData(_currentEncryptionData);
                }
            } else if (localName.equals("algorithm")) {
                Algorithm algorithm = new Algorithm();
                algorithm.setName(atts.getValue("manifest:algorithm-name"));
                algorithm.setInitializationVector(atts.getValue("manifest:initialization-vector"));
                if (_currentEncryptionData != null) {
                    _currentEncryptionData.setAlgorithm(algorithm);
                }
            } else if (localName.equals("key-derivation")) {
                KeyDerivation keyDerivation = new KeyDerivation();
                keyDerivation.setName(atts.getValue("manifest:key-derivation-name"));
                keyDerivation.setSalt(atts.getValue("manifest:salt"));
                if (atts.getValue("manifest:iteration-count") != null) {
                    try {
                        keyDerivation.setIterationCount(Integer.parseInt(atts.getValue("manifest:iteration-count")));
                    } catch (NumberFormatException nfe) {
                        throw new SAXException("not a number: " + atts.getValue("manifest:iteration-count"));
                    }
                }
                if (_currentEncryptionData != null) {
                    _currentEncryptionData.setKeyDerivation(keyDerivation);
                }
            }

        }

        /**
         * Receive notification of the end of an element.
         */
        public void endElement(String namespaceURI, String localName, String qName)
                throws SAXException {
            if (localName.equals("file-entry")) {
                if (_currentFileEntry.getPath() != null) {
                    mManifestEntries.put(_currentFileEntry.getPath(), _currentFileEntry);
                }
                mManifestList.add(_currentFileEntry.getPath());
                _currentFileEntry = null;
            } else if (localName.equals("encryption-data")) {
                _currentEncryptionData = null;
            }
        }

        /**
         * Receive notification of character data.
         */
        public void characters(char[] ch, int start, int length)
                throws SAXException {
        }

        /**
         * Receive notification of ignorable whitespace in element content.
         */
        public void ignorableWhitespace(char[] ch, int start, int length)
                throws SAXException {
        }

        /**
         * Receive notification of a processing instruction.
         */
        public void processingInstruction(String target, String data)
                throws SAXException {
        }

        /**
         * Receive notification of a skipped entity.
         */
        public void skippedEntity(String name) throws SAXException {
        }
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
                throws SAXException {

            // This deactivates the attempt to loadPackage the Math DTD
            if (publicId != null && publicId.startsWith("-//OpenOffice.org//DTD Modified W3C MathML")) {
                return new InputSource(new ByteArrayInputStream("<?xml version='1.0' encoding='UTF-8'?>".getBytes()));
            }
            if (systemId != null) {
                if ((mBaseURI != null) && systemId.startsWith(mBaseURI)) {
                    if (systemId.equals(mBaseURI)) {
                        InputStream in = null;
                        try {
                            in = getInputStream();
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
                        if (systemId.length() > mBaseURI.length() + 1) {
                            InputStream in = null;
                            try {
                                String path = systemId.substring(mBaseURI.length() + 1);
                                in = getInputStream(path);
                                InputSource ins = new InputSource(in);
                                ins.setSystemId(systemId);
                                return ins;
                            } catch (Exception ex) {
                                mLog.log(Level.SEVERE, null, ex);
                            } finally {
                                try {
                                    in.close();
                                } catch (IOException ex) {
                                    mLog.log(Level.SEVERE, null, ex);
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
                    } catch (IOException ex) {
                        mLog.log(Level.SEVERE, null, ex);
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
                src.setSystemId(uri.toString());
                return src;
            } catch (URISyntaxException use) {
                return null;
            }
        }
    }

    /**
     * get EntityResolver to be used in XML Parsers
     * which can resolve content inside the OdfPackage
     * @return a SAX EntityResolver
     */
    public EntityResolver getEntityResolver() {
        if (mResolver == null) {
            mResolver = new Resolver();
        }
        return mResolver;
    }

    /**
     * get URIResolver to be used in XSL Transformations
     * which can resolve content inside the OdfPackage
     * @return a TraX Resolver
     */
    public URIResolver getURIResolver() {
        if (mResolver == null) {
            mResolver = new Resolver();
        }
        return mResolver;
    }

    private static String getBaseURIFromFile(File file) throws Exception {
        String baseURI = file.getCanonicalFile().toURI().toString();
        if (File.separatorChar == '\\') {
            baseURI = baseURI.replaceAll("\\\\", SLASH);
        }
        return baseURI;
    }
}

