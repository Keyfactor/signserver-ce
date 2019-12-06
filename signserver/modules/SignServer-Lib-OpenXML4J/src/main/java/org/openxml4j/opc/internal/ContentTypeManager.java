/* ====================================================================
   Licensed to the Apache Software Foundation (ASF) under one or more
   contributor license agreements.  See the NOTICE file distributed with
   this work for additional information regarding copyright ownership.
   The ASF licenses this file to You under the Apache License, Version 2.0
   (the "License"); you may not use this file except in compliance with
   the License.  You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
==================================================================== 

 * Copyright (c) 2006, Wygwam
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met: 
 * 
 * - Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation and/or 
 * other materials provided with the distribution.
 * - Neither the name of Wygwam nor the names of its contributors may be 
 * used to endorse or promote products derived from this software without 
 * specific prior written permission. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT 
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.openxml4j.opc.internal;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;
import java.util.Map.Entry;
import java.util.zip.ZipOutputStream;

import org.apache.log4j.Logger;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.Namespace;
import org.dom4j.QName;
import org.dom4j.io.SAXReader;
import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.exceptions.InvalidOperationException;
import org.openxml4j.exceptions.OpenXML4JRuntimeException;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackagePartName;
import org.openxml4j.opc.PackagingURIHelper;

/**
 * Manage package content types ([Content_Types].xml part).
 * 
 * @author Julien Chable
 * @version 1.0
 */
public abstract class ContentTypeManager {

	protected static Logger logger = Logger.getLogger("org.openxml4j");

	/**
	 * Reference to the package using this content type manager.
	 */
	protected Package container;

	/**
	 * Content type part name.
	 */
	public static final String CONTENT_TYPES_PART_NAME = "[Content_Types].xml";

	/**
	 * Content type namespace
	 */
	public static final String TYPES_NAMESPACE_URI = "http://schemas.openxmlformats.org/package/2006/content-types";

	/* Xml elements in content type part */

	private static final String TYPES_TAG_NAME = "Types";

	private static final String DEFAULT_TAG_NAME = "Default";

	private static final String EXTENSION_ATTRIBUTE_NAME = "Extension";

	private static final String CONTENT_TYPE_ATTRIBUTE_NAME = "ContentType";

	private static final String OVERRIDE_TAG_NAME = "Override";

	private static final String PART_NAME_ATTRIBUTE_NAME = "PartName";

	/**
	 * Default content type tree. <Extension, ContentType>
	 */
	private TreeMap<String, String> defaultContentType;

	/**
	 * Override content type tree.
	 */
	private TreeMap<PackagePartName, String> overrideContentType;

	/**
	 * Constructor. Parses the content of the specified input stream.
	 * 
	 * @param archive
	 *            If different of <i>null</i> then the content types part is
	 *            retrieve and parse.
	 * @throws InvalidFormatException
	 *             If the content types part content is not valid.
	 */
	public ContentTypeManager(InputStream in, Package pkg)
			throws InvalidFormatException {
		this.container = pkg;
		this.defaultContentType = new TreeMap<String, String>();
		if (in != null) {
			try {
				parseContentTypesFile(in);
			} catch (InvalidFormatException e) {
				throw new InvalidFormatException(
						"Can't read content types part !");
			}
		}
	}

	/**
	 * Build association extention-> content type (will be stored in
	 * [Content_Types].xml) for example ContentType="image/png" Extension="png"
	 * 
	 * [M2.8]: When adding a new part to a package, the package implementer
	 * shall ensure that a content type for that part is specified in the
	 * Content Types stream; the package implementer shall perform the steps
	 * described in §9.1.2.3:
	 * 
	 * 1. Get the extension from the part name by taking the substring to the
	 * right of the rightmost occurrence of the dot character (.) from the
	 * rightmost segment.
	 * 
	 * 2. If a part name has no extension, a corresponding Override element
	 * shall be added to the Content Types stream.
	 * 
	 * 3. Compare the resulting extension with the values specified for the
	 * Extension attributes of the Default elements in the Content Types stream.
	 * The comparison shall be case-insensitive ASCII.
	 * 
	 * 4. If there is a Default element with a matching Extension attribute,
	 * then the content type of the new part shall be compared with the value of
	 * the ContentType attribute. The comparison might be case-sensitive and
	 * include every character regardless of the role it plays in the
	 * content-type grammar of RFC 2616, or it might follow the grammar of RFC
	 * 2616.
	 * 
	 * a. If the content types match, no further action is required.
	 * 
	 * b. If the content types do not match, a new Override element shall be
	 * added to the Content Types stream. .
	 * 
	 * 5. If there is no Default element with a matching Extension attribute, a
	 * new Default element or Override element shall be added to the Content
	 * Types stream.
	 * 
	 * 
	 * @param partUri
	 *            the uri that will be stored
	 * @return <b>false</b> if an error occured.
	 */
	public void addContentType(PackagePartName partName, String contentType) {
		boolean defaultCTExists = false;
		String extension = partName.getExtension().toLowerCase();
		if ((extension.length() == 0)
				|| (this.defaultContentType.containsKey(extension) && !(defaultCTExists = this.defaultContentType
						.containsValue(contentType))))
			this.addOverrideContentType(partName, contentType);
		else if (!defaultCTExists)
			this.addDefaultContentType(extension, contentType);
	}

	/**
	 * Add an override content type for a specific part.
	 * 
	 * @param partName
	 *            Name of the part.
	 * @param contentType
	 *            Content type of the part.
	 */
	private void addOverrideContentType(PackagePartName partName,
			String contentType) {
		if (overrideContentType == null)
			overrideContentType = new TreeMap<PackagePartName, String>();
		overrideContentType.put(partName, contentType);
	}

	/**
	 * Add a content type associated with the specified extension.
	 * 
	 * @param extension
	 *            The part name extension to bind to a content type.
	 * @param contentType
	 *            The content type associated with the specified extension.
	 */
	private void addDefaultContentType(String extension, String contentType) {
		// Remark : Originally the latest parameter was :
		// contentType.toLowerCase(). Change due to a request ID 1996748.
		defaultContentType.put(extension.toLowerCase(), contentType);
	}

	/**
	 * Delete a content type based on the specified part name. If the specified
	 * part name is register with an override content type, then this content
	 * type is remove, else the content type is remove in the default content
	 * type list if it exists and if no part is associated with it yet.
	 * 
	 * Check rule M2.4: The package implementer shall require that the Content
	 * Types stream contain one of the following for every part in the package:
	 * One matching Default element One matching Override element Both a
	 * matching Default element and a matching Override element, in which case
	 * the Override element takes precedence.
	 * 
	 * @param partUri
	 *            The part URI associated with the override content type to
	 *            delete.
	 * @exception InvalidOperationException
	 *                Throws if
	 */
	public void removeContentType(PackagePartName partName)
			throws InvalidOperationException {
		if (partName == null)
			throw new IllegalArgumentException("partName");

		/* Override content type */
		if (this.overrideContentType != null
				&& (this.overrideContentType.get(partName) != null)) {
			// Remove the override definition for the specified part.
			this.overrideContentType.remove(partName);
			return;
		}

		/* Default content type */
		String extensionToDelete = partName.getExtension();
		boolean deleteDefaultContentTypeFlag = true;
		if (this.container != null) {
			try {
				for (PackagePart part : this.container.getParts()) {
					if (!part.getPartName().equals(partName)
							&& part.getPartName().getExtension()
									.equalsIgnoreCase(extensionToDelete)) {
						deleteDefaultContentTypeFlag = false;
						break;
					}
				}
			} catch (InvalidFormatException e) {
				throw new InvalidOperationException(e.getMessage());
			}
		}

		// Remove the default content type, no other part use this content type.
		if (deleteDefaultContentTypeFlag) {
			this.defaultContentType.remove(extensionToDelete);
		}

		/*
		 * Check rule 2.4: The package implementer shall require that the
		 * Content Types stream contain one of the following for every part in
		 * the package: One matching Default element One matching Override
		 * element Both a matching Default element and a matching Override
		 * element, in which case the Override element takes precedence.
		 */
		if (this.container != null) {
			try {
				for (PackagePart part : this.container.getParts()) {
					if (!part.getPartName().equals(partName)
							&& this.getContentType(part.getPartName()) == null)
						throw new InvalidOperationException(
								"Rule M2.4 is not respected: Nor a default element or override element is associated with the part: "
										+ part.getPartName().getName());
				}
			} catch (InvalidFormatException e) {
				throw new InvalidOperationException(e.getMessage());
			}
		}
	}

	/**
	 * Check if the specified content type is already register.
	 * 
	 * @param contentType
	 *            The content type to check.
	 * @return <code>true</code> if the specified content type is already
	 *         register, then <code>false</code>.
	 */
	public boolean isContentTypeRegister(String contentType) {
		if (contentType == null)
			throw new IllegalArgumentException("contentType");

		return (this.defaultContentType.values().contains(contentType) || (this.overrideContentType != null && this.overrideContentType
				.values().contains(contentType)));
	}

	/**
	 * Get the content type for the specified part, if any.
	 * 
	 * Rule [M2.9]: To get the content type of a part, the package implementer
	 * shall perform the steps described in §9.1.2.4:
	 * 
	 * 1. Compare the part name with the values specified for the PartName
	 * attribute of the Override elements. The comparison shall be
	 * case-insensitive ASCII.
	 * 
	 * 2. If there is an Override element with a matching PartName attribute,
	 * return the value of its ContentType attribute. No further action is
	 * required.
	 * 
	 * 3. If there is no Override element with a matching PartName attribute,
	 * then a. Get the extension from the part name by taking the substring to
	 * the right of the rightmost occurrence of the dot character (.) from the
	 * rightmost segment. b. Check the Default elements of the Content Types
	 * stream, comparing the extension with the value of the Extension
	 * attribute. The comparison shall be case-insensitive ASCII.
	 * 
	 * 4. If there is a Default element with a matching Extension attribute,
	 * return the value of its ContentType attribute. No further action is
	 * required.
	 * 
	 * 5. If neither Override nor Default elements with matching attributes are
	 * found for the specified part name, the implementation shall not map this
	 * part name to a part.
	 * 
	 * @param partUri
	 *            The URI part to check.
	 * @return The content type associated with the URI (in case of an override
	 *         content type) or the extension (in case of default content type),
	 *         else <code>null</code>.
	 * 
	 * @exception OpenXML4JRuntimeException
	 *                Throws if the content type manager is not able to find the
	 *                content from an existing part.
	 */
	public String getContentType(PackagePartName partName) {
		if (partName == null)
			throw new IllegalArgumentException("partName");

		if ((this.overrideContentType != null)
				&& this.overrideContentType.containsKey(partName))
			return this.overrideContentType.get(partName);

		String extension = partName.getExtension().toLowerCase();
		if (this.defaultContentType.containsKey(extension))
			return this.defaultContentType.get(extension);

		/*
		 * [M2.4] : The package implementer shall require that the Content Types
		 * stream contain one of the following for every part in the package:
		 * One matching Default element, One matching Override element, Both a
		 * matching Default element and a matching Override element, in which
		 * case the Override element takes precedence.
		 */
		if (this.container != null && this.container.getPart(partName) != null) {
			throw new OpenXML4JRuntimeException(
					"Rule M2.4 exception : this error should NEVER happen, if so please send a mail to the developers team, thanks !");
		} else {
			return null;
		}
	}

	/**
	 * Clear all content types.
	 */
	public void clearAll() {
		this.defaultContentType.clear();
		if (this.overrideContentType != null)
			this.overrideContentType.clear();
	}

	/**
	 * Clear all override content types.
	 * 
	 */
	public void clearOverrideContentTypes() {
		if (this.overrideContentType != null)
			this.overrideContentType.clear();
	}

	/**
	 * Parse the content types part.
	 * 
	 * @throws InvalidFormatException
	 *             Throws if the content type doesn't exist or the XML format is
	 *             invalid.
	 */
	private void parseContentTypesFile(InputStream in)
			throws InvalidFormatException {
		try {
			SAXReader xmlReader = new SAXReader();
			Document xmlContentTypetDoc = xmlReader.read(in);

			// Default content types
			List defaultTypes = xmlContentTypetDoc.getRootElement().elements(
					DEFAULT_TAG_NAME);
			Iterator elementIteratorDefault = defaultTypes.iterator();
			while (elementIteratorDefault.hasNext()) {
				Element element = (Element) elementIteratorDefault.next();
				String extension = element.attribute(EXTENSION_ATTRIBUTE_NAME)
						.getValue();
				String contentType = element.attribute(
						CONTENT_TYPE_ATTRIBUTE_NAME).getValue();
				addDefaultContentType(extension, contentType);
			}

			// Overriden content types
			List overrideTypes = xmlContentTypetDoc.getRootElement().elements(
					OVERRIDE_TAG_NAME);
			Iterator elementIteratorOverride = overrideTypes.iterator();
			while (elementIteratorOverride.hasNext()) {
				Element element = (Element) elementIteratorOverride.next();
				URI uri = new URI(element.attribute(PART_NAME_ATTRIBUTE_NAME)
						.getValue());
				PackagePartName partName = PackagingURIHelper
						.createPartName(uri);
				String contentType = element.attribute(
						CONTENT_TYPE_ATTRIBUTE_NAME).getValue();
				addOverrideContentType(partName, contentType);
			}
		} catch (URISyntaxException urie) {
			throw new InvalidFormatException(urie.getMessage());
		} catch (DocumentException e) {
			throw new InvalidFormatException(e.getMessage());
		}
	}

	/**
	 * Save the contents type part.
	 * 
	 * @param outStream
	 *            The output stream use to save the XML content of the content
	 *            types part.
	 * @return <b>true</b> if the operation success, else <b>false</b>.
	 */
	public boolean save(OutputStream outStream) {
		Document xmlOutDoc = DocumentHelper.createDocument();

		// Building namespace
		Namespace dfNs = Namespace.get("", TYPES_NAMESPACE_URI);
		Element typesElem = xmlOutDoc
				.addElement(new QName(TYPES_TAG_NAME, dfNs));

		// Adding default types
		for (Entry<String, String> entry : defaultContentType.entrySet()) {
			appendDefaultType(typesElem, entry);
		}

		// Adding specific types if any exist
		if (overrideContentType != null) {
			for (Entry<PackagePartName, String> entry : overrideContentType
					.entrySet()) {
				appendSpecificTypes(typesElem, entry);
			}
		}
		xmlOutDoc.normalize();

		// Save content in the specified output stream
		return this.saveImpl(xmlOutDoc, outStream);
	}

	/**
	 * Use to append specific type XML elements, use by the save() method.
	 * 
	 * @param root
	 *            XML parent element use to append this override type element.
	 * @param entry
	 *            The values to append.
	 * @see #save(ZipOutputStream)
	 */
	private void appendSpecificTypes(Element root,
			Entry<PackagePartName, String> entry) {
		root.addElement(OVERRIDE_TAG_NAME).addAttribute(
				PART_NAME_ATTRIBUTE_NAME,
				((PackagePartName) entry.getKey()).getName()).addAttribute(
				CONTENT_TYPE_ATTRIBUTE_NAME, (String) entry.getValue());
	}

	/**
	 * Use to append default types XML elements, use by the save() metid.
	 * 
	 * @param root
	 *            XML parent element use to append this default type element.
	 * @param entry
	 *            The values to append.
	 * @see #save(ZipOutputStream)
	 */
	private void appendDefaultType(Element root, Entry<String, String> entry) {
		root.addElement(DEFAULT_TAG_NAME).addAttribute(
				EXTENSION_ATTRIBUTE_NAME, (String) entry.getKey())
				.addAttribute(CONTENT_TYPE_ATTRIBUTE_NAME,
						(String) entry.getValue());

	}

	/**
	 * Specific implementation of the save method. Call by the save() method,
	 * call before exiting.
	 * 
	 * @param out
	 *            The output stream use to write the content type XML.
	 */
	public abstract boolean saveImpl(Document content, OutputStream out);
}
