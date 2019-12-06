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

package org.openxml4j.opc.internal.unmarshallers;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.List;
import java.util.zip.ZipEntry;

import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.Namespace;
import org.dom4j.QName;
import org.dom4j.io.SAXReader;
import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.exceptions.OpenXML4JException;
import org.openxml4j.opc.PackageNamespaces;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackageProperties;
import org.openxml4j.opc.ZipPackage;
import org.openxml4j.opc.internal.PackagePropertiesPart;
import org.openxml4j.opc.internal.PartUnmarshaller;
import org.openxml4j.opc.internal.ZipHelper;

/**
 * Package properties unmarshaller.
 * 
 * @author Julien Chable
 * @version 1.0
 */
public class PackagePropertiesUnmarshaller implements PartUnmarshaller {

	private final static Namespace namespaceDC = new Namespace("dc",
			PackageProperties.NAMESPACE_DC);

	private final static Namespace namespaceCP = new Namespace("cp",
			PackageNamespaces.CORE_PROPERTIES);

	private final static Namespace namespaceDcTerms = new Namespace("dcterms",
			PackageProperties.NAMESPACE_DCTERMS);

	private final static Namespace namespaceXML = new Namespace("xml",
			"http://www.w3.org/XML/1998/namespace");

	private final static Namespace namespaceXSI = new Namespace("xsi",
			"http://www.w3.org/2001/XMLSchema-instance");

	protected static final String KEYWORD_CATEGORY = "category";

	protected static final String KEYWORD_CONTENT_STATUS = "contentStatus";

	protected static final String KEYWORD_CONTENT_TYPE = "contentType";

	protected static final String KEYWORD_CREATED = "created";

	protected static final String KEYWORD_CREATOR = "creator";

	protected static final String KEYWORD_DESCRIPTION = "description";

	protected static final String KEYWORD_IDENTIFIER = "identifier";

	protected static final String KEYWORD_KEYWORDS = "keywords";

	protected static final String KEYWORD_LANGUAGE = "language";

	protected static final String KEYWORD_LAST_MODIFIED_BY = "lastModifiedBy";

	protected static final String KEYWORD_LAST_PRINTED = "lastPrinted";

	protected static final String KEYWORD_MODIFIED = "modified";

	protected static final String KEYWORD_REVISION = "revision";

	protected static final String KEYWORD_SUBJECT = "subject";

	protected static final String KEYWORD_TITLE = "title";

	protected static final String KEYWORD_VERSION = "version";

	// TODO Load element with XMLBeans or dynamic table
	// TODO Check every element/namespace for compliance
	public PackagePart unmarshall(UnmarshallContext context, InputStream in)
			throws InvalidFormatException, IOException {
		PackagePropertiesPart coreProps = new PackagePropertiesPart(context
				.getPackage(), context.getPartName());

		// If the input stream is null then we try to get it from the
		// package.
		if (in == null) {
			if (context.getZipEntry() != null) {
				in = ((ZipPackage) context.getPackage()).getZipArchive()
						.getInputStream(context.getZipEntry());
			} else if (context.getPackage() != null) {
				// Try to retrieve the part inputstream from the URI
				ZipEntry zipEntry;
				try {
					zipEntry = ZipHelper
							.getCorePropertiesZipEntry((ZipPackage) context
									.getPackage());
				} catch (OpenXML4JException e) {
					throw new IOException(
							"Error while trying to get the part input stream.");
				}
				in = ((ZipPackage) context.getPackage()).getZipArchive()
						.getInputStream(zipEntry);
			} else
				throw new IOException(
						"Error while trying to get the part input stream.");
		}

		SAXReader xmlReader = new SAXReader();
		Document xmlDoc;
		try {
			xmlDoc = xmlReader.read(in);

			/* Check OPC compliance */

			// Rule M4.2, M4.3, M4.4 and M4.5/
			checkElementForOPCCompliance(xmlDoc.getRootElement());

			/* End OPC compliance */

		} catch (DocumentException e) {
			throw new IOException(e.getMessage());
		}

		coreProps.setCategoryProperty(loadCategory(xmlDoc));
		coreProps.setContentStatusProperty(loadContentStatus(xmlDoc));
		coreProps.setContentTypeProperty(loadContentType(xmlDoc));
		coreProps.setCreatedProperty(loadCreated(xmlDoc));
		coreProps.setCreatorProperty(loadCreator(xmlDoc));
		coreProps.setDescriptionProperty(loadDescription(xmlDoc));
		coreProps.setIdentifierProperty(loadIdentifier(xmlDoc));
		coreProps.setKeywordsProperty(loadKeywords(xmlDoc));
		coreProps.setLanguageProperty(loadLanguage(xmlDoc));
		coreProps.setLastModifiedByProperty(loadLastModifiedBy(xmlDoc));
		coreProps.setLastPrintedProperty(loadLastPrinted(xmlDoc));
		coreProps.setModifiedProperty(loadModified(xmlDoc));
		coreProps.setRevisionProperty(loadRevision(xmlDoc));
		coreProps.setSubjectProperty(loadSubject(xmlDoc));
		coreProps.setTitleProperty(loadTitle(xmlDoc));
		coreProps.setVersionProperty(loadVersion(xmlDoc));

		return coreProps;
	}

	private String loadCategory(Document xmlDoc) {
		Element el = xmlDoc.getRootElement().element(
				new QName(KEYWORD_CATEGORY, namespaceCP));
		if (el != null)
			return el.getStringValue();
		else
			return null;
	}

	private String loadContentStatus(Document xmlDoc) {
		Element el = xmlDoc.getRootElement().element(
				new QName(KEYWORD_CONTENT_STATUS, namespaceCP));
		if (el != null)
			return el.getStringValue();
		else
			return null;
	}

	private String loadContentType(Document xmlDoc) {
		Element el = xmlDoc.getRootElement().element(
				new QName(KEYWORD_CONTENT_TYPE, namespaceCP));
		if (el != null)
			return el.getStringValue();
		else
			return null;
	}

	private String loadCreated(Document xmlDoc) {
		Element el = xmlDoc.getRootElement().element(
				new QName(KEYWORD_CREATED, namespaceDcTerms));
		if (el != null)
			return el.getStringValue();
		else
			return null;
	}

	private String loadCreator(Document xmlDoc) {
		Element el = xmlDoc.getRootElement().element(
				new QName(KEYWORD_CREATOR, namespaceDC));
		if (el != null)
			return el.getStringValue();
		else
			return null;
	}

	private String loadDescription(Document xmlDoc) {
		Element el = xmlDoc.getRootElement().element(
				new QName(KEYWORD_DESCRIPTION, namespaceDC));
		if (el != null)
			return el.getStringValue();
		else
			return null;
	}

	private String loadIdentifier(Document xmlDoc) {
		Element el = xmlDoc.getRootElement().element(
				new QName(KEYWORD_IDENTIFIER, namespaceDC));
		if (el != null)
			return el.getStringValue();
		else
			return null;
	}

	private String loadKeywords(Document xmlDoc) {
		Element el = xmlDoc.getRootElement().element(
				new QName(KEYWORD_KEYWORDS, namespaceCP));
		if (el != null)
			return el.getStringValue();
		else
			return null;
	}

	private String loadLanguage(Document xmlDoc) {
		Element el = xmlDoc.getRootElement().element(
				new QName(KEYWORD_LANGUAGE, namespaceDC));
		if (el != null)
			return el.getStringValue();
		else
			return null;
	}

	private String loadLastModifiedBy(Document xmlDoc) {
		Element el = xmlDoc.getRootElement().element(
				new QName(KEYWORD_LAST_MODIFIED_BY, namespaceCP));
		if (el != null)
			return el.getStringValue();
		else
			return null;
	}

	private String loadLastPrinted(Document xmlDoc) {
		Element el = xmlDoc.getRootElement().element(
				new QName(KEYWORD_LAST_PRINTED, namespaceCP));
		if (el != null)
			return el.getStringValue();
		else
			return null;
	}

	private String loadModified(Document xmlDoc) {
		Element el = xmlDoc.getRootElement().element(
				new QName(KEYWORD_MODIFIED, namespaceDcTerms));
		if (el != null)
			return el.getStringValue();
		else
			return null;
	}

	private String loadRevision(Document xmlDoc) {
		Element el = xmlDoc.getRootElement().element(
				new QName(KEYWORD_REVISION, namespaceCP));
		if (el != null)
			return el.getStringValue();
		else
			return null;
	}

	private String loadSubject(Document xmlDoc) {
		Element el = xmlDoc.getRootElement().element(
				new QName(KEYWORD_SUBJECT, namespaceDC));
		if (el != null)
			return el.getStringValue();
		else
			return null;
	}

	private String loadTitle(Document xmlDoc) {
		Element el = xmlDoc.getRootElement().element(
				new QName(KEYWORD_TITLE, namespaceDC));
		if (el != null)
			return el.getStringValue();
		else
			return null;
	}

	private String loadVersion(Document xmlDoc) {
		Element el = xmlDoc.getRootElement().element(
				new QName(KEYWORD_VERSION, namespaceCP));
		if (el != null)
			return el.getStringValue();
		else
			return null;
	}

	/* OPC Compliance methods */

	/**
	 * Check the element for the following OPC compliance rules:
	 * 
	 * Rule M4.2: A format consumer shall consider the use of the Markup
	 * Compatibility namespace to be an error.
	 * 
	 * Rule M4.3: Producers shall not create a document element that contains
	 * refinements to the Dublin Core elements, except for the two specified in
	 * the schema: <dcterms:created> and <dcterms:modified> Consumers shall
	 * consider a document element that violates this constraint to be an error.
	 * 
	 * Rule M4.4: Producers shall not create a document element that contains
	 * the xml:lang attribute. Consumers shall consider a document element that
	 * violates this constraint to be an error.
	 * 
	 * Rule M4.5: Producers shall not create a document element that contains
	 * the xsi:type attribute, except for a <dcterms:created> or
	 * <dcterms:modified> element where the xsi:type attribute shall be present
	 * and shall hold the value dcterms:W3CDTF, where dcterms is the namespace
	 * prefix of the Dublin Core namespace. Consumers shall consider a document
	 * element that violates this constraint to be an error.
	 */
	public void checkElementForOPCCompliance(Element el)
			throws InvalidFormatException {
		// Check the current element
		List declaredNamespaces = el.declaredNamespaces();
		Iterator itNS = declaredNamespaces.iterator();
		while (itNS.hasNext()) {
			Namespace ns = (Namespace) itNS.next();

			// Rule M4.2
			if (ns.getURI().equals(PackageNamespaces.MARKUP_COMPATIBILITY))
				throw new InvalidFormatException(
						"OPC Compliance error [M4.2]: A format consumer shall consider the use of the Markup Compatibility namespace to be an error.");
		}

		// Rule M4.3
		if (el.getNamespace().getURI().equals(
				PackageProperties.NAMESPACE_DCTERMS)
				&& !(el.getName().equals(KEYWORD_CREATED) || el.getName()
						.equals(KEYWORD_MODIFIED)))
			throw new InvalidFormatException(
					"OPC Compliance error [M4.3]: Producers shall not create a document element that contains refinements to the Dublin Core elements, except for the two specified in the schema: <dcterms:created> and <dcterms:modified> Consumers shall consider a document element that violates this constraint to be an error.");

		// Rule M4.4
		if (el.attribute(new QName("lang", namespaceXML)) != null)
			throw new InvalidFormatException(
					"OPC Compliance error [M4.4]: Producers shall not create a document element that contains the xml:lang attribute. Consumers shall consider a document element that violates this constraint to be an error.");

		// Rule M4.5
		if (el.getNamespace().getURI().equals(
				PackageProperties.NAMESPACE_DCTERMS)) {
			// DCTerms namespace only use with 'created' and 'modified' elements
			String elName = el.getName();
			if (!(elName.equals(KEYWORD_CREATED) || elName
					.equals(KEYWORD_MODIFIED)))
				throw new InvalidFormatException("Namespace error : " + elName
						+ " shouldn't have the following naemspace -> "
						+ PackageProperties.NAMESPACE_DCTERMS);

			// Check for the 'xsi:type' attribute
			Attribute typeAtt = el.attribute(new QName("type", namespaceXSI));
			if (typeAtt == null)
				throw new InvalidFormatException("The element '" + elName
						+ "' must have the '" + namespaceXSI.getPrefix()
						+ ":type' attribute present !");

			// Check for the attribute value => 'dcterms:W3CDTF'
			if (!typeAtt.getValue().equals("dcterms:W3CDTF"))
				throw new InvalidFormatException("The element '" + elName
						+ "' must have the '" + namespaceXSI.getPrefix()
						+ ":type' attribute with the value 'dcterms:W3CDTF' !");
		}

		// Check its children
		Iterator itChildren = el.elementIterator();
		while (itChildren.hasNext())
			checkElementForOPCCompliance((Element) itChildren.next());
	}
}
