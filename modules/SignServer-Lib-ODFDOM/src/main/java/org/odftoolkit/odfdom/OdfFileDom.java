/************************************************************************
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
 * 
 * Copyright 2008 Sun Microsystems, Inc. All rights reserved.
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
package org.odftoolkit.odfdom;

import org.odftoolkit.odfdom.doc.*;
import java.lang.reflect.Field;
import org.apache.xerces.dom.DocumentImpl;
import org.odftoolkit.odfdom.doc.OdfElementFactory;
import org.odftoolkit.odfdom.doc.office.OdfOfficeAutomaticStyles;
import org.odftoolkit.odfdom.doc.office.OdfOfficeBody;
import org.odftoolkit.odfdom.doc.office.OdfOfficeMasterStyles;
import org.odftoolkit.odfdom.doc.office.OdfOfficeStyles;
import org.w3c.dom.DOMException;
import org.w3c.dom.Node;

/**
 * The DOM repesentation of an XML file within the ODF document.
 */
public class OdfFileDom extends DocumentImpl {

	private static final long serialVersionUID = 766167617530147000L;
	private String mPackagePath;
	private OdfDocument mOdfDocument;

	/**
	 * Creates the DOM representation of an XML file of an Odf document.
	 *
	 * @param odfDocument   the document the XML files belongs to
	 * @param packagePath   the internal package path to the XML file
	 */
	public OdfFileDom(OdfDocument odfDocument, String packagePath) {
		mOdfDocument = odfDocument;
		mPackagePath = packagePath;
	}

	/**
	 * Retrieves the Odf Document
	 * 
	 * @return The <code>OdfElement</code>
	 */
	public OdfDocument getOdfDocument() {
		return mOdfDocument;
	}

	/**
	 * Retrieves the <code>String</code> of Package Path
	 * 
	 * @return The path of package
	 */
	public String getPackagePath() {
		return mPackagePath;
	}

	/**
	 * Retrieves the ODF root element.
	 *
	 * @return The <code>OdfElement</code> being the root of the document.
	 */
	public OdfElement getRootElement() {
		return (OdfElement) getDocumentElement();
	}

	/**
	 * Create ODF element with namespace uri and qname
	 *
	 * @param nsuri The namespace uri
	 * @param qname The element qname
	 *
	 */
	public OdfElement createElementNS(String nsuri, String qname) throws DOMException {
		return createElementNS(OdfName.get(nsuri, qname));
	}

	/**
	 * Create ODF element with ODF name
	 * @param name The <code>OdfName</code>
	 * @return The <code>OdfElement</code>
	 * @throws DOMException
	 */
	public OdfElement createElementNS(OdfName name) throws DOMException {
		return OdfElementFactory.newOdfElement(this, name);
	}

	/**
	 * Create the ODF attribute with namespace uri and qname
	 * 
	 * @param nsuri  The namespace uri
	 * @param qname  the attribute qname
	 * @return The <code>OdfAttribute</code>
	 * @throws  DOMException
	 */
	public OdfAttribute createAttributeNS(String nsuri, String qname) throws DOMException {
		return createAttributeNS(OdfName.get(nsuri, qname));
	}

	/**
	 * Create the ODF attribute with ODF name
	 * @param name The <code>OdfName</code>
	 * @return  The <code>OdfAttribute</code>
	 * @throws DOMException
	 */
	public OdfAttribute createAttributeNS(OdfName name) throws DOMException {
		return OdfElementFactory.newOdfAttribute(this, name);
	}

	@SuppressWarnings("unchecked")
	public <T extends OdfElement> T newOdfElement(Class<T> clazz) {
		try {
			Field fname = clazz.getField("ELEMENT_NAME");
			OdfName name = (OdfName) fname.get(null);
			return (T) createElementNS(name);
		} catch (Exception ex) {
			if (ex instanceof RuntimeException) {
				throw (RuntimeException) ex;
			}
			return null;
		}
	}

	/**
	 * @return the style:office-styles element of this dom. May return null
	 *         if there is not yet such element in this dom.
	 *
	 * @see getOrCreateAutomaticStyles()
	 *
	 */
	public OdfOfficeStyles getOfficeStyles() {
		return OdfElement.findFirstChildNode(OdfOfficeStyles.class, getFirstChild());
	}

	/**
	 * Retrieve the ODF AutomaticStyles
	 * 
	 * @return the {@odf.element style:automatic-styles} element of this dom. May return null
	 *         if there is not yet such element in this dom.
	 *
	 * @see #getOrCreateAutomaticStyles()
	 *
	 */
	public OdfOfficeAutomaticStyles getAutomaticStyles() {
		return OdfElement.findFirstChildNode(OdfOfficeAutomaticStyles.class, getFirstChild());
	}

	/**
	 * @return the {@odf.element style:automatic-styles} element of this dom. If it does not
	 *         yet exists, a new one is inserted into the dom and returned.
	 *
	 */
	public OdfOfficeAutomaticStyles getOrCreateAutomaticStyles() {

		OdfOfficeAutomaticStyles automaticStyles = getAutomaticStyles();
		if (automaticStyles == null) {
			automaticStyles = newOdfElement(OdfOfficeAutomaticStyles.class);

			Node parent = getFirstChild();

			// try to insert before body or before master-styles element
			OdfElement sibling = OdfElement.findFirstChildNode(OdfOfficeBody.class, parent);
			if (sibling == null) {
				sibling = OdfElement.findFirstChildNode(OdfOfficeMasterStyles.class, parent);
			}

			if (sibling == null) {
				parent.appendChild(automaticStyles);
			} else {
				parent.insertBefore(automaticStyles, sibling);
			}
		}
		return automaticStyles;
	}

	@Override
	public String toString() {
		return ((OdfElement) this.getDocumentElement()).toString();
	}
}
