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

import org.apache.xerces.dom.AttrNSImpl;
import org.w3c.dom.DOMException;

/**
 * Base class for all attributes of the OpenDocument format
 */
abstract public class OdfAttribute extends AttrNSImpl {

   /**
    * Returns the attribute name.
    *
    * @return the <code>OdfName</code> for the attribute.
    */
   abstract public OdfName getOdfName();

   /** Creates a new instance of OdfAttribute
    * @param ownerDocument - the document the attribute belongs to
    * @param namespaceURI - The namespace URI of the attribute to create. When it is null or an empty string, this method behaves like createAttribute.
    * @param qualifiedName - The qualified name of the attribute to instantiate.
    * @throws DOMException - if the attribute could not be created
    */
   public OdfAttribute(OdfFileDom ownerDocument,
           String namespaceURI,
           String qualifiedName) throws DOMException {
       super(ownerDocument, namespaceURI, qualifiedName);
   }

   /** Creates a new instance of OdfAttribute
    * @param ownerDocument - the document the attribute belongs to
    * @param name - the <code>OdfName</code> representation of the attribute name.
    * @throws DOMException - if the attribute could not be created
    */
   public OdfAttribute(OdfFileDom ownerDocument,
           OdfName name) throws DOMException {
       super(ownerDocument, name.getUri(), name.getQName());
   }
   
   /**
	 * Returns the default value of {@odf.attribute table:number-columns-repeated}.
	 * 
	 * @return the default value as String
	 */
	abstract public String getDefault();

	/**
	 * Default value indicator
	 * 
	 * @return true if a default exists
	 */
	abstract public boolean hasDefault();
}
