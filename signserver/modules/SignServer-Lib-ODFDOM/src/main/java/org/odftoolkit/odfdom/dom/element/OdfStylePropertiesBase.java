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

package org.odftoolkit.odfdom.dom.element;

import org.odftoolkit.odfdom.OdfElement;
import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.OdfName;
import org.w3c.dom.DOMException;

/**
 *
 */
abstract public class OdfStylePropertiesBase extends OdfElement
{
    /**
	 * 
	 */
	private static final long serialVersionUID = -6575728390842696683L;

	/** Creates a new instance of OdfStyleProperties */
    public OdfStylePropertiesBase(OdfFileDom ownerDocument,
            String namespaceURI,
            String qualifiedName) throws DOMException {
        super(ownerDocument, namespaceURI, qualifiedName);
    }

    /** Creates a new instance of OdfStyleProperties */
    public OdfStylePropertiesBase(OdfFileDom ownerDocument, 
            OdfName aName) throws DOMException {
        super(ownerDocument,aName);
    }

    @Override
    public int hashCode()
    {
        return getOdfName().hashCode() + 7;
    }

    
}
