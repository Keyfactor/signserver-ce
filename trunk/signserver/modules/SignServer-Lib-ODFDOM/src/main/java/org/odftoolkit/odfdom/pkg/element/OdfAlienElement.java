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
package org.odftoolkit.odfdom.pkg.element;

import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.doc.*;
import org.odftoolkit.odfdom.OdfName;
import org.odftoolkit.odfdom.OdfElement;
import org.w3c.dom.DOMException;

/**
 * Temporary class until every ODF class is mapped
 */
public class OdfAlienElement extends OdfElement {

    /**
	 * 
	 */
	private static final long serialVersionUID = 6693153432396354134L;

	public OdfAlienElement(OdfFileDom ownerDocument,
            OdfName name) throws DOMException {
        super(ownerDocument, name.getUri(), name.getQName());
        ELEMENT_NAME = name;
    }
    public final OdfName ELEMENT_NAME;

    @Override
	public OdfName getOdfName() {
        return ELEMENT_NAME;
    }
}
