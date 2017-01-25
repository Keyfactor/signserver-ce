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

import org.odftoolkit.odfdom.OdfAttribute;
import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.doc.*;
import org.odftoolkit.odfdom.OdfName;
import org.w3c.dom.DOMException;

/**
 * Temporary class until every ODF class is mapped
 */
public class OdfAlienAttribute extends OdfAttribute {

    /**
	 * 
	 */
	private static final long serialVersionUID = 4210521398191729448L;

	/**
	 * 
	 */

	public OdfAlienAttribute(OdfFileDom ownerDocument,
            OdfName name) throws DOMException {
        super(ownerDocument, name.getUri(), name.getQName());
        ATTRIBUTE_NAME = name;
    }
    public final OdfName ATTRIBUTE_NAME;

    @Override
	public OdfName getOdfName() {
        return ATTRIBUTE_NAME;
    }

	@Override
	public String getDefault() {
		return null;
	}

	@Override
	public boolean hasDefault() {
		return false;
	}
}
