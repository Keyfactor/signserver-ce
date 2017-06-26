/*
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
 */

package org.odftoolkit.odfdom.dom.element;

import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.OdfName;
import org.odftoolkit.odfdom.OdfNamespace;
import org.odftoolkit.odfdom.dom.OdfNamespaceNames;
import org.odftoolkit.odfdom.dom.style.OdfStyleFamily;

/**
 *
 * @author Christian
 */
abstract public class OdfStyleablePresentationElement extends OdfStylableElement
{
	private static final long serialVersionUID = 3604813885619852184L;
	private static OdfName PresStyleAttrName = OdfName.get( OdfNamespace.get(OdfNamespaceNames.PRESENTATION), "style-name" );
    private static OdfName DrawStyleAttrName = OdfName.get( OdfNamespace.get(OdfNamespaceNames.DRAW), "style-name" );
    
    public OdfStyleablePresentationElement(OdfFileDom ownerDocument, OdfName name)
    {
        super( ownerDocument, name, OdfStyleFamily.Graphic, DrawStyleAttrName );
    }

    @Override
    public void setAttributeNS(String uri, String name, String value)
    {    
        if( (value != null) && (value.length() != 0) )
        {
            if( DrawStyleAttrName.equals( uri, name ) )
            {
                mStyleNameAttrib = DrawStyleAttrName;
                mFamily = OdfStyleFamily.Graphic;
            }
            else if( PresStyleAttrName.equals(uri,name ) )
            {
                mStyleNameAttrib = PresStyleAttrName;
                mFamily = OdfStyleFamily.Presentation;
            }
        }
        
        super.setAttributeNS(uri, name, value);
    }
}
