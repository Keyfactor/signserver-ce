
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

package org.odftoolkit.odfdom.doc.text;

import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.dom.element.text.TextOutlineStyleElement;
import org.w3c.dom.Node;

/**
 * Convenient functionalty for the parent ODF OpenDocument element
 *
 */
public class OdfTextOutlineStyle extends TextOutlineStyleElement
{
	private static final long serialVersionUID = -337172468409606629L;

	public OdfTextOutlineStyle( OdfFileDom ownerDoc )
    {
        super( ownerDoc );
    }

    /**
     * Retrieves the ODF TextOutlineLevelStyle with level count
     * 
     * @param level  The level count
     * @return The <code>OdfTextOutlineLevelStyle</code>
     */
	public OdfTextOutlineLevelStyle getLevel(int level )
    {
        Node levelElement = this.getFirstChild();

        while( levelElement != null )
        {
            if(levelElement instanceof OdfTextOutlineLevelStyle )
            {
                OdfTextOutlineLevelStyle levelStyle = (OdfTextOutlineLevelStyle)levelElement;
                if( levelStyle.getTextLevelAttribute().intValue() == level ) {
                    return levelStyle;
                }
            }
            levelElement = levelElement.getNextSibling();
        }
        return null;
    }
    
	/**
	 * Retrieves or create the ODF TextOutlineLevelStyle with level count
	 * 
	 * @param level The level count
	 * @return The <code>OdfTextOutlineLevelStyle</code>
	 */
    public OdfTextOutlineLevelStyle getOrCreateLevel(int level)
    {
        OdfTextOutlineLevelStyle style = getLevel(level);
        if( style == null )
        {
            style = ((OdfFileDom)this.ownerDocument).newOdfElement(OdfTextOutlineLevelStyle.class);
            style.setTextLevelAttribute(level);
            this.appendChild(style);
        }
        return style;
    }

}
