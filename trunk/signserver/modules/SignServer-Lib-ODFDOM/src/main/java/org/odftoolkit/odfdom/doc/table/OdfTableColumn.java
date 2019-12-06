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

package org.odftoolkit.odfdom.doc.table;

import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.doc.style.OdfStyle;
import org.odftoolkit.odfdom.dom.element.table.TableTableColumnElement;

/**
 * Convenient functionalty for the parent ODF OpenDocument element
 *
 */
public class OdfTableColumn extends TableTableColumnElement
{
	private OdfStyle m_defaultCellStyle;
    
    /** Creates a new instance of this class */
    public OdfTableColumn(OdfFileDom ownerDoc) {
        super(ownerDoc);
    }    
    
    public OdfTable getTable() {
        return getParentAs(OdfTable.class);
    }

    public void setDefaultCellStyle(OdfStyle s) {
        if (m_defaultCellStyle != null) {
            m_defaultCellStyle.removeStyleUser(this);
        }
        m_defaultCellStyle = s;
        if (m_defaultCellStyle != null) {
            m_defaultCellStyle.addStyleUser(this);
            this.setTableDefaultCellStyleNameAttribute(
                    m_defaultCellStyle.getStyleNameAttribute());
        }
    }

    public OdfStyle getDefaultCellStyle() {
        return m_defaultCellStyle;
    }

}
