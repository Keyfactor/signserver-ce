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

import org.odftoolkit.odfdom.dom.element.table.TableTableCellElementBase;
import org.w3c.dom.Node;

/**
 *
 *
 */
class OdfTableCellBaseImpl {

    static public int getColumnIndex(OdfTableCellBase _aBase) {
        OdfTableRow tr = _aBase.getTableRow();
        int result = 0;
        for (Node n : new DomNodeList(tr.getChildNodes())) {
            if (n == _aBase) {
                return result;
            }
            if (n instanceof TableTableCellElementBase) {
                result += ((TableTableCellElementBase)n).getTableNumberColumnsRepeatedAttribute().intValue();
            }
        }
        return result;
    }

    static public OdfTableColumn getTableColumn(OdfTableCellBase _aBase) {
        return _aBase.getTable().getTableColumn(_aBase.getColumnIndex());
    }

    static public OdfTable getTable(OdfTableCellBase _aBase) {
        OdfTableRow row = _aBase.getTableRow();
        return row.getTable();
    }
}
