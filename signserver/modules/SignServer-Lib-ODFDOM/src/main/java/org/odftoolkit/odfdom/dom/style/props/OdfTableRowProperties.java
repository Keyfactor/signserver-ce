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
// !!! GENERATED SOURCE CODE !!!
package org.odftoolkit.odfdom.dom.style.props;

import org.odftoolkit.odfdom.OdfNamespace;
import org.odftoolkit.odfdom.OdfName;
import org.odftoolkit.odfdom.dom.OdfNamespaceNames;


public interface OdfTableRowProperties {
    public final static OdfStyleProperty BackgroundColor = 
        OdfStyleProperty.get(OdfStylePropertiesSet.TableRowProperties, OdfName.get(OdfNamespace.get(OdfNamespaceNames.FO), "background-color"));
    public final static OdfStyleProperty BreakAfter = 
        OdfStyleProperty.get(OdfStylePropertiesSet.TableRowProperties, OdfName.get(OdfNamespace.get(OdfNamespaceNames.FO), "break-after"));
    public final static OdfStyleProperty BreakBefore = 
        OdfStyleProperty.get(OdfStylePropertiesSet.TableRowProperties, OdfName.get(OdfNamespace.get(OdfNamespaceNames.FO), "break-before"));
    public final static OdfStyleProperty KeepTogether = 
        OdfStyleProperty.get(OdfStylePropertiesSet.TableRowProperties, OdfName.get(OdfNamespace.get(OdfNamespaceNames.FO), "keep-together"));
    public final static OdfStyleProperty MinRowHeight = 
        OdfStyleProperty.get(OdfStylePropertiesSet.TableRowProperties, OdfName.get(OdfNamespace.get(OdfNamespaceNames.STYLE), "min-row-height"));
    public final static OdfStyleProperty RowHeight = 
        OdfStyleProperty.get(OdfStylePropertiesSet.TableRowProperties, OdfName.get(OdfNamespace.get(OdfNamespaceNames.STYLE), "row-height"));
    public final static OdfStyleProperty UseOptimalRowHeight = 
        OdfStyleProperty.get(OdfStylePropertiesSet.TableRowProperties, OdfName.get(OdfNamespace.get(OdfNamespaceNames.STYLE), "use-optimal-row-height"));
}
