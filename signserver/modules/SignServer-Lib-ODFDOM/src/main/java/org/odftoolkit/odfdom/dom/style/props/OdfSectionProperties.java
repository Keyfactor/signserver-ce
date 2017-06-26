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


public interface OdfSectionProperties {
    public final static OdfStyleProperty BackgroundColor = 
        OdfStyleProperty.get(OdfStylePropertiesSet.SectionProperties, OdfName.get(OdfNamespace.get(OdfNamespaceNames.FO), "background-color"));
    public final static OdfStyleProperty MarginLeft = 
        OdfStyleProperty.get(OdfStylePropertiesSet.SectionProperties, OdfName.get(OdfNamespace.get(OdfNamespaceNames.FO), "margin-left"));
    public final static OdfStyleProperty MarginRight = 
        OdfStyleProperty.get(OdfStylePropertiesSet.SectionProperties, OdfName.get(OdfNamespace.get(OdfNamespaceNames.FO), "margin-right"));
    public final static OdfStyleProperty Protect = 
        OdfStyleProperty.get(OdfStylePropertiesSet.SectionProperties, OdfName.get(OdfNamespace.get(OdfNamespaceNames.STYLE), "protect"));
    public final static OdfStyleProperty WritingMode = 
        OdfStyleProperty.get(OdfStylePropertiesSet.SectionProperties, OdfName.get(OdfNamespace.get(OdfNamespaceNames.STYLE), "writing-mode"));
    public final static OdfStyleProperty DontBalanceTextColumns = 
        OdfStyleProperty.get(OdfStylePropertiesSet.SectionProperties, OdfName.get(OdfNamespace.get(OdfNamespaceNames.TEXT), "dont-balance-text-columns"));
    public final static OdfStyleProperty Editable = 
    	OdfStyleProperty.get(OdfStylePropertiesSet.SectionProperties, OdfName.get(OdfNamespace.get(OdfNamespaceNames.STYLE), "editable"));

}
