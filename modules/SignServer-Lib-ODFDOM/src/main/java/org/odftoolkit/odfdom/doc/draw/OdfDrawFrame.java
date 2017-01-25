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

package org.odftoolkit.odfdom.doc.draw;

import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.dom.attribute.text.TextAnchorTypeAttribute;
import org.odftoolkit.odfdom.dom.element.draw.DrawFrameElement;

/**
 * Convenient functionalty for the parent ODF OpenDocument element
 *
 */
public class OdfDrawFrame extends DrawFrameElement
{

    // 2DO: OdfMeassure / OdfUnit

	private static final long serialVersionUID = -2260696671403198845L;

	// 2DO - What are mandatory ODF attributes, what are the OOo defaults?
    // 2DO - mandatory attributes part of the constructor default values should always be set in constructor
    /** Creates a new instance of this class */
    public OdfDrawFrame(OdfFileDom ownerDoc) {
        super(ownerDoc);
        this.setTextAnchorTypeAttribute(TextAnchorTypeAttribute.Value.PARAGRAPH.toString());
    }

}
