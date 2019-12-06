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
import org.odftoolkit.odfdom.dom.element.text.TextPElement;

/**
 * Convenient functionalty for the parent ODF OpenDocument element
 *
 */
public class OdfTextParagraph extends TextPElement {

    /** Creates a new instance of this class */
    public OdfTextParagraph(OdfFileDom ownerDoc) {
        super(ownerDoc);
    }

    /** Creates a new instance of this class with the given style name.
     * If the style name is null or the null string, no style is added.
     */
    public OdfTextParagraph(OdfFileDom ownerDoc, String styleName) {
        super(ownerDoc);
        if (styleName != null && (!(styleName.equals("")))) {
            this.setStyleName(styleName);
        }
    }

    /**
     * Creates an instance of this class with the given styleName and content.
     * If the style name is null or the null string, no style is added.
     * If the content is null or the null string, no content is added.
     * @param ownerDoc the owner document DOM
     * @param styleName the style:style-name value
     * @param content the paragraph content
     */
    public OdfTextParagraph(OdfFileDom ownerDoc,
        String styleName, String content) {
        super(ownerDoc);
        this.addStyledContent(styleName, content);
    }

    /**
     * Add the given content to the paragraph.
     * If the content is null or the null string, no content is added.
     * @param content the paragraph content
     * @return the paragraph object
     */
    public OdfTextParagraph addContent(String content) {
        if (content != null && !content.equals("")) {
            this.appendChild(this.getOwnerDocument().createTextNode(content));
        }
        return this;
    }

    /**
     * Add the given content to the paragraph.
     * If the content is null or the null string, no content is added.
     * Embedded \n are converted to <code>&lt;text:line-break&gt;</code>
     * elements, and multiple blanks to <code>&lt;text:s</code>
     * @param content the paragraph content
     * @return the paragraph object
     */
    public OdfTextParagraph addContentWhitespace(String content) {
        if (content != null && !content.equals("")) {
            new OdfWhitespaceProcessor().append(this, content);
        }
        return this;
    }

    /**
     * Set a paragraph to have the given styleName and add the given content.
     * If the style name is null or the null string, no style is added.
     * If the content is null or the null string, no content is added.
     * @param styleName the style:style-name value
     * @param content the paragraph content
     * @return the paragraph object
     */
    public OdfTextParagraph addStyledContent(String styleName, String content) {
        if (styleName != null && (!(styleName.equals("")))) {
            setStyleName(styleName);
        }
        return addContent(content);
    }

    /**
     * Set a paragraph to have the given styleName and add the given content.
     * If the style name is null or the null string, no style is added.
     * If the content is null or the null string, no content is added.
     * Embedded \n are converted to <code>&lt;text:line-break&gt;</code>
     * elements, and multiple blanks to <code>&lt;text:s</code>
     * @param styleName the style:style-name value
     * @param content the paragraph content
     * @return the paragraph object
     */
    public OdfTextParagraph addStyledContentWhitespace(String styleName,
        String content) {
        if (styleName != null && (!(styleName.equals("")))) {
            setStyleName(styleName);
        }
        return addContentWhitespace(content);
    }

    /**
     * Add a span with the given styleName and content to this paragraph.
     * If the style name is null or the null string, no span is added.
     * If the content is null or the null string, no span is added.
     * Embedded \n are converted to <code>&lt;text:line-break&gt;</code>
     * elements, and multiple blanks to <code>&lt;text:s</code>
     * @param styleName
     * @param content
     * @return the heading object
     */
    public OdfTextParagraph addStyledSpan(String styleName, String content) {
        if (styleName != null && !styleName.equals("") &&
            content != null && !content.equals("")) {
            this.appendChild(new OdfTextSpan(
                (OdfFileDom) this.getOwnerDocument(),
                styleName, content));
        }
        return this;
    }

    /**
     * Add a span with the given styleName and content to this paragraph.
     * If the style name is null or the null string, no span is added.
     * If the content is null or the null string, no span is added.
     * @param styleName
     * @param content
     * @return the heading object
     */
    public OdfTextParagraph addStyledSpanWhitespace(String styleName,
        String content) {
        OdfTextSpan span;
        if (styleName != null && !styleName.equals("") &&
            content != null && !content.equals("")) {
            span = new OdfTextSpan((OdfFileDom) this.getOwnerDocument());
            span.addStyledContentWhitespace(styleName, content);
            appendChild(span);
        }
        return this;
    }
}
