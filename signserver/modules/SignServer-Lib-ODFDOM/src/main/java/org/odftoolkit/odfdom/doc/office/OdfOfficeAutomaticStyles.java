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
package org.odftoolkit.odfdom.doc.office;

import java.util.ArrayList;
import java.util.HashMap;

import java.util.Iterator;
import java.util.SortedSet;
import java.util.TreeSet;
import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.doc.number.OdfNumberBooleanStyle;
import org.odftoolkit.odfdom.doc.number.OdfNumberCurrencyStyle;
import org.odftoolkit.odfdom.doc.number.OdfNumberDateStyle;
import org.odftoolkit.odfdom.doc.number.OdfNumberStyle;
import org.odftoolkit.odfdom.doc.number.OdfNumberPercentageStyle;
import org.odftoolkit.odfdom.doc.number.OdfNumberTextStyle;
import org.odftoolkit.odfdom.doc.number.OdfNumberTimeStyle;
import org.odftoolkit.odfdom.doc.style.OdfStylePageLayout;
import org.odftoolkit.odfdom.doc.style.OdfStyle;
import org.odftoolkit.odfdom.doc.text.OdfTextListStyle;
import org.odftoolkit.odfdom.OdfElement;
import org.odftoolkit.odfdom.dom.element.OdfStylableElement;
import org.odftoolkit.odfdom.dom.element.office.OfficeAutomaticStylesElement;
import org.odftoolkit.odfdom.dom.style.OdfStyleFamily;
import org.w3c.dom.Node;

/**
 * Convenient functionalty for the parent ODF OpenDocument element
 *
 */
public class OdfOfficeAutomaticStyles extends OfficeAutomaticStylesElement {

    private static final long serialVersionUID = -2925910664631016175L;
    // styles that are only in OdfAutomaticStyles
    private HashMap<String, OdfStylePageLayout> mPageLayouts;
    // styles that are common for OdfStyles and OdfAutomaticStyles
    private OdfStylesBase mStylesBaseImpl;

    public OdfOfficeAutomaticStyles(OdfFileDom ownerDoc) {
	super(ownerDoc);
	mStylesBaseImpl = new OdfStylesBase();
    }

    /**
     * Create an <code>OdfStyle</code> element with style family
     * 
     * @param styleFamily  The <code>OdfStyleFamily</code> element
     * @return an <code>OdfStyle</code> element 
     */
    public OdfStyle newStyle(OdfStyleFamily styleFamily) {
	OdfFileDom dom = (OdfFileDom) this.ownerDocument;
	OdfStyle newStyle = dom.newOdfElement(OdfStyle.class);
	newStyle.setStyleFamilyAttribute(styleFamily.getName());

	newStyle.setStyleNameAttribute(newUniqueStyleName(styleFamily));

	this.appendChild(newStyle);

	return newStyle;
    }

    /**
     * Create an <code>OdfTextListStyle</code> element
     * 
     * @return an <code>OdfTextListStyle</code> element 
     */
    public OdfTextListStyle newListStyle() {
	OdfFileDom dom = (OdfFileDom) this.ownerDocument;
	OdfTextListStyle newStyle = dom.newOdfElement(OdfTextListStyle.class);

	newStyle.setStyleNameAttribute(newUniqueStyleName(OdfStyleFamily.List));

	this.appendChild(newStyle);

	return newStyle;
    }

    /** Returns the <code>OdfStylePageLayout</code> element with the given name.
     *
     * @param name is the name of the page layout
     * @return the page layout or null if there is no such page layout
     */
    public OdfStylePageLayout getPageLayout(String name) {
	if (mPageLayouts != null) {
	    return mPageLayouts.get(name);
	} else {
	    return null;
	}
    }

    /** 
     * Returns the <code>OdfStyleStyle</code> element with the given name and family.
     *
     * @param name is the name of the style
     * @param familyType is the family of the style
     * @return the style or null if there is no such style
     */
    public OdfStyle getStyle(String name, OdfStyleFamily familyType) {
	return mStylesBaseImpl.getStyle(name, familyType);
    }

    /** 
     * Returns an iterator for all <code>OdfStyleStyle</code> elements for the given family.
     *
     * @param familyType
     * @return an iterator for all <code>OdfStyleStyle</code> elements for the given family
     */
    public Iterable<OdfStyle> getStylesForFamily(OdfStyleFamily familyType) {
	return mStylesBaseImpl.getStylesForFamily(familyType);
    }

    /** 
     * Returns an iterator for all <code>OdfStyleStyle</code> elements.
     *
     * @return an iterator for all <code>OdfStyleStyle</code> elements
     */
    public Iterable<OdfStyle> getAllStyles() {
	return mStylesBaseImpl.getAllOdfStyles();
    }

    /** 
     * Returns the <code>OdfTextListStyle</code> element with the given name.
     *
     * @param name is the name of the list style
     * @return the list style or null if there is no such list style
     */
    public OdfTextListStyle getListStyle(String name) {
	return mStylesBaseImpl.getListStyle(name);
    }

    /** 
     * Returns an iterator for all <code>OdfTextListStyle</code> elements.
     *
     * @return an iterator for all <code>OdfTextListStyle</code> elements
     */
    public Iterable<OdfTextListStyle> getListStyles() {
	return mStylesBaseImpl.getListStyles();
    }

    /** 
     * Returns the <code>OdfNumberNumberStyle</code> element with the given name.
     *
     * @param name is the name of the number style
     * @return the number style or null if there is no such number style
     */
    public OdfNumberStyle getNumberStyle(String name) {
	return mStylesBaseImpl.getNumberStyle(name);
    }

    /** 
     * Returns an iterator for all <code>OdfNumberNumberStyle</code> elements.
     *
     * @return an iterator for all <code>OdfNumberNumberStyle</code> elements
     */
    public Iterable<OdfNumberStyle> getNumberStyles() {
	return mStylesBaseImpl.getNumberStyles();
    }

    /** 
     * Returns the <code>OdfNumberDateStyle</code> element with the given name.
     *
     * @param name is the name of the date style
     * @return the date style or null if there is no such date style
     */
    public OdfNumberDateStyle getDateStyle(String name) {
	return mStylesBaseImpl.getDateStyle(name);
    }

    /** 
     * Returns an iterator for all <code>OdfNumberDateStyle</code> elements.
     *
     * @return an iterator for all <code>OdfNumberDateStyle</code> elements
     */
    public Iterable<OdfNumberDateStyle> getDateStyles() {
	return mStylesBaseImpl.getDateStyles();
    }

    /** 
     * Returns the <code>OdfNumberPercentageStyle</code> element with the given name.
     *
     * @param name is the name of the percentage style
     * @return the percentage style null if there is no such percentage style
     */
    public OdfNumberPercentageStyle getPercentageStyle(String name) {
	return mStylesBaseImpl.getPercentageStyle(name);
    }

    /** 
     * Returns an iterator for all <code>OdfNumberPercentageStyle</code> elements.
     *
     * @return an iterator for all <code>OdfNumberPercentageStyle</code> elements
     */
    public Iterable<OdfNumberPercentageStyle> getPercentageStyles() {
	return mStylesBaseImpl.getPercentageStyles();
    }

    /** 
     * Returns the <code>OdfNumberCurrencyStyle</code> element with the given name.
     *
     * @param name is the name of the currency style
     * @return the currency style null if there is no such currency style
     */
    public OdfNumberCurrencyStyle getCurrencyStyle(String name) {
	return mStylesBaseImpl.getCurrencyStyle(name);
    }

    /** 
     * Returns an iterator for all <code>OdfNumberCurrencyStyle</code> elements.
     *
     * @return an iterator for all <code>OdfNumberCurrencyStyle</code> elements
     */
    public Iterable<OdfNumberCurrencyStyle> getCurrencyStyles() {
	return mStylesBaseImpl.getCurrencyStyles();
    }

    /** 
     * Returns the <code>OdfNumberTimeStyle</code> element with the given name.
     *
     * @param name is the name of the time style
     * @return the time style null if there is no such time style
     */
    public OdfNumberTimeStyle getTimeStyle(String name) {
	return mStylesBaseImpl.getTimeStyle(name);
    }

    /** 
     * Returns an iterator for all <code>OdfNumberTimeStyle</code> elements.
     *
     * @return an iterator for all <code>OdfNumberTimeStyle</code> elements
     */
    public Iterable<OdfNumberTimeStyle> getTimeStyles() {
	return mStylesBaseImpl.getTimeStyles();
    }

    /** 
     * Returns the <code>OdfNumberBooleanStyle</code> element with the given name.
     *
     * @param name is the name of the boolean style
     * @return the boolean style null if there is no such boolean style
     */
    public OdfNumberBooleanStyle getBooleanStyle(String name) {
	return mStylesBaseImpl.getBooleanStyle(name);
    }

    /** 
     * Returns an iterator for all <code>OdfNumberBooleanStyle</code> elements.
     *
     * @return an iterator for all <code>OdfNumberBooleanStyle</code> elements
     */
    public Iterable<OdfNumberBooleanStyle> getBooleanStyles() {
	return mStylesBaseImpl.getBooleanStyles();
    }

    /** 
     * Returns the <code>OdfNumberTextStyle</code> element with the given name.
     *
     * @param name is the name of the text style
     * @return the text style null if there is no such text style
     */
    public OdfNumberTextStyle getTextStyle(String name) {
	return mStylesBaseImpl.getTextStyle(name);
    }

    /** 
     * Returns an iterator for all <code>OdfNumberTextStyle</code> elements.
     *
     * @return an iterator for all <code>OdfNumberTextStyle</code> elements
     */
    public Iterable<OdfNumberTextStyle> getTextStyles() {
	return mStylesBaseImpl.getTextStyles();
    }

    @Override
    protected void onOdfNodeInserted(OdfElement node, Node refNode) {
	if (node instanceof OdfStylePageLayout) {
	    OdfStylePageLayout pageLayout = (OdfStylePageLayout) node;
	    if (mPageLayouts == null) {
		mPageLayouts = new HashMap<String, OdfStylePageLayout>();
	    }

	    mPageLayouts.put(pageLayout.getStyleNameAttribute(), pageLayout);
	} else {
	    mStylesBaseImpl.onOdfNodeInserted(node, refNode);
	}
    }

    @Override
    protected void onOdfNodeRemoved(OdfElement node) {
	if (node instanceof OdfStylePageLayout) {
	    if (mPageLayouts != null) {
		OdfStylePageLayout pageLayout = (OdfStylePageLayout) node;
		mPageLayouts.remove(pageLayout.getStyleNameAttribute());
	    }
	} else {
	    mStylesBaseImpl.onOdfNodeRemoved(node);
	}
    }

    /** 
     * This methods removes all automatic styles that are currently not used by
     * any styleable element. Additionally all duplicate automatic styles will
     * be removed.
     */
    public void optimize() {
	Iterator<OdfStyle> iter = mStylesBaseImpl.getAllOdfStyles().iterator();
	SortedSet<OdfStyle> stylesSet = new TreeSet<OdfStyle>();
	while (iter.hasNext()) {
	    OdfStyle cur = iter.next();

	    // skip styles which are not in use:
	    if (cur.getStyleUserCount() < 1) {
		continue;
	    }

	    SortedSet<OdfStyle> tail = stylesSet.tailSet(cur);
	    OdfStyle found = tail.size() > 0 ? tail.first() : null;
	    if (found != null && found.equals(cur)) {
		// cur already in set. Replace all usages of cur by found:
		Iterator<OdfStylableElement> styleUsersIter = cur.getStyleUsers().iterator();
		ArrayList<OdfStylableElement> styleUsers = new ArrayList<OdfStylableElement>();
		while (styleUsersIter.hasNext()) {
		    styleUsers.add(styleUsersIter.next());
		}
		styleUsersIter = styleUsers.iterator();
		while (styleUsersIter.hasNext()) {
		    OdfStylableElement elem = styleUsersIter.next();
		    OdfStyle autoStyle = elem.getAutomaticStyle();
		    if (autoStyle != null) {
			elem.setStyleName(found.getStyleNameAttribute());
		    }
		}
	    } else {
		stylesSet.add(cur);
	    }
	}

	OdfStyle style = OdfElement.findFirstChildNode(OdfStyle.class, this);
	while (style != null) {
	    OdfStyle nextStyle = OdfElement.findNextChildNode(OdfStyle.class, style);
	    if (style.getStyleUserCount() < 1) {
		this.removeChild(style);
	    }

	    style = nextStyle;
	}
    }

    /**
     * This method makes the style unique
     * 
     * @param referenceStyle The reference <code>OdfStyle</code> element
     * @return an <code>OdfStyle</code> element
     */
    public OdfStyle makeStyleUnique(OdfStyle referenceStyle) {
	OdfStyle newStyle = null;

	if (referenceStyle.getOwnerDocument() != this.getOwnerDocument()) {
	    // import style from a different dom
	    newStyle = (OdfStyle) this.getOwnerDocument().importNode(referenceStyle, true);
	} else {
	    // just clone
	    newStyle = (OdfStyle) referenceStyle.cloneNode(true);
	}

	newStyle.setStyleNameAttribute(newUniqueStyleName(newStyle.getFamily()));
	appendChild(newStyle);

	return newStyle;
    }

    private String newUniqueStyleName(OdfStyleFamily styleFamily) {
	String unique_name;

	if (styleFamily.equals(OdfStyleFamily.List)) {
	    do {
		unique_name = String.format("l%06x", (int) (Math.random() * 0xffffff));
	    } while (getListStyle(unique_name) != null);
	} else {
	    do {
		unique_name = String.format("a%06x", (int) (Math.random() * 0xffffff));
	    } while (getStyle(unique_name, styleFamily) != null);
	}
	return unique_name;
    }
}
