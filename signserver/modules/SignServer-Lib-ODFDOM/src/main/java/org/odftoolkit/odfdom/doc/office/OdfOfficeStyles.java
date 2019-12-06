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
import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.doc.draw.OdfDrawFillImage;
import org.odftoolkit.odfdom.doc.draw.OdfDrawGradient;
import org.odftoolkit.odfdom.doc.draw.OdfDrawHatch;
import org.odftoolkit.odfdom.doc.draw.OdfDrawMarker;
import org.odftoolkit.odfdom.doc.number.OdfNumberBooleanStyle;
import org.odftoolkit.odfdom.doc.number.OdfNumberCurrencyStyle;
import org.odftoolkit.odfdom.doc.number.OdfNumberDateStyle;
import org.odftoolkit.odfdom.doc.number.OdfNumberStyle;
import org.odftoolkit.odfdom.doc.number.OdfNumberPercentageStyle;
import org.odftoolkit.odfdom.doc.number.OdfNumberTextStyle;
import org.odftoolkit.odfdom.doc.number.OdfNumberTimeStyle;
import org.odftoolkit.odfdom.doc.style.OdfDefaultStyle;
import org.odftoolkit.odfdom.doc.style.OdfStyle;
import org.odftoolkit.odfdom.doc.text.OdfTextListStyle;
import org.odftoolkit.odfdom.doc.text.OdfTextOutlineStyle;
import org.odftoolkit.odfdom.OdfElement;
import org.odftoolkit.odfdom.dom.element.office.OfficeStylesElement;
import org.odftoolkit.odfdom.dom.style.OdfStyleFamily;
import org.w3c.dom.Node;

/**
 * Convenient functionalty for the parent ODF OpenDocument element
 *
 */
public class OdfOfficeStyles extends OfficeStylesElement {


    private static final long serialVersionUID = 700763983193326060L;

    // styles that are only in OdfOfficeStyles
    private HashMap<OdfStyleFamily, OdfDefaultStyle> mDefaultStyles;
    private HashMap<String, OdfDrawMarker> mMarker;
    private HashMap<String, OdfDrawGradient> mGradients;
    private HashMap<String, OdfDrawHatch> mHatches;
    private HashMap<String, OdfDrawFillImage> mFillImages;
    private OdfTextOutlineStyle mOutlineStyle;
    // styles that are common for OdfOfficeStyles and OdfOfficeAutomaticStyles
    private OdfStylesBase mStylesBaseImpl;

    public OdfOfficeStyles(OdfFileDom ownerDoc) {
        super(ownerDoc);
        mStylesBaseImpl = new OdfStylesBase();
    }
    
    /**
     * Create an ODF style with style name and family
     * 
     * @param name  The style name
     * @param family The style family
     * @return  The <code>OdfStyle</code> element
     */
    public OdfStyle newStyle(String name, OdfStyleFamily family) {
        OdfStyle newStyle = ((OdfFileDom) this.ownerDocument).newOdfElement(OdfStyle.class);
        newStyle.setStyleNameAttribute(name);
        newStyle.setStyleFamilyAttribute(family.getName());
        this.appendChild(newStyle);
        return newStyle;
    }

    /**
     * Retrieve or create ODF default style
     * 
     * @param family The style family
     * @return The code>OdfDefaultStyle</code> element
     */
    public OdfDefaultStyle getOrCreateDefaultStyle(OdfStyleFamily family) {
        OdfDefaultStyle style = getDefaultStyle(family);
        if (style == null) {
            style = ((OdfFileDom) this.ownerDocument).newOdfElement(OdfDefaultStyle.class);
            style.setStyleFamilyAttribute(family.getName());
            this.appendChild(style);
        }
        return style;
    }
    
    /**
     * Create ODF TextListStyle 
     * 
     * @param name  The style name
     * @return The code>OdfTextListStyle</code> element
     */
    public OdfTextListStyle newListStyle(String name) {
        OdfTextListStyle newStyle = ((OdfFileDom) this.ownerDocument).newOdfElement(OdfTextListStyle.class);
        newStyle.setStyleNameAttribute(name);
        this.appendChild(newStyle);
        return newStyle;
    }

    /**
     * Retrieve or create ODF OutlineStyle
     * 
     * @return The code>OdfTextOutlineStyle</code> element
     */
    public OdfTextOutlineStyle getOrCreateOutlineStyle() {
        if (mOutlineStyle == null) {
            this.appendChild(((OdfFileDom) this.ownerDocument).newOdfElement(OdfTextOutlineStyle.class));
        }

        return mOutlineStyle;
    }

    /** 
     * Returns the <code>OdfTextOutlineStyle</code> element.
     *
     * @return a pointer to the outline stye or null if there is no such element
     */
    public OdfTextOutlineStyle getOutlineStyle() {
        return mOutlineStyle;
    }

    /** 
     * Returns the <code>OdfStyleDefaultStyle</code>  element.
     *
     * @param familyType is the family for the default style
     * @return the default style with the given family or null if there is no such default style
     */
    public OdfDefaultStyle getDefaultStyle(OdfStyleFamily familyType) {
        if (mDefaultStyles != null) {
            return mDefaultStyles.get(familyType);
        } else {
            return null;
        }
    }

    /** 
     * Returns an iterator for all <code>OdfStyleDefaultStyle</code> elements.
     *
     * @return iterator for all <code>OdfStyleDefaultStyle</code> elements
     */
    public Iterable<OdfDefaultStyle> getDefaultStyles() {
        if (mDefaultStyles != null) {
            return mDefaultStyles.values();
        } else {
            return new ArrayList<OdfDefaultStyle>();
        }
    }

    /** 
     * Returns the <code>OdfDrawMarker</code> element with the given name.
     *
     * @param name is the name of the marker
     * @return the marker or null if there is no such marker
     */
    public OdfDrawMarker getMarker(String name) {
        if (mMarker != null) {
            return mMarker.get(name);
        } else {
            return null;
        }
    }

    /** 
     * Returns an iterator for all <code>OdfDrawMarker</code> elements.
     *
     * @return an iterator for all <code>OdfDrawMarker</code> elements
     */
    public Iterable<OdfDrawMarker> getMarker() {
        if (mMarker != null) {
            return mMarker.values();
        } else {
            return new ArrayList<OdfDrawMarker>();
        }
    }

    /** 
     * Returns the <code>OdfDrawGradient</code> element with the given name.
     *
     * @param name is the name of the gradient
     * @return the gradient or null if there is no such gradient
     */
    public OdfDrawGradient getGradient(String name) {
        if (mGradients != null) {
            return mGradients.get(name);
        } else {
            return null;
        }
    }

    /** 
     * Returns an iterator for all <code>OdfDrawGradient</code> elements.
     *
     * @return an iterator for all <code>OdfDrawGradient</code> elements
     */
    public Iterable<OdfDrawGradient> getGradients() {
        if (mGradients != null) {
            return mGradients.values();
        } else {
            return new ArrayList<OdfDrawGradient>();
        }
    }

    /** 
     * Returns the <code>OdfDrawHatch</code> element with the given name.
     *
     * @param name is the name of the hatch
     * @return the hatch or null if there is no such hatch
     */
    public OdfDrawHatch getHatch(String name) {
        if (mHatches != null) {
            return mHatches.get(name);
        } else {
            return null;
        }
    }

    /** 
     * Returns an iterator for all <code>OdfDrawHatch</code> elements.
     *
     * @return an iterator for all <code>OdfDrawHatch</code> elements
     */
    public Iterable<OdfDrawHatch> getHatches() {
        if (mHatches != null) {
            return mHatches.values();
        } else {
            return new ArrayList<OdfDrawHatch>();
        }
    }

    /** 
     * Returns the <code>OdfDrawFillImage</code> element with the given name.
     *
     * @param name is the name of the fill image
     * @return the fill image or null if there is no such fill image
     */
    public OdfDrawFillImage getFillImage(String name) {
        if (mFillImages != null) {
            return mFillImages.get(name);
        } else {
            return null;
        }
    }

    /** 
     * Returns an iterator for all <code>OdfDrawFillImage</code> elements.
     *
     * @return an iterator for all <code>OdfDrawFillImage</code> elements
     */
    public Iterable<OdfDrawFillImage> getFillImages() {
        if (mFillImages != null) {
            return mFillImages.values();
        } else {
            return new ArrayList<OdfDrawFillImage>();
        }
    }

    /** 
     * Returns the <code>OdfStyle</code> element with the given name and family.
     *
     * @param name is the name of the style
     * @param familyType is the family of the style
     * @return the style or null if there is no such style
     */
    public OdfStyle getStyle(String name, OdfStyleFamily familyType) {
        return mStylesBaseImpl.getStyle(name, familyType);
    }

    /** 
     * Returns an iterator for all <code>OdfStyle</code> elements for the given family.
     *
     * @param familyType
     * @return an iterator for all <code>OdfStyle</code> elements for the given family
     */
    public Iterable<OdfStyle> getStylesForFamily(OdfStyleFamily familyType) {
        return mStylesBaseImpl.getStylesForFamily(familyType);
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
        if (node instanceof OdfDefaultStyle) {
            OdfDefaultStyle defaultStyle = (OdfDefaultStyle) node;
            if (mDefaultStyles == null) {
                mDefaultStyles = new HashMap<OdfStyleFamily, OdfDefaultStyle>();
            }

            mDefaultStyles.put(defaultStyle.getFamily(), defaultStyle);
        } else if (node instanceof OdfDrawMarker) {
            OdfDrawMarker marker = (OdfDrawMarker) node;
            if (mMarker == null) {
                mMarker = new HashMap<String, OdfDrawMarker>();
            }

            mMarker.put(marker.getDrawNameAttribute(), marker);
        } else if (node instanceof OdfDrawGradient) {
            OdfDrawGradient gradient = (OdfDrawGradient) node;
            if (mGradients == null) {
                mGradients = new HashMap<String, OdfDrawGradient>();
            }

            mGradients.put(gradient.getDrawNameAttribute(), gradient);
        } else if (node instanceof OdfDrawHatch) {
            OdfDrawHatch hatch = (OdfDrawHatch) node;
            if (mHatches == null) {
                mHatches = new HashMap<String, OdfDrawHatch>();
            }

            mHatches.put(hatch.getDrawNameAttribute(), hatch);
        } else if (node instanceof OdfDrawFillImage) {
            OdfDrawFillImage fillImage = (OdfDrawFillImage) node;

            if (mFillImages == null) {
                mFillImages = new HashMap<String, OdfDrawFillImage>();
            }

            mFillImages.put(fillImage.getDrawNameAttribute(), fillImage);
        } else if (node instanceof OdfTextOutlineStyle) {
            mOutlineStyle = (OdfTextOutlineStyle) node;
        } else {
            mStylesBaseImpl.onOdfNodeInserted(node, refNode);
        }
    }

    @Override
    protected void onOdfNodeRemoved(OdfElement node) {
        if (node instanceof OdfDefaultStyle) {
            if (mDefaultStyles != null) {
                OdfDefaultStyle defaultStyle = (OdfDefaultStyle) node;
                mDefaultStyles.remove(defaultStyle.getFamily());
            }
        } else if (node instanceof OdfDrawMarker) {
            if (mMarker != null) {
                OdfDrawMarker marker = (OdfDrawMarker) node;
                mMarker.remove(marker.getDrawNameAttribute());
            }
        } else if (node instanceof OdfDrawGradient) {
            if (mGradients != null) {
                OdfDrawGradient gradient = (OdfDrawGradient) node;
                mGradients.remove(gradient.getDrawNameAttribute());
            }
        } else if (node instanceof OdfDrawHatch) {
            if (mHatches != null) {
                OdfDrawHatch hatch = (OdfDrawHatch) node;
                mHatches.remove(hatch.getDrawNameAttribute());
            }
        } else if (node instanceof OdfDrawFillImage) {
            if (mFillImages != null) {
                OdfDrawFillImage fillImage = (OdfDrawFillImage) node;
                mFillImages.remove(fillImage.getDrawNameAttribute());
            }
        } else if (node instanceof OdfTextOutlineStyle) {
            if (mOutlineStyle == (OdfTextOutlineStyle) node) {
                mOutlineStyle = null;
            }
        } else {
            mStylesBaseImpl.onOdfNodeRemoved(node);
        }
    }
}
