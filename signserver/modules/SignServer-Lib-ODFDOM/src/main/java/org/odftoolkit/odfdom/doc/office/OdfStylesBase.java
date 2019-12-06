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
import org.odftoolkit.odfdom.doc.number.OdfNumberBooleanStyle;
import org.odftoolkit.odfdom.doc.number.OdfNumberCurrencyStyle;
import org.odftoolkit.odfdom.doc.number.OdfNumberDateStyle;
import org.odftoolkit.odfdom.doc.number.OdfNumberPercentageStyle;
import org.odftoolkit.odfdom.doc.number.OdfNumberTextStyle;
import org.odftoolkit.odfdom.doc.number.OdfNumberTimeStyle;
import org.odftoolkit.odfdom.doc.style.OdfStyle;
import org.odftoolkit.odfdom.doc.text.OdfTextListStyle;
import org.odftoolkit.odfdom.OdfElement;
import org.odftoolkit.odfdom.doc.number.OdfNumberStyle;
import org.odftoolkit.odfdom.dom.style.OdfStyleFamily;
import org.w3c.dom.Node;

/**
 * Implements shared functions for OdfAutomaticStyles and OdfStyles.
 */
class OdfStylesBase {

    private HashMap<OdfStyleFamily, ArrayList<OdfStyle>> mStyles;
    private ArrayList<OdfTextListStyle> mListStyles;
    private ArrayList<OdfNumberStyle> mNumberStyles;
    private ArrayList<OdfNumberDateStyle> mDateStyles;
    private ArrayList<OdfNumberPercentageStyle> mPercentageStyles;
    private ArrayList<OdfNumberCurrencyStyle> mCurrencyStyles;
    private ArrayList<OdfNumberTimeStyle> mTimeStyles;
    private ArrayList<OdfNumberBooleanStyle> mBooleanStyles;
    private ArrayList<OdfNumberTextStyle> mTextStyles;

    // For documentation see OdfAutomaticStyles or OdfStyles.
    OdfStyle getStyle(String name, OdfStyleFamily familyType) {
        if (mStyles != null) {
            ArrayList<OdfStyle> familyMap = mStyles.get(familyType);
            if (familyMap != null) {
                for (OdfStyle odfStyleStyle : familyMap) {
                    if (odfStyleStyle.getStyleNameAttribute().equals(name)) {
                        return odfStyleStyle;
                    }
                }
            }
        }
        return null;
    }

    /** Returns an iterator for all <code>OdfStyle</code> elements.
     *
     * @return iterator for all <code>OdfStyle</code> elements
     */
    Iterable<OdfStyle> getAllOdfStyles() {
        ArrayList<OdfStyle> allStyles = new ArrayList<OdfStyle>();
        if (mStyles != null) {
            for (OdfStyleFamily family : mStyles.keySet()) {
                ArrayList<OdfStyle> familySet = mStyles.get(family);
                if (familySet != null) {
                    allStyles.addAll(familySet);
                }
            }
        }
        return allStyles;
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    Iterable<OdfStyle> getStylesForFamily(OdfStyleFamily familyType) {
        if (mStyles != null) {
            ArrayList<OdfStyle> familyStyles = mStyles.get(familyType);
            if (familyStyles != null) {
                return familyStyles;
            }
        }
        return new ArrayList<OdfStyle>();
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    OdfTextListStyle getListStyle(String name) {
        if (mListStyles != null) {
            for (OdfTextListStyle odfTextListStyle : mListStyles) {
                if (odfTextListStyle.getStyleNameAttribute().equals(name)) {
                    return odfTextListStyle;
                }
            }
        }
        return null;
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    Iterable<OdfTextListStyle> getListStyles() {
        if (mListStyles != null) {
            return mListStyles;
        } else {
            return new ArrayList<OdfTextListStyle>();
        }
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    OdfNumberStyle getNumberStyle(String name) {
        if (mNumberStyles != null) {
            for (OdfNumberStyle odfNumberStyle : mNumberStyles) {
                if (odfNumberStyle.getStyleNameAttribute().equals(name)) {
                    return odfNumberStyle;
                }
            }
        }
        return null;
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    Iterable<OdfNumberStyle> getNumberStyles() {
        if (mNumberStyles != null) {
            return mNumberStyles;
        } else {
            return new ArrayList<OdfNumberStyle>();
        }
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    OdfNumberDateStyle getDateStyle(String name) {
        if (mDateStyles != null) {
            for (OdfNumberDateStyle odfNumberDateStyle : mDateStyles) {
                if (odfNumberDateStyle.getStyleNameAttribute().equals(name)) {
                    return odfNumberDateStyle;
                }
            }
        }
        return null;
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    Iterable<OdfNumberDateStyle> getDateStyles() {
        if (mDateStyles != null) {
            return mDateStyles;
        } else {
            return new ArrayList<OdfNumberDateStyle>();
        }
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    OdfNumberPercentageStyle getPercentageStyle(String name) {
        if (mPercentageStyles != null) {
            for (OdfNumberPercentageStyle odfNumberPercentageStyle : mPercentageStyles) {
                if (odfNumberPercentageStyle.getStyleNameAttribute().equals(name)) {
                    return odfNumberPercentageStyle;
                }
            }
        }
        return null;
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    Iterable<OdfNumberPercentageStyle> getPercentageStyles() {
        if (mPercentageStyles != null) {
            return mPercentageStyles;
        } else {
            return new ArrayList<OdfNumberPercentageStyle>();
        }
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    OdfNumberCurrencyStyle getCurrencyStyle(String name) {
        if (mCurrencyStyles != null) {
            for (OdfNumberCurrencyStyle odfNumberCurrencyStyle : mCurrencyStyles) {
                if (odfNumberCurrencyStyle.getStyleNameAttribute().equals(name)) {
                    return odfNumberCurrencyStyle;
                }
            }
        }
        return null;
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    Iterable<OdfNumberCurrencyStyle> getCurrencyStyles() {
        if (mCurrencyStyles != null) {
            return mCurrencyStyles;
        } else {
            return new ArrayList<OdfNumberCurrencyStyle>();
        }
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    OdfNumberTimeStyle getTimeStyle(String name) {
        if (mTimeStyles != null) {
            for (OdfNumberTimeStyle odfNumberTimeStyle : mTimeStyles) {
                if (odfNumberTimeStyle.getStyleNameAttribute().equals(name)) {
                    return odfNumberTimeStyle;
                }
            }
        }
        return null;
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    Iterable<OdfNumberTimeStyle> getTimeStyles() {
        if (mTimeStyles != null) {
            return mTimeStyles;
        } else {
            return new ArrayList<OdfNumberTimeStyle>();
        }
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    OdfNumberBooleanStyle getBooleanStyle(String name) {
        if (mBooleanStyles != null) {
            for (OdfNumberBooleanStyle odfNumberBooleanStyle : mBooleanStyles) {
                if (odfNumberBooleanStyle.getStyleNameAttribute().equals(name)) {
                    return odfNumberBooleanStyle;
                }
            }
        }
        return null;
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    Iterable<OdfNumberBooleanStyle> getBooleanStyles() {
        if (mBooleanStyles != null) {
            return mBooleanStyles;
        } else {
            return new ArrayList<OdfNumberBooleanStyle>();
        }
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    OdfNumberTextStyle getTextStyle(String name) {
        if (mTextStyles != null) {
            for (OdfNumberTextStyle odfNumberTextStyle : mTextStyles) {
                if (odfNumberTextStyle.getStyleNameAttribute().equals(name)) {
                    return odfNumberTextStyle;
                }
            }
        }
        return null;
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    Iterable<OdfNumberTextStyle> getTextStyles() {
        if (mTextStyles != null) {
            return mTextStyles;
        } else {
            return new ArrayList<OdfNumberTextStyle>();
        }
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    void onOdfNodeInserted(OdfElement node, Node refNode) {
        if (node instanceof OdfStyle) {
            OdfStyle style = (OdfStyle) node;
            if (mStyles == null) {
                mStyles = new HashMap<OdfStyleFamily, ArrayList<OdfStyle>>();
            }
            ArrayList<OdfStyle> familyMap = mStyles.get(style.getFamily());
            if (familyMap == null) {
                familyMap = new ArrayList<OdfStyle>();
                mStyles.put(style.getFamily(), familyMap);
            }
            // do not need return value: familyMap is never null.
            addStyleToList(familyMap, style);
        } else if (node instanceof OdfTextListStyle) {
            mListStyles = addStyleToList(mListStyles, (OdfTextListStyle) node);
        } else if (node instanceof OdfNumberStyle) {
            mNumberStyles = addStyleToList(mNumberStyles, (OdfNumberStyle) node);
        } else if (node instanceof OdfNumberDateStyle) {
            mDateStyles = addStyleToList(mDateStyles, (OdfNumberDateStyle) node);
        } else if (node instanceof OdfNumberPercentageStyle) {
            mPercentageStyles = addStyleToList(mPercentageStyles, (OdfNumberPercentageStyle) node);
        } else if (node instanceof OdfNumberCurrencyStyle) {
            mCurrencyStyles = addStyleToList(mCurrencyStyles, (OdfNumberCurrencyStyle) node);
        } else if (node instanceof OdfNumberTimeStyle) {
            mTimeStyles = addStyleToList(mTimeStyles, (OdfNumberTimeStyle) node);
        } else if (node instanceof OdfNumberBooleanStyle) {
            mBooleanStyles = addStyleToList(mBooleanStyles, (OdfNumberBooleanStyle) node);
        } else if (node instanceof OdfNumberTextStyle) {
            mTextStyles = addStyleToList(mTextStyles, (OdfNumberTextStyle) node);
        }
    }

    // For documentation see OdfAutomaticStyles or OdfStyles.
    void onOdfNodeRemoved(OdfElement node) {
        if (node instanceof OdfStyle) {
            if (mStyles != null) {
                OdfStyle style = (OdfStyle) node;
                ArrayList<OdfStyle> familyMap = mStyles.get(style.getFamily());
                removeOdfStyleFromList(familyMap, style);
                if (familyMap != null && familyMap.isEmpty()) {
                    mStyles.remove(style.getFamily());
                }
            }
        } else if (node instanceof OdfTextListStyle) {
            removeStyleFromList(mListStyles, (OdfTextListStyle) node);
        } else if (node instanceof OdfNumberStyle) {
            removeStyleFromList(mNumberStyles, (OdfNumberStyle) node);
        } else if (node instanceof OdfNumberDateStyle) {
            removeStyleFromList(mDateStyles, (OdfNumberDateStyle) node);
        } else if (node instanceof OdfNumberPercentageStyle) {
            removeStyleFromList(mPercentageStyles, (OdfNumberPercentageStyle) node);
        } else if (node instanceof OdfNumberCurrencyStyle) {
            removeStyleFromList(mCurrencyStyles, (OdfNumberCurrencyStyle) node);
        } else if (node instanceof OdfNumberTimeStyle) {
            removeStyleFromList(mTimeStyles, (OdfNumberTimeStyle) node);
        } else if (node instanceof OdfNumberBooleanStyle) {
            removeStyleFromList(mBooleanStyles, (OdfNumberBooleanStyle) node);
        } else if (node instanceof OdfNumberTextStyle) {
            removeStyleFromList(mTextStyles, (OdfNumberTextStyle) node);
        }
    }

    /**
     * Add a generic style to a generic list.
     * @param <T> Any style class.
     * @param list The list, may be null if list nis used for the first time.
     * @param style The style that has to be added to the list.
     * @return The list: needed if the list is null initially: the new created
     * list is not implicitly returned in that case.
     */
    private static <T> ArrayList<T> addStyleToList(ArrayList<T> list, T style) {
        if (list == null) {
            list = new ArrayList<T>();
        }
        list.add(style);
        return list;
    }

    /**
     * Remove a generic style from a generic list.
     * @param <T> Any style class.
     * @param list The list, may be null: nothing is done then.
     * @param style The style that has to be removed from the list.
     */
    private static <T> void removeStyleFromList(ArrayList<T> list, T style) {
        if (list != null) {
            list.remove(style);
        }
    }

    /**
     * Remove a style of type OdfStyle from a list. This is necessary because
     * OdfStyleBase extends equals, so styles may be equal in the list with
     * different names.
     * @param list The list, may be null: nothing is done then.
     * @param style The style that has to be removed from the list.
     */
    private static void removeOdfStyleFromList(ArrayList<OdfStyle> list, OdfStyle style) {
        if (list != null) {
            int index = 0;
            ArrayList<OdfStyle> removed = new ArrayList<OdfStyle>();
            while ((index = list.indexOf(style)) != -1) {
                OdfStyle removedStyle = list.remove(index);
                if (!style.getStyleNameAttribute().equals(removedStyle.getStyleNameAttribute())) {
                    removed.add(removedStyle);
                }
            }
            list.addAll(removed);
        }
    }
}
