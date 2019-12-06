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

import java.util.logging.Logger;

import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.doc.office.OdfOfficeAutomaticStyles;
import org.odftoolkit.odfdom.doc.office.OdfOfficeStyles;
import org.odftoolkit.odfdom.dom.element.text.TextListElement;
import org.odftoolkit.odfdom.dom.element.text.TextListLevelStyleElementBase;
import org.w3c.dom.Node;

/**
 * Convenient functionalty for the parent ODF OpenDocument element
 *
 */
public class OdfTextList extends TextListElement
{
	/** 
	 * Creates a new instance of OdfList.
	 * 
     * @param ownerDoc 
     */
    public OdfTextList(OdfFileDom ownerDoc) {
        super(ownerDoc);
    }

	/** 
	 * Creates a new instance of OdfList.
	 * 
     * @param	ownerDoc	The document to which the list belongs
	 * @param	itemList	An array of the list items, each preceded by
	 *						delimiters that	indicate nesting level.
	 * @param	indentDelim The character used as level nesting delimiter.
	 * @param	listStyleName	Name to be applied to each
	 *							 <code>text:list</code> element.
     */
	public OdfTextList(OdfFileDom ownerDoc, String[] itemList, char indentDelim,
		String listStyleName)
	{
		super(ownerDoc);
		OdfTextList[] listArray = new OdfTextList[10];
		OdfTextListItem listItem;
		OdfTextParagraph para;
		String item;
		int level = 0;
		int lastLevel = 0;
		int lev; // loop counter

		listArray[0] = this;
		for (int i = 0; i < itemList.length; i++)
		{
			level = 0;
			item = itemList[i];

			// determine level of indenting by counting delimiters,
			// then get rid of the delimiters
			while (level < item.length() && item.charAt(level) == indentDelim)
			{
				level++;
			}
			item = item.substring(level);

			if (level > lastLevel) // open the sub-levels
			{
				for (lev = lastLevel+1; lev <= level; lev++)
				{
					listArray[lev] = new OdfTextList(ownerDoc);
					listArray[lev].setTextStyleNameAttribute(listStyleName);
				}
			}
			else if (level < lastLevel)	// close off the intervening lists
			{
				closeLevels(ownerDoc, listArray, lastLevel, level);
			}
			 // now that we are at the proper level, add the item.
			listArray[level].setTextStyleNameAttribute(listStyleName);
			listItem = new OdfTextListItem(ownerDoc);
			para = new OdfTextParagraph(ownerDoc);
			para.setTextContent(item);
			listItem.appendChild(para);
			listArray[level].appendChild(listItem);
			lastLevel = level;
		}

		// close off any remaining open lists
		closeLevels(ownerDoc, listArray, lastLevel, 0);
	}

	private void closeLevels(OdfFileDom ownerDoc,
		OdfTextList[] listArray, int fromLevel, int toLevel)
	{
		for (int level = fromLevel; level > toLevel; level--)
		{
			if (!listArray[level-1].hasChildNodes())
			{
				/* Force a list item */
				listArray[level-1].appendChild(
					new OdfTextListItem(ownerDoc));
			}
			listArray[level-1].getLastChild().appendChild(
				listArray[level]);
		}
	}

    /**
     * Retrieves Odf Text List Style
     * 
     * @return the <code>OdfTextListStyle</code> element
     */
	public OdfTextListStyle getListStyle() 
    {
        OdfTextListStyle style = null;
        
        String listName = getTextStyleNameAttribute();
        if (listName != null && listName.length() > 0)
        {
            OdfOfficeAutomaticStyles autoStyles = ((OdfFileDom)this.ownerDocument).getAutomaticStyles();
            if( autoStyles != null ) {
				style = autoStyles.getListStyle(listName);
			}
            
            if( style == null )
            {
            	OdfOfficeStyles styles = mOdfDocument.getDocumentStyles();
                if( styles != null ) {
                    style = styles.getListStyle(listName);
                }
            }
        }
        else
        {
            // if no style is specified at this particular list element, we
            // ask the parent list (if any)
            OdfTextList parentList = getParentList();
            if (parentList != null) {
                style = parentList.getListStyle();
            }
        }
        
        return style;
    }

	/**
	 * Retrieves the list level count
	 * 
	 * @return the level count
	 */
    public int getListLevel() {
        int level = 1;
        Node parent = getParentNode();
        while (parent != null) {
            if (parent instanceof TextListElement) {
                level++;
            }
            parent = parent.getParentNode();
        }
        return level;
    }

    /**
     * Retrieves the List Level Style
     * 
     * @return the <code>TextListLevelStyleElementBase</code>
     */
    public TextListLevelStyleElementBase getListLevelStyle() {
        TextListLevelStyleElementBase odfListLevelStyle = null;
        OdfTextListStyle style = getListStyle();
        int level = getListLevel();
        if (style != null) {
            odfListLevelStyle = style.getLevel(level);
        } else {
            Logger.getLogger(OdfTextList.class.getName()).warning("No ListLevelStyle found!");
        }
        return odfListLevelStyle;
    }

    /**
     * Retrieves or create local list style
     * 
     * @return the <code>OdfTextListStyle</code> element
     */
    public OdfTextListStyle getOrCreateLocalListStyle()
    {
        OdfTextListStyle listStyle = getListStyle();
        if( listStyle == null )
        {
            OdfOfficeAutomaticStyles autoStyles = ((OdfFileDom)this.ownerDocument).getOrCreateAutomaticStyles();
            if( autoStyles != null ) {
				listStyle = autoStyles.newListStyle();
			}
        }
        return listStyle;
    }

    /**
     * Retrieves the parent list of text list
     * 
     * @return The <code>OdfTextList</code>
     */
    public OdfTextList getParentList() {
        Node parent = getParentNode();
        while (parent != null) {
            if (parent instanceof OdfTextList) {
                return (OdfTextList) parent;
            }
            parent = parent.getParentNode();
        }
        return null;
    }

}
