
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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.dom.element.OdfStyleBase;
import org.odftoolkit.odfdom.dom.element.text.TextListLevelStyleElementBase;
import org.odftoolkit.odfdom.dom.element.text.TextListStyleElement;
import org.odftoolkit.odfdom.dom.style.OdfStyleFamily;
import org.odftoolkit.odfdom.dom.style.props.OdfListLevelProperties;
import org.w3c.dom.Node;

/**
 * Convenient functionalty for the parent ODF OpenDocument element
 *
 * List styles require a lot of code to create one level at a time.
 * This class contains constructors that create an entire OdfListStyle
 * based on a delimited string or an array of strings.
 * Each item in the string (or array) represents a list level
 * style for levels 1-10.
 *
 * <p>If an item contains <code>1</code>, <code>I</code>,
 * <code>i</code>, <code>A</code>, or <code>a</code>, then it is presumed
 * to be a numbering style; otherwise it is a bulleted style.</p>
 */
public class OdfTextListStyle extends TextListStyleElement
{
   
	private static final long serialVersionUID = -5493176392198676430L;

	/** Maximum number of levels in a list. */
	protected static final int MAX_LIST_LEVEL = 10;
	/** List should show all levels of numbering. */
	public static final boolean SHOW_ALL_LEVELS = true;
	/** List should show only one level of numbering. */
	public static final boolean SHOW_ONE_LEVEL = false;

	public OdfTextListStyle( OdfFileDom ownerDoc )
    {
        super( ownerDoc );
    }

	/**
	 * Creates an OdfListStyle.
	 * @param ownerDoc the document that this list style belongs to.
	 * @param name the name of this list style.
	 * @param specifiers the string of level specifiers.
	 * @param delim the delimiter for splitting the string into levels.
	 * @param spacing a css "length" telling how far to indent each level; also min. label width
	 * @param showAllLevels true if you want to display all levels of numbering, false otherwise.
	*/
	public OdfTextListStyle(OdfFileDom ownerDoc,
		String name,
		String specifiers, String delim, String spacing, boolean showAllLevels)
	{
		super(ownerDoc);
		String[] specArray = specifiers.split(delim);
		newListStyle(name, specArray, spacing, showAllLevels);
	}

	/**
	 * Constructor for OdfEasyListStyle.
	 * @param ownerDoc the document that this list style belongs to.
	 * @param name the name of this list style.
	 * @param specArray an array of strings of level specifications.
	 * @param spacing a css "length" telling how far to indent each level; also min. label width
	 * @param showAllLevels true if you want to display all levels of numbering, false otherwise.
	*/
	public OdfTextListStyle(OdfFileDom ownerDoc,
		String name,
		String[] specArray, String spacing, boolean showAllLevels)
	{
		super(ownerDoc);
		newListStyle(name, specArray, spacing, showAllLevels);
	}

	/** returns the given level or null if it does not exist
     * 
     * @param level is the level number that should be returned
     * @return an instance of TextListLevelStyleImageElement,
     *         TextListLevelStyleBulletElement, TextListLevelStyleNumberElement or
     *         null.
     */
    public TextListLevelStyleElementBase getLevel(int level )
    {
        Node levelElement = this.getFirstChild();
        
        while( levelElement != null )
        {
            if( levelElement instanceof TextListLevelStyleElementBase )
            {
                if( level == 1 ) {
                    return (TextListLevelStyleElementBase) levelElement;
                }
                else {
                    --level;
                }
                
            }
            levelElement = levelElement.getNextSibling();
        }
        return null;
    }

    /** always returns the given level with the given class. If that level does
     *  not exist or has a different class than it is (re)created.
     * 
     * @param level is the level number that should be returned
     * @param clazz is the class of the level, should be
     *        TextListLevelStyleImageElement, TextListLevelStyleBulletElement or
     *        TextListLevelStyleNumberElement.
     * @return
     *        a list level style with the given level and class
     */
    @SuppressWarnings("unchecked")
    public TextListLevelStyleElementBase getOrCreateListLevel( int level, Class clazz )
    {
        TextListLevelStyleElementBase levelStyle = getLevel( level );
        if( (levelStyle != null) && clazz.isInstance(levelStyle) ) {
            return levelStyle;
        }
        
        if( levelStyle != null ) {
            removeChild(levelStyle);
        }
        
        levelStyle = (TextListLevelStyleElementBase)
                        ((OdfFileDom)this.ownerDocument).newOdfElement(clazz);
        levelStyle.setTextLevelAttribute(level);
        appendChild(levelStyle);
        
        return levelStyle;
    }
    
    @Override
    public OdfStyleFamily getFamily()
    {
        return OdfStyleFamily.List;
    }

    @Override
    public OdfStyleBase getParentStyle()
    {
        return null;
    }

	/**
	 * Creates the OdfTextListStyle element.
	 * This is a utility routine called by the constructors.
	 * @param name the <code>style:name</code> of this list style
	 * @param specArray specifications for each level of the list
	 * @param spacing a CSS length that gives the amount of space before
	 * a label and the minimum label width
	 * @param showAllLevels if true, display all levels of a numbered list item
	 */
	private void newListStyle(String name,
		String[] specArray, String spacing,
		boolean showAllLevels)
	{
		Pattern numFormatPattern = Pattern.compile("([1IiAa])");
		Pattern cssLengthPattern = Pattern.compile("([^a-z]+)\\s*([a-z]+)?");
		String numPrefix = "";
		String numSuffix = "";
		String numberFormat = "";
		Matcher m;
		double cssLengthNum;
		String cssLengthUnits;
		int displayLevels;

		OdfTextListLevelStyleNumber number;
		OdfTextListLevelStyleBullet bullet;
		TextListLevelStyleElementBase styleItem;

		this.setStyleNameAttribute(name);

		// split up the spacing into length and units
		m = cssLengthPattern.matcher(spacing);
		if (m.find())
		{
			try
			{
				cssLengthNum = Double.parseDouble(m.group(1));
			}
			catch (NumberFormatException oops)
			{
				cssLengthNum = 0.0;
			}
			cssLengthUnits = (m.group(2) == null) ? "" : m.group(2);
		}
		else
		{
			cssLengthNum = 0;
			cssLengthUnits = "";
		}


		for (int i = 0; i < Math.min(specArray.length, MAX_LIST_LEVEL); i++)
		{
			specArray[i] = specArray[i].trim();
			m = numFormatPattern.matcher( specArray[i] );
			if (m.find())	// if it has 1, I, i, A, or a, it's a numbering style
			{
				numberFormat = m.group(1);
				numPrefix = specArray[i].substring( 0, m.start(1) );
				numSuffix = specArray[i].substring( m.end(1) );
				displayLevels = (showAllLevels) ? (i+1) : 1;
				number = new OdfTextListLevelStyleNumber(
					(OdfFileDom)this.ownerDocument);
				number.setStyleNumPrefixAttribute(numPrefix);
				number.setStyleNumFormatAttribute(numberFormat);
				number.setStyleNumSuffixAttribute(numSuffix);
				number.setTextDisplayLevelsAttribute( displayLevels );
				styleItem = number;
			}
			else	// it's a bullet style
			{
				bullet = new OdfTextListLevelStyleBullet(
					(OdfFileDom)this.ownerDocument);
				bullet.setStyleNumPrefixAttribute("");
				bullet.setStyleNumSuffixAttribute("");
				if (!specArray[i].equals(""))
				{
					bullet.setTextBulletCharAttribute(specArray[i].substring(0,1));
				}
				else
				{
					bullet.setTextBulletCharAttribute("");
				}
				styleItem = bullet;
			}

			styleItem.setTextLevelAttribute(i+1);
			styleItem.setProperty(OdfListLevelProperties.SpaceBefore,
				Double.toString(cssLengthNum * (i+1)) + cssLengthUnits);
			styleItem.setProperty(OdfListLevelProperties.MinLabelWidth,
				Double.toString(cssLengthNum) + cssLengthUnits);
			this.appendChild(styleItem);

		}
	}

}
