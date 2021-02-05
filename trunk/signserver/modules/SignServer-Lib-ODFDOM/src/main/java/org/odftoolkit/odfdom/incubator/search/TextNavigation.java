/************************************************************************
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
 * 
 * Copyright 2009 IBM. All rights reserved.
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
package org.odftoolkit.odfdom.incubator.search;

import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.odftoolkit.odfdom.OdfElement;
import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.doc.OdfDocument;
import org.odftoolkit.odfdom.doc.OdfTextDocument;
import org.odftoolkit.odfdom.doc.office.OdfOfficeMasterStyles;
import org.odftoolkit.odfdom.doc.text.OdfWhitespaceProcessor;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * A derived Navigation class used for navigate the text content
 * it is used to search the document and find the matched text 
 * and would return TextSelection instance
 *
 */
public class TextNavigation extends Navigation {

	private String mMatchedElementName = "text:p,text:h";
	private String mPatternText;
	private OdfTextDocument mTextDocument;
	private TextSelection mCurrentSelectedItem;
	private String mCurrentText;
	private int mCurrentIndex;
	private boolean mbFinishFindInHeaderFooter;

	/**
	 * Construct TextNavigation with matched condition and navigation scope
	 * @param pattern	the matched pattern String
	 * @param doc	the navigation scope
	 */
	public TextNavigation(String pattern, OdfTextDocument doc) {
		this.mPatternText = pattern;
		mTextDocument = doc;
		mCurrentSelectedItem = null;
		mbFinishFindInHeaderFooter = false;
	}

	//the matched text might exist in header/footer
	private TextSelection findInHeaderFooter(TextSelection selected) {
		OdfFileDom styledom = null;
		OdfOfficeMasterStyles masterpage = null;
		OdfElement element = null;

		if (selected != null) {
			OdfElement containerElement = selected.getContainerElement();
			int index = selected.getIndex();
			OdfWhitespaceProcessor textProcessor = new OdfWhitespaceProcessor();
			String content = textProcessor.getText(containerElement);

			int nextIndex = -1;
			Pattern pattern = Pattern.compile(mPatternText);
			Matcher matcher = pattern.matcher(content);
			//start from the end index of the selected item
			if (matcher.find(index + selected.getText().length())) {
				// here just consider \n\r\t occupy one char
				nextIndex = matcher.start();
				int eIndex = matcher.end();
				mCurrentText = content.substring(nextIndex, eIndex);
			}
			if (nextIndex != -1) {
				TextSelection item = new TextSelection(mCurrentText, selected.getContainerElement(), nextIndex);
				return item;
			}
		}
		try {
			styledom = mTextDocument.getStylesDom();
			NodeList list = styledom.getElementsByTagName("office:master-styles");
			if (styledom == null) {
				return null;
			}
			if (list.getLength() > 0) {
				masterpage = (OdfOfficeMasterStyles) list.item(0);
			} else {
				return null;
			}

			if (selected == null) {
				element = (OdfElement) getNextMatchElementInTree(masterpage, masterpage);
			} else {
				element = (OdfElement) getNextMatchElementInTree(selected.getContainerElement(), masterpage);
			}

			if (element != null) {
				TextSelection item = new TextSelection(mCurrentText, element, mCurrentIndex);
				return item;
			} else {
				return null;
			}

		} catch (Exception ex) {
			Logger.getLogger(TextNavigation.class.getName()).log(Level.SEVERE, null, ex);
			ex.printStackTrace();
		}
		return null;
	}

	//found the next selection start from the 'selected' TextSelection
	private TextSelection findnext(TextSelection selected) {
		if (!mbFinishFindInHeaderFooter) {
			TextSelection styleselected = findInHeaderFooter(selected);
			if (styleselected != null) {
				return styleselected;
			}
			selected = null;
			mbFinishFindInHeaderFooter = true;
		}

		if (selected == null) {
			OdfElement element = null;
			try {
				element = (OdfElement) getNextMatchElement((Node) mTextDocument.getContentRoot());
			} catch (Exception ex) {
				Logger.getLogger(TextNavigation.class.getName()).log(Level.SEVERE, null, ex);
				ex.printStackTrace();

			}
			if (element != null) {
				return new TextSelection(mCurrentText, element, mCurrentIndex);
			} else {
				return null;
			}
		}

		OdfElement containerElement = selected.getContainerElement();
		int index = selected.getIndex();
		OdfWhitespaceProcessor textProcessor = new OdfWhitespaceProcessor();
		String content = textProcessor.getText(containerElement);

		int nextIndex = -1;
		Pattern pattern = Pattern.compile(mPatternText);
		Matcher matcher = pattern.matcher(content);
		//start from the end index of the selected item
		if (matcher.find(index + selected.getText().length())) {
			// here just consider \n\r\t occupy one char
			nextIndex = matcher.start();
			int eIndex = matcher.end();
			mCurrentText = content.substring(nextIndex, eIndex);
		}
		if (nextIndex != -1) {
			TextSelection item = new TextSelection(mCurrentText, selected.getContainerElement(), nextIndex);
			return item;
		} else {
			OdfElement element = (OdfElement) getNextMatchElement((Node) containerElement);
			if (element != null) {
				TextSelection item = new TextSelection(mCurrentText, element, mCurrentIndex);
				return item;
			} else {
				return null;
			}
		}
	}

	/* (non-Javadoc)
	 * @see org.odftoolkit.odfdom.incubator.search.Navigation#getCurrentItem()
	 */
	@Override
	public Selection getCurrentItem() {
		Selection.SelectionManager.registerItem(mCurrentSelectedItem);
		return mCurrentSelectedItem;
	}

	/* (non-Javadoc)
	 * @see org.odftoolkit.odfdom.incubator.search.Navigation#hasNext()
	 */
	@Override
	public boolean hasNext() {
		mCurrentSelectedItem = findnext(mCurrentSelectedItem);
		return (mCurrentSelectedItem != null);
	}

	/**
	 * check if the text content of element match the specified pattern string
	 * @param element	navigate this element
	 * @return true if the text content of this element match this pattern; 
	 * 		   false if not match
	 */
	@Override
	public boolean match(Node element) {
		if (element instanceof OdfElement) {
			if (mMatchedElementName.indexOf(element.getNodeName()) != -1) {
				OdfWhitespaceProcessor textProcessor = new OdfWhitespaceProcessor();
				String content = textProcessor.getText(element);

				Pattern pattern = Pattern.compile(mPatternText);
				Matcher matcher = pattern.matcher(content);
				while (matcher.find()) {
					System.out.println(matcher.group());
					// here just consider \n\r\t occupy one char
					mCurrentIndex = matcher.start();
					int eIndex = matcher.end();
					mCurrentText = content.substring(mCurrentIndex, eIndex);
					return true;
				}
			}
		}
		return false;
	}
}
