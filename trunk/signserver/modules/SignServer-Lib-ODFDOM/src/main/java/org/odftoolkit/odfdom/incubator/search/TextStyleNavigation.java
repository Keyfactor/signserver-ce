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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;

import org.odftoolkit.odfdom.OdfElement;
import org.odftoolkit.odfdom.OdfNamespace;
import org.odftoolkit.odfdom.doc.OdfTextDocument;
import org.odftoolkit.odfdom.doc.style.OdfDefaultStyle;
import org.odftoolkit.odfdom.doc.style.OdfStyle;
import org.odftoolkit.odfdom.doc.text.OdfTextHeading;
import org.odftoolkit.odfdom.doc.text.OdfTextParagraph;
import org.odftoolkit.odfdom.dom.OdfNamespaceNames;
import org.odftoolkit.odfdom.dom.element.OdfStylableElement;
import org.odftoolkit.odfdom.dom.style.OdfStyleFamily;
import org.odftoolkit.odfdom.dom.style.props.OdfStyleProperty;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * A derived Navigation class used for navigate the mText content
 * it is used to search the document and find the matched style properties
 * and would return TextSelection instance
 */
public class TextStyleNavigation extends Navigation {

	private OdfTextDocument mTextDocument;
	private TextSelection mCurrentSelectedItem;
	private int mCurrentIndex;
	private Map<OdfStyleProperty, String> mProps;
	private String mText;
	private Node mPhNode;
	private int mIndex;
	private Node mNode;

	/**
	 * Construct TextStyleNavigation with style properties condition and navigation scope
	 * @param props	the matched style properties conditions
	 * @param doc	the navigation search scope
	 */
	public TextStyleNavigation(Map<OdfStyleProperty, String> props, OdfTextDocument doc) {
		mTextDocument = doc;
		mCurrentSelectedItem = null;
		this.mProps = props;
	}

	/*
	 * Find next TextSelection which match specified style
	 */
	private TextSelection findnext(TextSelection selected) {
		OdfElement element = null;
		if (selected == null) {

			try {
				mNode = getNextMatchElement((Node) mTextDocument.getContentRoot());
			} catch (Exception ex) {
				Logger.getLogger(TextStyleNavigation.class.getName()).log(Level.SEVERE, null, ex);
				ex.printStackTrace();
			}
		} else {
			try {
				mNode = getNextMatchElement(mNode);
			} catch (Exception ex) {
				Logger.getLogger(TextStyleNavigation.class.getName()).log(Level.SEVERE, null, ex);
				ex.printStackTrace();
			}
		}
		if (mNode != null) {
			element = (OdfElement) getPHElement(mNode);
			TextSelection item = new TextSelection(mText, element, mCurrentIndex);
			return item;
		}
		return null;
	}

	private Node getPHElement(Node node) {

		//get paragraph or heading element       
		if (node instanceof OdfTextParagraph) {
			mPhNode = node;
		} else if (node instanceof OdfTextHeading) {
			mPhNode = node;
		} else {
			getPHElement(node.getParentNode());
		}
		return mPhNode;
	}

	/* (non-Javadoc)
	 * get current TextSelection
	 * @see org.odftoolkit.odfdom.incubator.search.Navigation#getCurrentItem()
	 */
	@Override
	public Selection getCurrentItem() {
		Selection.SelectionManager.registerItem(mCurrentSelectedItem);
		return mCurrentSelectedItem;
	}

	/* (non-Javadoc)
	 * check if has next TextSelection with satisfied style
	 * @see org.odftoolkit.odfdom.incubator.search.Navigation#hasNext()
	 */
	@Override
	public boolean hasNext() {
		mCurrentSelectedItem = findnext(mCurrentSelectedItem);
		return (mCurrentSelectedItem != null);
	}

	/**
	 * check if the element has the specified style properties
	 * @param element	navigate this element
	 * @return true if this element has the specified style properties
	 * 		   false if not match
	 */
	@Override
	public boolean match(Node element) {
		boolean match = false;
		if (element.getNodeType() == Node.TEXT_NODE && !element.getNodeValue().trim().equals("")) {
			if (element.getParentNode() instanceof OdfStylableElement) {
				OdfStylableElement parStyleElement = (OdfStylableElement) element.getParentNode();

				String parStyleName = getStyleName(parStyleElement);

				if (getMatchStyleNames().contains(parStyleName)) {
					match = true;
					mText = element.getNodeValue();
					NodeList nodes = getPHElement(element.getParentNode()).getChildNodes();
					mIndex = 0;
					getIndex(nodes, element);
				}
			}
		}
		return match;
	}

	private void getIndex(NodeList nodes, Node element) {
		for (int i = 0; i < nodes.getLength(); i++) {
			Node node = nodes.item(i);
			if (node == element) {
				mCurrentIndex = mIndex;
				break;
			} else {
				if (node.getNodeType() == Node.TEXT_NODE) {
					mIndex = mIndex + node.getNodeValue().length();
				} else if (node.getNodeType() == Node.ELEMENT_NODE) {
					if (node.getLocalName().equals("s")) // mText:s
					{
						try {
							mIndex = mIndex + Integer.parseInt(((Element) node).getAttributeNS(OdfNamespaceNames.TEXT.getNamespaceUri(), "c"));
						} catch (Exception e) {
							mIndex++;
						}

					} else if (node.getLocalName().equals("line-break")) {
						mIndex++;
					} else if (node.getLocalName().equals("tab")) {
						mIndex++;
					} else {
						getIndex(node.getChildNodes(), element);
					}
				}
			}
		}
	}

	private String getStyleName(OdfStylableElement element) {
		String stylename = element.getStyleName();
		if (stylename == null) {
			if (element.getParentNode() instanceof OdfStylableElement) {
				getStyleName((OdfStylableElement) element.getParentNode());
			} else {
				stylename = "defaultstyle";
			}
		}
		return stylename;
	}

	private Set<String> getMatchStyleNames() {
		XPath mInputXPath = XPathFactory.newInstance().newXPath();
		mInputXPath.setNamespaceContext(new OdfNamespace());
		Set<String> styleNames = new HashSet<String>();
		String sname;
		HashMap<String, OdfDefaultStyle> defaultStyles = new HashMap<String, OdfDefaultStyle>();
		try {

			NodeList defStyleList = mTextDocument.getDocumentStyles().getElementsByTagName("style:default-style");
			for (int i = 0; i < defStyleList.getLength(); i++) {
				OdfDefaultStyle defStyle = (OdfDefaultStyle) defStyleList.item(i);
				defaultStyles.put(defStyle.getFamilyName(), defStyle);
			}

			NodeList styleList = mTextDocument.getDocumentStyles().getElementsByTagName("style:style");
			for (int i = 0; i < styleList.getLength(); i++) {
				OdfStyle sStyle = (OdfStyle) styleList.item(i);
				//get default properties and style properties
				Map<OdfStyleProperty, String> map = sStyle.getStylePropertiesDeep();
				//check if properties include all search properties and value equal
				Iterator<OdfStyleProperty> pIter = mProps.keySet().iterator();
				boolean isStyle = false;
				while (pIter.hasNext()) {
					isStyle = false;
					OdfStyleProperty p = pIter.next();
					if (map.containsKey(p)) {
						if (map.get(p).equals(mProps.get(p))) {
							isStyle = true;
						} else {
							break;
						}
					} else {
						break;
					}
				}
				//put all match style names
				if (isStyle) {
					sname = sStyle.getStyleNameAttribute();
					//if(sname.contains("default"))sname="defaultstyle";
					styleNames.add(sname);
				}
			}
			//get all automatic styles
			Iterator<OdfStyle> cStyles = mTextDocument.getContentDom().getAutomaticStyles().getAllStyles().iterator();
			while (cStyles.hasNext()) {
				OdfStyle cStyle = cStyles.next();
				//get default properties and style properties
				Map<OdfStyleProperty, String> map = cStyle.getStylePropertiesDeep();

				if (cStyle.getParentStyle() == null) {
					if (cStyle.getFamilyName().equals("text")) {
						if (defaultStyles.containsKey("text")) {
							getTextDefaultProperties("text", defaultStyles, map);
						} else {
							getTextDefaultProperties("paragraph", defaultStyles, map);
						}
					}
				}

				//check if the search properties is in properties
				Iterator<OdfStyleProperty> pIter = mProps.keySet().iterator();
				boolean isStyle = false;
				while (pIter.hasNext()) {
					isStyle = false;
					OdfStyleProperty p = pIter.next();
					if (map.containsKey(p)) {
						if (map.get(p).equals(mProps.get(p))) {
							isStyle = true;
						} else {
							break;
						}
					} else {
						break;
					}
				}
				//put all match style names
				if (isStyle) {
					styleNames.add(cStyle.getStyleNameAttribute());
				}
			}

		} catch (Exception e1) {
			Logger.getLogger(TextStyleNavigation.class.getName()).log(Level.SEVERE, null, e1);
			e1.printStackTrace();
		}
		return styleNames;
	}

	private void getTextDefaultProperties(
			String familyName,
			HashMap<String, OdfDefaultStyle> defaultStyles,
			Map<OdfStyleProperty, String> map) {
		OdfDefaultStyle defStyle = defaultStyles.get(familyName);
		if (defStyle != null) {
			OdfStyleFamily family = defStyle.getFamily();
			if (family != null) {
				for (OdfStyleProperty property : family.getProperties()) {
					if (!map.containsKey(property) && defStyle.hasProperty(property)) {
						map.put(property, defStyle.getProperty(property));
					}
				}
			}
		}

	}
}
