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

import java.net.URL;
import java.util.Map;
import java.util.TreeMap;

import org.odftoolkit.odfdom.OdfElement;
import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.OdfNamespace;
import org.odftoolkit.odfdom.doc.style.OdfStyle;
import org.odftoolkit.odfdom.doc.text.OdfTextHeading;
import org.odftoolkit.odfdom.doc.text.OdfTextHyperlink;
import org.odftoolkit.odfdom.doc.text.OdfTextParagraph;
import org.odftoolkit.odfdom.doc.text.OdfTextSpace;
import org.odftoolkit.odfdom.doc.text.OdfTextSpan;
import org.odftoolkit.odfdom.doc.text.OdfWhitespaceProcessor;
import org.odftoolkit.odfdom.dom.OdfNamespaceNames;
import org.odftoolkit.odfdom.dom.element.OdfStylableElement;
import org.odftoolkit.odfdom.dom.element.OdfStyleBase;
import org.odftoolkit.odfdom.dom.style.OdfStyleFamily;
import org.odftoolkit.odfdom.dom.style.props.OdfStylePropertiesSet;
import org.odftoolkit.odfdom.dom.style.props.OdfStyleProperty;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * A TextSelection can describe a sub element in a mParagraph element or a mHeading element.
 * it is recognized by the container element(which type should be OdfTextParagraph or
 *  OdfTextHeadingt), the start index of the text content of the container element and 
 *  the text content of this selection.
 * 
 */
public class TextSelection extends Selection {

	private String mMatchedText;
	private OdfTextParagraph mParagraph;
	private OdfTextHeading mHeading;
	private int mIndexInContainer;
	private boolean mIsInserted;

	/**
	 * Constructor of TextSelection
	 * @param text				the text content of this TextSelection
	 * @param containerElement	the mParagraph element or mHeading element that contain this TextSelection
	 * @param index				the start index of the text content of the container element
	 * 
	 */
	TextSelection(String text, OdfElement containerElement, int index) {
		mMatchedText = text;
		if (containerElement instanceof OdfTextParagraph) {
			mParagraph = (OdfTextParagraph) containerElement;
		} else if (containerElement instanceof OdfTextHeading) {
			mHeading = (OdfTextHeading) containerElement;
		}
		mIndexInContainer = index;
	}

	/**
	 * Get the mParagraph element or mHeading element that contain this TextSelection
	 * @return OdfElement	the container element
	 */
	@Override
	public OdfElement getElement() {
		return getContainerElement();
	}

	/**
	 * Get the mParagraph element or mHeading element that contain this text
	 * @return OdfElement
	 */
	public OdfElement getContainerElement() {
		if (mParagraph != null) {
			return mParagraph;
		} else {
			return mHeading;
		}
	}

	/**
	 * Get the start index of the text content of its container element
	 * @return index	the start index of the text content of its container element
	 */
	@Override
	public int getIndex() {
		return mIndexInContainer;
	}

	/**
	 * Get the text content of this TextSelection 
	 * @return text	the text content
	 */
	public String getText() {
		return mMatchedText;
	}

	/*
	 * Validate if the selection is still available.
	 * @return true	if the selection is available; false if the selection is not available.
	 */
	private boolean validate() {
		if (getContainerElement() == null) {
			return false;
		}
		OdfElement container = getContainerElement();
		if (container == null) {
			return false;
		}
		OdfWhitespaceProcessor textProcessor = new OdfWhitespaceProcessor();
		String content = textProcessor.getText(container);
		if (content.indexOf(mMatchedText, mIndexInContainer) == mIndexInContainer) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Delete the selection from the document
	 * the other matched selection in the same container element will be updated automatically
	 * because the start index of the following selections will be changed when the previous 
	 * selection has been deleted 
	 * @throws InvalidNavigationException if the selection is unavailable.
	 */
	@Override
	public void cut() throws InvalidNavigationException {
		if (validate() == false) {
			throw new InvalidNavigationException("No matched string at this position");
		}
		OdfElement container = getContainerElement();
		delete(mIndexInContainer, mMatchedText.length(), container);
		SelectionManager.refreshAfterCut(this);
		mMatchedText = "";
	}

	/**
	 * Apply a style to the selection so that the text style of this selection 
	 * will append the specified style
	 * @param style	the style can be from the current document or user defined
	 * @throws InvalidNavigationException if the selection is unavailable.
	 */
	public void applyStyle(OdfStyleBase style) throws InvalidNavigationException {
		//append the specified style to the selection
		if (validate() == false) {
			throw new InvalidNavigationException("No matched string at this position");
		}
		OdfElement parentElement = getContainerElement();

		int leftLength = getText().length();
		int index = mIndexInContainer;

		appendStyle(index, leftLength, parentElement, style);

	}

	/*
	 * append specified style for a range text of pNode
	 * from 'fromindex' and cover 'leftLength'
	 */
	private void appendStyle(int fromindex, int leftLength, Node pNode, OdfStyleBase style) {
		if ((fromindex == 0) && (leftLength == 0)) {
			return;
		}
		int nodeLength = 0;
		Node node = pNode.getFirstChild();
		OdfWhitespaceProcessor textProcessor = new OdfWhitespaceProcessor();

		while (node != null) {
			if ((fromindex == 0) && (leftLength == 0)) {
				return;
			}
			if (node.getNodeType() == Node.TEXT_NODE) {
				nodeLength = node.getNodeValue().length();
			} else if (node.getNodeType() == Node.ELEMENT_NODE) {
				if (node.getLocalName().equals("s")) // text:s
				{
					try {
						nodeLength = Integer.parseInt(((Element) node).getAttributeNS(OdfNamespaceNames.TEXT.getNamespaceUri(), "c"));
					} catch (Exception e) {
						nodeLength = 1;
					}

				} else if (node.getLocalName().equals("line-break")) {
					nodeLength = 1;
				} else if (node.getLocalName().equals("tab")) {
					nodeLength = 1;
				} else {
					nodeLength = textProcessor.getText((OdfElement) node).length();
				}

			}
			if (nodeLength <= fromindex) {
				fromindex -= nodeLength;
			} else {
				// the start index is in this node
				if (node.getNodeType() == Node.TEXT_NODE) {
					String value = node.getNodeValue();
					node.setNodeValue(value.substring(0, fromindex));
					int endLength = fromindex + leftLength;
					int nextLength = value.length() - endLength;

					Node nextNode = node.getNextSibling();
					Node parNode = node.getParentNode();
					// init text:a
					OdfTextSpan textSpan = new OdfTextSpan(
							(OdfFileDom) node.getOwnerDocument());
					Node newNode = null;
					if (nextLength >= 0) {
						textSpan.setTextContent(value.substring(fromindex,
								endLength));
						newNode = node.cloneNode(true);
						newNode.setNodeValue(value.substring(endLength, value.length()));
						leftLength = 0;
					} else {
						textSpan.setTextContent(value.substring(fromindex,
								value.length()));
						leftLength = endLength - value.length();
					}
					textSpan.setProperties(style.getStyleProperties());

					if (nextNode != null) {
						parNode.insertBefore(textSpan, nextNode);
						if (newNode != null) {
							parNode.insertBefore(newNode, nextNode);
						}
					} else {
						parNode.appendChild(textSpan);
						if (newNode != null) {
							parNode.appendChild(newNode);
						}
					}
					fromindex = 0;
					if (nextNode != null) {
						node = nextNode;
					} else {
						node = textSpan;
					}

				} else if (node.getNodeType() == Node.ELEMENT_NODE) {
					// if text:s?????????
					if (node.getLocalName().equals("s")) // text:s
					{
						// delete space
						((OdfTextSpace) node).setTextCAttribute(new Integer(
								nodeLength - fromindex));
						leftLength = leftLength - (nodeLength - fromindex);
						fromindex = 0;

					} else if (node.getLocalName().equals("line-break") || node.getLocalName().equals("tab")) {
						fromindex = 0;
						leftLength--;
					} else {
						appendStyle(fromindex, leftLength, node, style);
						int length = (fromindex + leftLength) - nodeLength;
						leftLength = length > 0 ? length : 0;
						fromindex = 0;
					}

				}

			}
			node = node.getNextSibling();
		}
	}

	/**
	 * Replace the text content of selection with a new string
	 * 
	 * @param newText	the replace text String
	 * @throws InvalidNavigationException if the selection is unavailable.
	 */
	public void replaceWith(String newText) throws InvalidNavigationException {
		if (validate() == false) {
			throw new InvalidNavigationException("No matched string at this position");
		}

		OdfElement parentElement = getContainerElement();

		int leftLength = getText().length();
		int index = mIndexInContainer;
		delete(index, leftLength, parentElement);
		OdfTextSpan textSpan = new OdfTextSpan((OdfFileDom) parentElement.getOwnerDocument());
		textSpan.addContentWhitespace(newText);
		/*if (startElement instanceof OdfStyleBase)
		textSpan.setProperties(((OdfStyleBase) startElement)
		.getStyleProperties());*/
		mIsInserted = false;
		insertSpan(textSpan, index, parentElement);
		// optimize the parent element
		optimize(parentElement);
		int offset = newText.length() - leftLength;
		SelectionManager.refresh(this.getContainerElement(), offset, index + getText().length());
		mMatchedText = newText;
	}

	/**
	 * Paste this selection just before a specific selection.
	 * @param positionItem	a selection that is used to point out the position
	 * @throws InvalidNavigationException if the selection is unavailable.
	 */
	@Override
	public void pasteAtFrontOf(Selection positionItem) throws InvalidNavigationException {
		if (validate() == false) {
			throw new InvalidNavigationException("No matched string at this position");
		}
		int indexOfNew = 0;
		OdfElement newElement = positionItem.getElement();
		if (positionItem instanceof TextSelection) {
			indexOfNew = ((TextSelection) positionItem).getIndex();
			newElement = ((TextSelection) positionItem).getContainerElement();
		}

		OdfTextSpan textSpan = getSpan((OdfFileDom) positionItem.getElement().getOwnerDocument());
		mIsInserted = false;
		insertSpan(textSpan, indexOfNew, newElement);
		adjustStyle(newElement, textSpan, null);
		SelectionManager.refreshAfterPasteAtFrontOf(this, positionItem);
	}

	/**
	 * Paste this selection just after a specific selection.
	 * @param positionItem	a selection that is used to point out the position
	 * @throws InvalidNavigationException if the selection is unavailable.
	 */
	@Override
	public void pasteAtEndOf(Selection positionItem) throws InvalidNavigationException {
		if (validate() == false) {
			throw new InvalidNavigationException("No matched string at this position");
		}
		int indexOfNew = 0;//TODO: think about and test if searchitem is a element selection
		OdfElement newElement = positionItem.getElement();
		if (positionItem instanceof TextSelection) {
			indexOfNew = ((TextSelection) positionItem).getIndex() + ((TextSelection) positionItem).getText().length();
			newElement = ((TextSelection) positionItem).getContainerElement();
		}

		OdfTextSpan textSpan = getSpan((OdfFileDom) positionItem.getElement().getOwnerDocument());

		mIsInserted = false;
		insertSpan(textSpan, indexOfNew, newElement);
		adjustStyle(newElement, textSpan, null);
		SelectionManager.refreshAfterPasteAtEndOf(this, positionItem);
	}

	/**
	 * Add a hypertext reference to the selection
	 * 
	 * @param url	the url of the hypertext reference
	 * @throws InvalidNavigationException if the selection is unavailable.
	 */
	public void addHref(URL url) throws InvalidNavigationException {
		if (validate() == false) {
			throw new InvalidNavigationException("No matched string at this position");
		}
		OdfElement parentElement = getContainerElement();

		int leftLength = getText().length();
		int index = mIndexInContainer;

		addHref(index, leftLength, parentElement, url.toString());
	}

	/*
	 * add href for a range text of pNode from the 'fromindex' text, and the href will cover
	 * 'leftLength' text
	 * 
	 */
	private void addHref(int fromindex, int leftLength, Node pNode, String href) {
		if ((fromindex == 0) && (leftLength == 0)) {
			return;
		}
		int nodeLength = 0;
		Node node = pNode.getFirstChild();
		OdfWhitespaceProcessor textProcessor = new OdfWhitespaceProcessor();

		while (node != null) {
			if ((fromindex == 0) && (leftLength == 0)) {
				return;
			}
			if (node.getNodeType() == Node.TEXT_NODE) {
				nodeLength = node.getNodeValue().length();
			} else if (node.getNodeType() == Node.ELEMENT_NODE) {
				if (node.getLocalName().equals("s")) // text:s
				{
					try {
						nodeLength = Integer.parseInt(((Element) node).getAttributeNS(OdfNamespaceNames.TEXT.getNamespaceUri(), "c"));
					} catch (Exception e) {
						nodeLength = 1;
					}

				} else if (node.getLocalName().equals("line-break")) {
					nodeLength = 1;
				} else if (node.getLocalName().equals("tab")) {
					nodeLength = 1;
				} else {
					nodeLength = textProcessor.getText((OdfElement) node).length();
				}

			}
			if (nodeLength <= fromindex) {
				fromindex -= nodeLength;
			} else {
				// the start index is in this node
				if (node.getNodeType() == Node.TEXT_NODE) {
					String value = node.getNodeValue();
					node.setNodeValue(value.substring(0, fromindex));
					int endLength = fromindex + leftLength;
					int nextLength = value.length() - endLength;

					Node nextNode = node.getNextSibling();
					Node parNode = node.getParentNode();
					// init text:a
					OdfTextHyperlink textLink = new OdfTextHyperlink(
							(OdfFileDom) node.getOwnerDocument());
					Node newNode = null;
					if (nextLength >= 0) {
						textLink.setTextContent(value.substring(fromindex,
								endLength));
						newNode = node.cloneNode(true);
						newNode.setNodeValue(value.substring(endLength, value.length()));
						leftLength = 0;
					} else {
						textLink.setTextContent(value.substring(fromindex,
								value.length()));
						leftLength = endLength - value.length();
					}
					textLink.setXlinkTypeAttribute("simple");
					textLink.setXlinkHrefAttribute(href);

					if (nextNode != null) {
						parNode.insertBefore(textLink, nextNode);
						if (newNode != null) {
							parNode.insertBefore(newNode, nextNode);
						}
					} else {
						parNode.appendChild(textLink);
						if (newNode != null) {
							parNode.appendChild(newNode);
						}
					}
					fromindex = 0;
					if (nextNode != null) {
						node = nextNode;
					} else {
						node = textLink;
					}

				} else if (node.getNodeType() == Node.ELEMENT_NODE) {
					// if text:s?????????
					if (node.getLocalName().equals("s")) // text:s
					{
						// delete space
						((OdfTextSpace) node).setTextCAttribute(new Integer(
								nodeLength - fromindex));
						leftLength = leftLength - (nodeLength - fromindex);
						fromindex = 0;

					} else if (node.getLocalName().equals("line-break") || node.getLocalName().equals("tab")) {
						fromindex = 0;
						leftLength--;
					} else {
						addHref(fromindex, leftLength, node, href);
						int length = (fromindex + leftLength) - nodeLength;
						leftLength = length > 0 ? length : 0;
						fromindex = 0;
					}

				}

			}
			node = node.getNextSibling();
		}
	}
	/*
	 * delete the pNode from the fromindex text, and delete leftLength text
	 */

	private void delete(int fromindex, int leftLength, Node pNode) {
		if ((fromindex == 0) && (leftLength == 0)) {
			return;
		}
		int nodeLength = 0;
		Node node = pNode.getFirstChild();
		OdfWhitespaceProcessor textProcessor = new OdfWhitespaceProcessor();

		while (node != null) {
			if ((fromindex == 0) && (leftLength == 0)) {
				return;
			}
			if (node.getNodeType() == Node.TEXT_NODE) {
				nodeLength = node.getNodeValue().length();
			} else if (node.getNodeType() == Node.ELEMENT_NODE) {
				if (node.getLocalName().equals("s")) // text:s
				{
					try {
						nodeLength = Integer.parseInt(((Element) node).getAttributeNS(OdfNamespaceNames.TEXT.getNamespaceUri(), "c"));
					} catch (Exception e) {
						nodeLength = 1;
					}

				} else if (node.getLocalName().equals("line-break")) {
					nodeLength = 1;
				} else if (node.getLocalName().equals("tab")) {
					nodeLength = 1;
				} else {
					nodeLength = textProcessor.getText((OdfElement) node).length();
				}

			}
			if (nodeLength <= fromindex) {
				fromindex -= nodeLength;
			} else {
				// the start index is in this node
				if (node.getNodeType() == Node.TEXT_NODE) {
					String value = node.getNodeValue();
					StringBuffer buffer = new StringBuffer();
					buffer.append(value.substring(0, fromindex));
					int endLength = fromindex + leftLength;
					int nextLength = value.length() - endLength;
					fromindex = 0;
					if (nextLength >= 0) {
						// delete the result
						buffer.append(value.substring(endLength, value.length()));
						leftLength = 0;
					} else {
						leftLength = endLength - value.length();
					}
					node.setNodeValue(buffer.toString());

				} else if (node.getNodeType() == Node.ELEMENT_NODE) {
					// if text:s?????????
					if (node.getLocalName().equals("s")) // text:s
					{
						// delete space
						((OdfTextSpace) node).setTextCAttribute(new Integer(
								nodeLength - fromindex));
						leftLength = leftLength - (nodeLength - fromindex);
						fromindex = 0;

					} else if (node.getLocalName().equals("line-break") || node.getLocalName().equals("tab")) {
						fromindex = 0;
						leftLength--;
					} else {
						delete(fromindex, leftLength, node);
						int length = (fromindex + leftLength) - nodeLength;
						leftLength = length > 0 ? length : 0;
						fromindex = 0;
					}

				}

			}
			node = node.getNextSibling();
		}
	}

	@Override
	protected void refreshAfterFrontalDelete(Selection deleteItem) {
		if (deleteItem instanceof TextSelection) {
			mIndexInContainer -= ((TextSelection) deleteItem).getText().length();
		}
	}

	@Override
	protected void refreshAfterFrontalInsert(Selection pasteItem) {
		if (pasteItem instanceof TextSelection) {
			mIndexInContainer += ((TextSelection) pasteItem).getText().length();
		}
	}

	@Override
	protected void refresh(int offset) {
		mIndexInContainer += offset;
	}

	/**
	 * return a String Object representing this selection value
	 * the text content of the selection, start index in the container element and the
	 * text content of the container element will be provided
	 * @return a String representation of the value of this TextSelection
	 */
	@Override
	public String toString() {
		OdfWhitespaceProcessor textProcessor = new OdfWhitespaceProcessor();

		return "[" + mMatchedText + "] started from " + mIndexInContainer + " in paragraph:" + textProcessor.getText(getContainerElement());
	}

	// return a new span that cover this selection
	// and keep the original style of this selection
	private OdfTextSpan getSpan(OdfFileDom ownerDoc) {
		OdfElement parentElement = getContainerElement();

		if (parentElement != null) {
			Node copyParentNode = parentElement.cloneNode(true);
			if (ownerDoc != parentElement.getOwnerDocument()) {
				copyParentNode = ownerDoc.adoptNode(copyParentNode);
			}
			OdfTextSpan textSpan = new OdfTextSpan(ownerDoc);
			int sIndex = mIndexInContainer;
			int eIndex = sIndex + mMatchedText.length();
			// delete the content except the selection string
			// delete from the end to start, so that the postion will not be
			// impact by delete action
			OdfWhitespaceProcessor textProcessor = new OdfWhitespaceProcessor();
			delete(eIndex, textProcessor.getText(copyParentNode).length() - eIndex, copyParentNode);
			delete(0, sIndex, copyParentNode);
			optimize(copyParentNode);
			Node childNode = copyParentNode.getFirstChild();
			while (childNode != null) {
				textSpan.appendChild(childNode.cloneNode(true));
				childNode = childNode.getNextSibling();
			}
			// apply text style for the textSpan
			if (copyParentNode instanceof OdfStylableElement) {
				applyTextStyleProperties(getTextStylePropertiesDeep((OdfStylableElement) copyParentNode),
						textSpan);
			}
			return textSpan;
		}
		return null;
	}

	/*
	 * optimize the text element by deleting the empty text node
	 * 
	 * @param element
	 */
	private void optimize(Node pNode) {
		// check if the text:a can be optimized
		OdfWhitespaceProcessor textProcess = new OdfWhitespaceProcessor();
		Node node = pNode.getFirstChild();
		while (node != null) {
			Node nextNode = node.getNextSibling();
			//if ((node.getNodeType() == Node.ELEMENT_NODE) && (node.getPrefix().equals("text"))) {
			if (node instanceof OdfTextSpan) {
				if (textProcess.getText(node).length() == 0) {
					node.getParentNode().removeChild(node);
				} else {
					optimize(node);
				}
			}
			node = nextNode;
		}
	}
	
	/*
	 * apply the styleMap to the toElement
	 * reserve the style property of toElement if it is also exist in styleMap
	 */

	private void applyTextStyleProperties(Map<OdfStyleProperty, String> styleMap,
			OdfStylableElement toElement) {
		if (styleMap != null) {
			//preserve the style property of toElement if it is also exist in styleMap
			OdfStyle resultStyleElement = toElement.getAutomaticStyles().newStyle(
					OdfStyleFamily.Text);

			for (Map.Entry<OdfStyleProperty, String> entry : styleMap.entrySet()) {
				if (toElement.hasProperty(entry.getKey())) {
					resultStyleElement.setProperty(entry.getKey(), toElement.getProperty(entry.getKey()));
				} else {
					resultStyleElement.setProperty(entry.getKey(), entry.getValue());
				}
			}
			toElement.setStyleName(resultStyleElement.getStyleNameAttribute());
		}
	}

	/*
	 * insert textSpan into the from index of pNode
	 */
	private void insertSpan(OdfTextSpan textSpan, int fromindex, Node pNode) {
		if (fromindex < 0) {
			fromindex = 0;
		}
		if (fromindex == 0 && mIsInserted) {
			return;
		}
		OdfWhitespaceProcessor textProcessor = new OdfWhitespaceProcessor();
		int nodeLength = 0;
		Node node = pNode.getFirstChild();
		while (node != null) {
			if (fromindex <= 0 && mIsInserted) {
				return;
			}
			if (node.getNodeType() == Node.TEXT_NODE) {
				nodeLength = node.getNodeValue().length();
				if ((fromindex != 0) && (nodeLength < fromindex)) {
					fromindex -= nodeLength;
				} else {
					// insert result after node, and insert an new text node
					// after
					// the result node
					String value = node.getNodeValue();
					StringBuffer buffer = new StringBuffer();
					buffer.append(value.substring(0, fromindex));
					// insert the text span in appropriate position
					node.setNodeValue(buffer.toString());
					Node nextNode = node.getNextSibling();
					Node parNode = node.getParentNode();

					Node newNode = node.cloneNode(true);
					newNode.setNodeValue(value.substring(fromindex, value.length()));
					if (nextNode != null) {
						parNode.insertBefore(textSpan, nextNode);
						parNode.insertBefore(newNode, nextNode);
					} else {
						parNode.appendChild(textSpan);
						parNode.appendChild(newNode);
					}
					mIsInserted = true;
					return;
				}
			} else if (node.getNodeType() == Node.ELEMENT_NODE) {
				if (node.getLocalName().equals("s")) // text:s
				{
					try {
						nodeLength = Integer.parseInt(((Element) node).getAttributeNS(OdfNamespaceNames.TEXT.getNamespaceUri(), "c"));
					} catch (Exception e) {
						nodeLength = 1;
					}
					fromindex -= nodeLength;

				} else if (node.getLocalName().equals("line-break")) {
					nodeLength = 1;
					fromindex--;
				} else if (node.getLocalName().equals("tab")) {
					nodeLength = 1;
					fromindex--;
				} else {
					nodeLength = textProcessor.getText(node).length();
					insertSpan(textSpan, fromindex, node);
					fromindex -= nodeLength;
				}

			}
			node = node.getNextSibling();
		}
	}

	/*
	 * the textSpan must be the child element of parentNode
	 * this method is used to keep the style of text span when it has been insert into the parentNode
	 * if we don't deal with the style, the inserted span will also have the style of parentNode
	 * 
	 */
	private void adjustStyle(Node parentNode, OdfTextSpan textSpan, Map<OdfStyleProperty, String> styleMap) {
		if (parentNode instanceof OdfStylableElement) {
			OdfStylableElement pStyleNode = (OdfStylableElement) parentNode;
			if (styleMap == null) {
				styleMap = getTextStylePropertiesDeep(pStyleNode);
			}
			Node node = parentNode.getFirstChild();
			while (node != null) {
				if (node.getNodeType() == Node.TEXT_NODE) {
					if (node.getTextContent().length() > 0) {
						Node nextNode = node.getNextSibling();
						OdfTextSpan span = new OdfTextSpan((OdfFileDom) node.getOwnerDocument());
						span.appendChild(node);
						if (nextNode != null) {
							parentNode.insertBefore(span, nextNode);
						} else {
							parentNode.appendChild(span);
						}
						node = span;
						applyTextStyleProperties(styleMap, (OdfStylableElement) node);
					}
				} else if ((node instanceof OdfStylableElement)) {
					if (!node.equals(textSpan)) {
						Map<OdfStyleProperty, String> styles = getTextStylePropertiesDeep(pStyleNode);
						Map<OdfStyleProperty, String> styles1 = getTextStylePropertiesDeep((OdfStylableElement) node);
						if (styles == null) {
							styles = styles1;
						} else if (styles1 != null) {
							styles.putAll(styles1);
						}
						int comp = node.compareDocumentPosition(textSpan);
						//if node contains textSpan, then recurse the node
						if ((comp & Node.DOCUMENT_POSITION_CONTAINED_BY) > 0) {
							adjustStyle(node, textSpan, styles);
						} else {
							applyTextStyleProperties(styles, (OdfStylableElement) node);
						}
					}

				}
				node = node.getNextSibling();
			}
			//change the parentNode to default style
			//here we don't know the default style name, so here just
			//remove the text:style-name attribute
			pStyleNode.removeAttributeNS(OdfNamespace.get(OdfNamespaceNames.TEXT).toString(), "style-name");
		}
	}

	/*
	 * get a map containing text properties of the specified styleable element.
	 * @return  a map of text properties.
	 */
	private Map<OdfStyleProperty, String> getTextStyleProperties(OdfStylableElement element) {
		String styleName = element.getStyleName();
		OdfStyleBase styleElement = element.getAutomaticStyles().getStyle(
				styleName, element.getStyleFamily());

		if (styleElement == null) {
			styleElement = element.getDocumentStyle();
		}
		if (styleElement != null) {
			//check if it is the style:defaut-style
			if ((styleElement.getPropertiesElement(OdfStylePropertiesSet.ParagraphProperties) == null) &&
					(styleElement.getPropertiesElement(OdfStylePropertiesSet.TextProperties) == null)) {
				styleElement = ((OdfFileDom) styleElement.getOwnerDocument()).getOdfDocument().getDocumentStyles().getDefaultStyle(styleElement.getFamily());
			}
			TreeMap<OdfStyleProperty, String> result = new TreeMap<OdfStyleProperty, String>();
			OdfStyleFamily family = OdfStyleFamily.Text;
			if (family != null) {
				for (OdfStyleProperty property : family.getProperties()) {
					if (styleElement.hasProperty(property)) {
						result.put(property, styleElement.getProperty(property));
					}
				}
			}
			return result;
		}
		return null;
	}

	/*
	 * get a map containing text properties of the specified styleable element.
	 * The map will also include any properties set by parent styles
	 * @return  a map of text properties.
	 *
	 */
	private Map<OdfStyleProperty, String> getTextStylePropertiesDeep(OdfStylableElement element) {
		String styleName = element.getStyleName();
		OdfStyleBase styleElement = element.getAutomaticStyles().getStyle(
				styleName, element.getStyleFamily());

		if (styleElement == null) {
			styleElement = element.getDocumentStyle();
		}
		TreeMap<OdfStyleProperty, String> result = new TreeMap<OdfStyleProperty, String>();
		while (styleElement != null) {
			//check if it is the style:defaut-style
			if ((styleElement.getPropertiesElement(OdfStylePropertiesSet.ParagraphProperties) == null) &&
					(styleElement.getPropertiesElement(OdfStylePropertiesSet.TextProperties) == null)) {
				styleElement = ((OdfFileDom) styleElement.getOwnerDocument()).getOdfDocument().getDocumentStyles().getDefaultStyle(styleElement.getFamily());
			}
			OdfStyleFamily family = OdfStyleFamily.Text;
			if (family != null) {
				for (OdfStyleProperty property : family.getProperties()) {
					if (styleElement.hasProperty(property)) {
						result.put(property, styleElement.getProperty(property));
					}
				}
			}
			styleElement = styleElement.getParentStyle();

		}
		return result;
	}
}
