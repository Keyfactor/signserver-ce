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

import org.w3c.dom.Node;

/**
 * Abstract class Navigation used to navigate the document
 * and find the matched element by the user defined conditions
 *
 */
public abstract class Navigation {

	/**
	 * Return true if document still has more matched Selection
	 * when traversing the document(In other words return true
	 * if getNextMatchElement() would return an element instance
	 * rather than return null)
	 * @return true if document still has more matched Selection,
	 * and vice versa
	 *
	 */
	abstract public boolean hasNext();
	//abstract public void gotoPrevious();

	/**
	 * get the current Selection result
	 * @return the current Selection result
	 */
	abstract public Selection getCurrentItem();

	/**
	 * check if the element match the user defined condition
	 * @param element	navigate this element
	 * @return true if the element match the user defined condition;
	 * 		   false if not match
	 *
	 */
	abstract public boolean match(Node element);

	/**
	 * get the next matched element in a whole dom tree
	 * @param startpoint	navigate from the startpoint
	 * @return	the next matched element
	 */
	protected Node getNextMatchElement(Node startpoint) {
		Node matchedNode = null;
		matchedNode = traverseTree(startpoint);

		Node currentpoint = startpoint;
		while ((matchedNode == null) && (currentpoint != null)) {
			Node sibling = currentpoint.getNextSibling();
			if ((sibling != null) &&
					(sibling.getNodeType() == Node.TEXT_NODE || sibling.getNodeType() == Node.ELEMENT_NODE) && (match(sibling))) {
				matchedNode = sibling;
			}
			while ((sibling != null) && (matchedNode == null)) {
				if ((sibling.getNodeType() == Node.TEXT_NODE || sibling.getNodeType() == Node.ELEMENT_NODE)) {
					matchedNode = traverseTree(sibling);
				}
				sibling = sibling.getNextSibling();
				if (sibling != null && match(sibling)) {
					matchedNode = sibling;
				}
			}
			currentpoint = currentpoint.getParentNode();
		}

		return matchedNode;
	}

	/**
	 * get the next matched element in a sub tree
	 * @param startpoint	navigate from the startpoint
	 * @param root			the root of the sub tree
	 * @return	the next matched element
	 */
	protected Node getNextMatchElementInTree(Node startpoint, Node root) {
		Node matchedNode = null;
		matchedNode = traverseTree(startpoint);

		Node currentpoint = startpoint;
		while ((matchedNode == null) && (currentpoint != root)) {
			Node sibling = currentpoint.getNextSibling();
			if ((sibling != null) &&
					(sibling.getNodeType() == Node.TEXT_NODE || sibling.getNodeType() == Node.ELEMENT_NODE) && (match(sibling))) {
				matchedNode = sibling;
			}
			while ((sibling != null) && (matchedNode == null)) {
				if ((sibling.getNodeType() == Node.TEXT_NODE || sibling.getNodeType() == Node.ELEMENT_NODE)) {
					matchedNode = traverseTree(sibling);
				}
				sibling = sibling.getNextSibling();
				if (sibling != null && match(sibling)) {
					matchedNode = sibling;
				}
			}
			currentpoint = currentpoint.getParentNode();
		}

		return matchedNode;
	}

	private Node traverseTree(Node root) {
		Node matchedNode = null;
		if (root == null) {
			return null;
		}
		//if (match(root)) return root;

		Node node = root.getFirstChild();
		while (node != null) {
			if ((node.getNodeType() == Node.TEXT_NODE || node.getNodeType() == Node.ELEMENT_NODE)) {
				if (match(node) == true) {
					matchedNode = node;
					break;
				} else {
					matchedNode = traverseTree(node);
					if (matchedNode != null) {
						break;
					}
				}
			}
			node = node.getNextSibling();
		}
		return matchedNode;
	}
}
