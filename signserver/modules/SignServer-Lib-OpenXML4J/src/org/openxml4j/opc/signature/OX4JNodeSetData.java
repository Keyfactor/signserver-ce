/* ====================================================================
   Licensed to the Apache Software Foundation (ASF) under one or more
   contributor license agreements.  See the NOTICE file distributed with
   this work for additional information regarding copyright ownership.
   The ASF licenses this file to You under the Apache License, Version 2.0
   (the "License"); you may not use this file except in compliance with
   the License.  You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
==================================================================== 

 * Copyright (c) 2006, Wygwam
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met: 
 * 
 * - Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation and/or 
 * other materials provided with the distribution.
 * - Neither the name of Wygwam nor the names of its contributors may be 
 * used to endorse or promote products derived from this software without 
 * specific prior written permission. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT 
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.openxml4j.opc.signature;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.xml.crypto.NodeSetData;

import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

/**
 * Implementation of NodeSetData class
 * 
 * @author aziz.goktepe (aka rayback_2)
 * 
 * patch originally created for SignServer project {@link http://www.signserver.org}
 * 
 */
public class OX4JNodeSetData implements NodeSetData {

	final HashSet nodeSet = new HashSet();
	private Node rootNode;

	public Node getRootNode() {
		return rootNode;
	}

	public OX4JNodeSetData(Node pRootNode) {
		rootNode = pRootNode;
		toNodeSet(rootNode, nodeSet);
	}

	@Override
	public Iterator iterator() {
		return nodeSet.iterator();
	}

    @SuppressWarnings("unchecked") // XXX: Uses unchecked calls
	private void toNodeSet(final Node rootNode, final Set result) {
		// handle EKSHA1 under DKT
		if (rootNode == null)
			return;
		switch (rootNode.getNodeType()) {
		case Node.ELEMENT_NODE:
			result.add(rootNode);
			Element el = (Element) rootNode;
			if (el.hasAttributes()) {
				NamedNodeMap nl = ((Element) rootNode).getAttributes();
				for (int i = 0; i < nl.getLength(); i++) {
					result.add(nl.item(i));
				}
			}
			// no return keep working
		case Node.DOCUMENT_NODE:
			for (Node r = rootNode.getFirstChild(); r != null; r = r
					.getNextSibling()) {
				if (r.getNodeType() == Node.TEXT_NODE) {
					result.add(r);
					while ((r != null) && (r.getNodeType() == Node.TEXT_NODE)) {
						r = r.getNextSibling();
					}
					if (r == null)
						return;
				}
				toNodeSet(r, result);
			}
			return;
		case Node.COMMENT_NODE:
			return;
		case Node.DOCUMENT_TYPE_NODE:
			return;
		default:
			result.add(rootNode);
		}
		return;
	}
}
