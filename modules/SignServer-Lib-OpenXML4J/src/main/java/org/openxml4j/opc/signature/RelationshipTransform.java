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

import java.util.HashMap;
import java.util.List;
import java.util.Vector;

import org.dom4j.Document;
import org.dom4j.DocumentFactory;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.Namespace;
import org.dom4j.Node;
import org.dom4j.QName;
import org.dom4j.XPath;
import org.openxml4j.opc.PackageNamespaces;
import org.openxml4j.opc.PackageRelationship;

/**
 * Helper class for doing relationship transform as specified by ECMA 376
 * 
 * @author aziz.goktepe (aka rayback_2)
 * 
 *         patch originally created for SignServer project {@link http
 *         ://www.signserver.org}
 * 
 */
public class RelationshipTransform {

	public static Document DoRelationshipTransform(Document docIn,
			List<String> pRelationshipIds, List<String> pRelationshipTypes)
			throws Exception {

		// defensively copy document
		Document doc = (Document) docIn.clone();

		// THE RELATIONSHIPS TRANSFORM ALGORITHM STEPS AS DEFINED IN ECMA-376
		// SECOND EDITION PART 2

		// STEP 1: PROCESSING VERSIONING INSTRUCTIONS

		// 1. The package implementer shall process the versioning instructions,
		// considering that the only known
		// namespace is the Relationships namespace.
		// TODO : SKIPPED

		// 2. The package implementer shall remove all ignorable content,
		// ignoring preservation attributes.
		// TODO : SKIPPED

		// 3. The package implementer shall remove all versioning instructions.
		// TODO : needs testing
		// TODO : removing all processing instructions instead of only
		// versioning ?!
		RemoveProcessingInstructions(doc);

		// STEP 2: SORT AND FILTER RELATIONSHIPS

		// 1. The package implementer shall remove all namespace declarations
		// except the Relationships namespace declaration.
		// 2. The package implementer shall remove the Relationships namespace
		// prefix, if it is present.
		// TODO : needs testing

		RemoveAllNameSpacesExceptRelationship(doc);

		// 3. The package implementer shall sort relationship elements by Id
		// value in lexicographical order,
		// considering Id values as case-sensitive Unicode strings.
		SortRelationshipElementsById(doc);

		// 4. The package implementer shall remove all Relationship elements
		// that do not have either an Id value
		// that matches any SourceId value or a Type value that matches any
		// SourceType value, among the
		// SourceId and SourceType values specified in the transform definition.
		// Producers and consumers shall
		// compare values as case-sensitive Unicode strings. [M6.27] The
		// resulting XML document holds all
		// Relationship elements that either have an Id value that matches a
		// SourceId value or a Type value that
		// matches a SourceType value specified in the transform definition.
		// TODO : needs testing
		FilterRelationshipsByTypeAndId(doc, pRelationshipIds,
				pRelationshipTypes);

		// STEP 3: PREPARE FOR CANONICALIZATION

		// 1. The package implementer shall remove all characters between the
		// Relationships start tag and the first
		// Relationship start tag.
		// NOTE : OK because of Side effect 2 of SortRelationshipElementsById
		// method

		// 2. The package implementer shall remove any contents of the
		// Relationship element.
		RemoveContentsFromRelationshipElements(doc);

		// 3. The package implementer shall remove all characters between the
		// last Relationship end tag and the
		// Relationships end tag.
		// NOTE : OK because of Side effect 2 of SortRelationshipElementsById
		// method

		// 4. If there are no Relationship elements, the package implementer
		// shall remove all characters between
		// the Relationships start tag and the Relationships end tag.
		// NOTE : OK because of Side effect 2 of SortRelationshipElementsById
		// method

		// 5. The package implementer shall remove comments from the
		// Relationships XML content.
		// NOTE : all comments inside root element (relationships start and end
		// tags) are removed as Side effect 1 of SortRelationshipElementsById
		// and as a result of executing RemoveContentsFromRelationshipElements
		// method
		// So we can only concern about top level comments
		// TODO : needs testing
		RemoveAllTopLevelComments(doc);

		// 6. The package implementer shall add a TargetMode attribute with its
		// default value, if this optional
		// attribute is missing from the Relationship element.
		// NOTE : we are adding TargetMode = Internal to all missing
		// relationship elements
		AddTargetModeInternalAttributeIfMissing(doc);

		// 7. The package implementer can generate Relationship elements as
		// start-tag/end-tag pairs with empty
		// content, or as empty elements. A canonicalization transform, applied
		// immediately after the
		// Relationships Transform, converts all XML elements into
		// start-tag/end-tag pairs.

		// doc.asXML() would add versioning instruction to xml, whereas
		// doc.getRootElement().asXML() wont : see Step 1.3
		// return doc.getRootElement().asXML();

		return doc;
	}

	/*
	 * removing all processing instructions
	 */
	@SuppressWarnings("unchecked")
	private static void RemoveProcessingInstructions(Document doc) {
		List<String> processingInstructions = doc.processingInstructions();
		for (String s : processingInstructions) {
			System.out.println("removing processing instruction : " + s);
			doc.removeProcessingInstruction(s);
		}
	}

	/*
	 * remove all additional namespaces and prefix from every element in
	 * document
	 */
	private static void RemoveAllNameSpacesExceptRelationship(Document doc) {
		RemoveAllNameSpacesExceptRelationship(doc.getRootElement());
		for (Object e : doc.getRootElement().elements()) {
			RemoveAllNameSpacesExceptRelationship((Element) e);
		}
	}

	/*
	 * removes all namespace declarations from element except for Relationship
	 * namespace also ensures the relationship namespace does not have a prefix
	 */
	@SuppressWarnings("unchecked")
	public static void RemoveAllNameSpacesExceptRelationship(Element elem) {

		// if the default namespace is not correct or if it has a prefix
		// fix it by setting to correct value without prefix
		if (elem.getNamespace().getStringValue() != PackageNamespaces.RELATIONSHIPS
				|| elem.getNamespace().getPrefix() != "") {
			elem.setQName(new QName(elem.getName(), DocumentFactory
					.getInstance().createNamespace("",
							PackageNamespaces.RELATIONSHIPS)));
		}

		// remove all additional namespace declarations
		List<Namespace> additionalNameSpaces = elem.additionalNamespaces();
		for (Namespace nms : additionalNameSpaces) {
			elem.remove(nms);
		}
	}

	/*
	 * sorts relationship elements by Id . Side Effect 1: deletes all nodes that
	 * are not relationship from content of root element. Side Effect 2: since
	 * whole content of root element is replaced , all character data between
	 * the root element start and end tag is removed
	 */
	@SuppressWarnings("unchecked")
	public static void SortRelationshipElementsById(Document doc) {
		HashMap map = new HashMap();
		map.put("rel", PackageNamespaces.RELATIONSHIPS);

		XPath xpath = DocumentHelper.createXPath("//rel:"
				+ PackageRelationship.RELATIONSHIP_TAG_NAME);
		xpath.setNamespaceURIs(map);

		XPath sortXpath = DocumentHelper.createXPath("@Id");

		List<Element> sortedElements = xpath.selectNodes(doc, sortXpath);

		doc.getRootElement().setContent(sortedElements);
	}

	/*
	 * removes all relationships whose Ids are not specified in
	 * pRelationshipIds, and whose types are not specified in pRelationshipTypes
	 * string list NOTE : if relationshipIds passed is null then nothing is
	 * filtered and all relationships are retained in result set
	 */
	@SuppressWarnings("unchecked")
	public static void FilterRelationshipsByTypeAndId(Document doc,
			List<String> pRelationshipIds, List<String> pRelationshipTypes) {

		// if relationshipIds passed is null then nothing is filtered
		if (pRelationshipIds == null)
			return;

		List<Element> rels = (List<Element>) doc.getRootElement().elements();

		boolean isToBeRemoved;
		for (Element el : rels) {
			// set this record to be removed
			isToBeRemoved = true;

			if (pRelationshipIds != null
					&& pRelationshipIds.contains(el.attribute("Id").getValue())) {
				// this relationship is one listed in Ids so dont remove
				isToBeRemoved = false;
			}
			if (pRelationshipTypes != null
					&& pRelationshipTypes.contains(el.attribute("Type")
							.getValue())) {
				// this relationship is one listed in Types so dont remove
				isToBeRemoved = false;
			}

			if (isToBeRemoved) {
				el.detach();
			}
		}
	}

	/*
	 * Removes all content from all Relationship elements (content is the data
	 * between Relationship start and end tags
	 */
	@SuppressWarnings("unchecked")
	public static void RemoveContentsFromRelationshipElements(Document doc) {
		List<Element> rels = (List<Element>) doc.getRootElement().elements();

		for (Element el : rels) {
			el.clearContent();
		}
	}

	/*
	 * removes all comments from xml document
	 */
	public static void RemoveAllTopLevelComments(Document doc) {
		List<Node> tobeRemovedNodes = new Vector<Node>();
		for (int i = 0; i < doc.nodeCount(); i++) {
			if (doc.node(i).getNodeType() == Document.COMMENT_NODE)
				tobeRemovedNodes.add(doc.node(i));
		}

		for (Node tempNode : tobeRemovedNodes) {
			doc.remove(tempNode);
		}
	}

	/*
	 * Add TargetMode = Internal attribute to all relationship elements that are
	 * missing this attribute
	 */
	@SuppressWarnings("unchecked")
	public static void AddTargetModeInternalAttributeIfMissing(Document doc) {
		List<Element> rels = (List<Element>) doc.getRootElement().elements();

		for (Element el : rels) {
			if (el.attribute(PackageRelationship.TARGET_MODE_ATTRIBUTE_NAME) == null) {
				el.addAttribute(PackageRelationship.TARGET_MODE_ATTRIBUTE_NAME,
						"Internal"); // cant use TargetMode.INTERNAL.toString()
				// because of case sensitivity
			}
		}
	}
}
