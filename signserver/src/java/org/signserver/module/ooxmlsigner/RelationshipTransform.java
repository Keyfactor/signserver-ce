package org.signserver.module.ooxmlsigner;

import java.io.InputStream;
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
import org.dom4j.io.SAXReader;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackageNamespaces;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackageRelationship;
import org.openxml4j.opc.PackagingURIHelper;

public class RelationshipTransform {

	public static Document DoRelationshipTransform(Package p,
			String pRelationshipPartName, List<String> pRelationshipIds)
			throws Exception {

		// open relationships part
		SAXReader docReader = new SAXReader();
		PackagePart relsPart = p.getPart(PackagingURIHelper
				.createPartName(pRelationshipPartName));
		InputStream is = relsPart.getInputStream();
		Document doc = docReader.read(is);

		return DoRelationshipTransform(doc, pRelationshipIds);
	}

	public static Document DoRelationshipTransform(Document docIn,
			List<String> pRelationshipIds) throws Exception {

		//defensively copy document  
		Document doc = (Document)docIn.clone();
		
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
		// NOTE : we use only Ids
		// TODO : needs testing
		FilterRelationshipsById(doc, pRelationshipIds);

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
		//return doc.getRootElement().asXML();
		
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
	 * removes all relationships whose Ids are not specified in pRelationshipIds
	 * string list NOTE : if relationshipIds passed is null then nothing is
	 * filtered and all relationships are retained in result set
	 */
	@SuppressWarnings("unchecked")
	public static void FilterRelationshipsById(Document doc,
			List<String> pRelationshipIds) {

		// if relationshipIds passed is null then nothing is filtered
		if (pRelationshipIds == null)
			return;

		List<Element> rels = (List<Element>) doc.getRootElement().elements();

		for (Element el : rels) {
			if (!pRelationshipIds.contains(el.attribute("Id").getValue())) {
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
						"Internal"); // cant use TargetMode.INTERNAL.toString() because of case sensitivity
			}
		}
	}
}
