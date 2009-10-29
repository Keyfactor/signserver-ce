package org.openxml4j.signaturehelpers;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.xml.crypto.NodeSetData;

import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

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
