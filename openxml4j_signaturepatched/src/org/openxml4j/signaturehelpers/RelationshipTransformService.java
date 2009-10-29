package org.openxml4j.signaturehelpers;

import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.NodeSetData;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.dom4j.io.DOMWriter;
import org.jcp.xml.dsig.internal.dom.DOMUtils;
import org.openxml4j.opc.PackageNamespaces;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/*
 * transform service that implements OOXML relationship transform as per ECMA376-2
 */
public class RelationshipTransformService extends TransformService {

	public static final String RELATIONSHIP_REFERENCE_TAG_NAME = "RelationshipReference";
	public static final String RELATIONSHIP_REFERENCE_SOURCE_ID_ATTR_NAME = "SourceId";

	protected RelationshipTransformParameterSpec params;
	protected Document ownerDoc;
	protected Element transformElem;

	@Override
	public void init(TransformParameterSpec arg0)
			throws InvalidAlgorithmParameterException {

		if (arg0 == null) {
			throw new NullPointerException();
		}

		if (!(arg0 instanceof RelationshipTransformParameterSpec)) {
			throw new InvalidAlgorithmParameterException();
		}

		// params should contain the relationship Ids that are to be included in
		// transform
		params = (RelationshipTransformParameterSpec) arg0;

	}

	@Override
	public void init(XMLStructure arg0, XMLCryptoContext arg1)
			throws InvalidAlgorithmParameterException {
		if (arg0 == null) {
			throw new NullPointerException();
		}
	}

	@Override
	public void marshalParams(XMLStructure parent, XMLCryptoContext context)
			throws MarshalException {
		if (parent == null) {
			throw new NullPointerException();
		}

		transformElem = (Element) ((javax.xml.crypto.dom.DOMStructure) parent)
				.getNode();
		ownerDoc = DOMUtils.getOwnerDocument(transformElem);

		// for each relationshipId add relationship reference element
		if (params != null && params.getRelationShipIdsToInclude() != null) {
			for (String s : params.getRelationShipIdsToInclude()) {

				Element relationshipRef = DOMUtils
						.createElement(
								ownerDoc,
								RelationshipTransformService.RELATIONSHIP_REFERENCE_TAG_NAME,
								PackageNamespaces.DIGITAL_SIGNATURE, "mdssi");
				DOMUtils
						.setAttribute(
								relationshipRef,
								RelationshipTransformService.RELATIONSHIP_REFERENCE_SOURCE_ID_ATTR_NAME,
								s);

				// explicitly add namespace so it is not omitted during c18n
				relationshipRef.setAttributeNS("http://www.w3.org/2000/xmlns/",
						"xmlns:mdssi", PackageNamespaces.DIGITAL_SIGNATURE);

				transformElem.appendChild(relationshipRef);

			}
		}
	}

	@Override
	public AlgorithmParameterSpec getParameterSpec() {
		return params;
	}

	@Override
	public boolean isFeatureSupported(String arg0) {
		return false;
	}

	@Override
	public Data transform(Data arg0, XMLCryptoContext arg1)
			throws TransformException {
		// implement the relationship transform
		NodeSetData inData = (NodeSetData) arg0;

		return transformIt(inData);
	}

	@Override
	public Data transform(Data arg0, XMLCryptoContext arg1, OutputStream arg2)
			throws TransformException {
		// implement the relationship transform
		NodeSetData inData = (NodeSetData) arg0;

		return transformIt(inData);
	}

	private Data transformIt(NodeSetData inData) throws TransformException {
		// get relationships node

		org.w3c.dom.Node relationshipsNode = ((OX4JNodeSetData) inData)
				.getRootNode().getFirstChild();

		// convert relationships node to dom4j document
		DOMReader2 dr = new DOMReader2();
		org.dom4j.Document doc4j = dr.read(relationshipsNode);
		org.dom4j.Document doc4jRet = null;
		try {
			// perform transform on dom4j document
			doc4jRet = RelationshipTransform.DoRelationshipTransform(doc4j,
					params.getRelationShipIdsToInclude());

			// convert transformed doc4j document to dom document
			org.dom4j.io.DOMWriter dw = new DOMWriter();
			final org.w3c.dom.Document docRes = dw.write(doc4jRet);

			OX4JNodeSetData opcNodeSet = new OX4JNodeSetData(docRes);
			return opcNodeSet;

		} catch (Exception e) {
			throw new TransformException(e);
		}
	}
}
