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

import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.NodeSetData;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.dom4j.io.DOMWriter;
import org.apache.jcp.xml.dsig.internal.dom.DOMUtils;
import org.openxml4j.exceptions.OpenXML4JException;
import org.openxml4j.opc.PackageNamespaces;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * 
 * Implementation of transform service that implements OOXML relationship
 * transform as per ECMA376-2
 * 
 * @author aziz.goktepe (aka rayback_2)
 * 
 *         patch originally created for SignServer project {@link http
 *         ://www.signserver.org}
 * 
 */
public class RelationshipTransformService extends TransformService {

	public static final String RELATIONSHIP_REFERENCE_TAG_NAME = "RelationshipReference";
	public static final String RELATIONSHIP_REFERENCE_SOURCE_ID_ATTR_NAME = "SourceId";
	public static final String RELATIONSHIP_REFERENCE_SOURCE_TYPE_ATTR_NAME = "SourceType";

	protected RelationshipTransformParameterSpec params;
	protected Document ownerDoc;
	protected Element transformElem;

	@Override
	public void init(TransformParameterSpec arg0)
			throws InvalidAlgorithmParameterException {

		if (arg0 == null) {
			throw new NullPointerException(
					"RelationshipParameterScep passed cannot be null");
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
			throw new NullPointerException(
					"Relationship transform passed cannot be null");
		}

		// we are given node , construct transform parameter specs from it
		Element transformElem = (Element) ((DOMStructure) arg0).getNode();
		try {
			setRelationshipTransformParameterSpecFromNode(transformElem);
		} catch (OpenXML4JException e) {
			throw new InvalidAlgorithmParameterException(e);
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
		if (params != null
				&& params.getRelationShipSourceIdsToInclude() != null) {
			for (String s : params.getRelationShipSourceIdsToInclude()) {

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
					params.getRelationShipSourceIdsToInclude(), params
							.getRelationshipSourceTypesToInclude());

			// convert transformed doc4j document to dom document
			org.dom4j.io.DOMWriter dw = new DOMWriter();
			final org.w3c.dom.Document docRes = dw.write(doc4jRet);

			OX4JNodeSetData opcNodeSet = new OX4JNodeSetData(docRes);
			return opcNodeSet;

		} catch (Exception e) {
			throw new TransformException(e);
		}
	}

	/**
	 * retrieves relationship transform parameter spec from the transform
	 * element given
	 * 
	 * @param pTransformElem
	 * @throws OpenXML4JException
	 */
	private void setRelationshipTransformParameterSpecFromNode(
			Element pTransformElem) throws OpenXML4JException {

		NodeList transformparams = pTransformElem.getChildNodes();
		if (transformparams == null || transformparams.getLength() == 0) {
			// relationship transform does not have any subnodes
			// (transform element), so there's no parameter !! throw
			// exception
			throw new OpenXML4JException(
					"Relationship transform specified , but no parameters given to relationship transform. ");
		}

		List<String> relationshipSourceIdsToInclude = null;
		List<String> relationshipSourceTypesToInclude = null;

		// now get all childnodes of transform and retrieve
		for (int i = 0; i < transformparams.getLength(); i++) {

			RelationshipIdentifier relIdent = null;
			Node tempNode = null;

			// either SourceId or SourceType should be present as
			// attribute
			NamedNodeMap nl = transformparams.item(i).getAttributes();
			tempNode = nl
					.getNamedItem(RelationshipTransformService.RELATIONSHIP_REFERENCE_SOURCE_ID_ATTR_NAME);

			if (tempNode != null) {
				// found sourceId
				if (relationshipSourceIdsToInclude == null)
					relationshipSourceIdsToInclude = new ArrayList<String>();

				relationshipSourceIdsToInclude.add(tempNode.getNodeValue());
				continue;
			}

			// if sourceId not found search for SourceType
			tempNode = nl
					.getNamedItem(RelationshipTransformService.RELATIONSHIP_REFERENCE_SOURCE_TYPE_ATTR_NAME);
			if (tempNode != null) {
				// found SourceType
				if (relationshipSourceTypesToInclude == null)
					relationshipSourceTypesToInclude = new ArrayList<String>();

				relationshipSourceTypesToInclude.add(tempNode.getNodeValue());
				continue;
			}

			// if neither sourceId nor SourceType found , something
			// is wrong throw exception
			throw new OpenXML4JException(
					"Relationship transform parameter found but neither SourceId nor SourceType is not specified.");
		}

		params = new RelationshipTransformParameterSpec(
				relationshipSourceIdsToInclude,
				relationshipSourceTypesToInclude);
	}
}
