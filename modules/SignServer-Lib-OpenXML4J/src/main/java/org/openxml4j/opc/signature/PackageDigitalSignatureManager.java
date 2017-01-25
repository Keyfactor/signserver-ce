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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.UUID;
import java.util.Vector;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.exceptions.InvalidOperationException;
import org.openxml4j.exceptions.OpenXML4JException;
import org.openxml4j.exceptions.OpenXML4JRuntimeException;
import org.openxml4j.opc.CertificateEmbeddingOption;
import org.openxml4j.opc.ContentTypes;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackageAccess;
import org.openxml4j.opc.PackageNamespaces;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackagePartName;
import org.openxml4j.opc.PackageRelationship;
import org.openxml4j.opc.PackageRelationshipCollection;
import org.openxml4j.opc.PackageRelationshipTypes;
import org.openxml4j.opc.PackagingURIHelper;
import org.openxml4j.opc.TargetMode;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * class that manages digital signature creation, parsing and verification
 * 
 * @author aziz.goktepe (aka rayback_2)
 * 
 *         patch originally created for SignServer project {@link http
 *         ://www.signserver.org}
 * 
 */
public final class PackageDigitalSignatureManager {

	private final static String defaultOriginPartURL = "/_xmlsignatures/origin.sigs";

	private final static PackagePartName defaultOriginPartName;

	private final static String defaultHashAlgorithm = "http://www.w3.org/2000/09/xmldsig#sha1";

	private CertificateEmbeddingOption embeddingOption;

	private Package _container;

	/**
	 * Flag that indicates if the search for the origin has already be done for
	 * speed up matter.
	 */
	private boolean originPartSearchDone = false;

	/**
	 * The digital signature origin part.
	 */
	private PackagePart originPart;

	/**
	 * Flag that indicates if the search for the signatures has already be done
	 * for speed up matter
	 */

	private boolean signaturesSearchDone = false;

	/**
	 * Signatures currently in the package.
	 */
	private List<PackageDigitalSignature> signatures;

	public Package getContainer() {
		return this._container;
	}

	public static String getDefaultHashAlgorithm() {
		return defaultHashAlgorithm;
	}

	public static PackagePartName getDefaultOriginPartName() {
		return defaultOriginPartName;
	}

	public CertificateEmbeddingOption getEmbeddingOption() {
		return embeddingOption;
	}

	public void setEmbeddingOption(CertificateEmbeddingOption embeddingOption) {

		if (embeddingOption != CertificateEmbeddingOption.IN_SIGNATURE_PART) {
			throw new InvalidOperationException(
					"Only IN_SIGNATURE_PART Certificate Embedding Option is supported.");
		}

		this.embeddingOption = embeddingOption;
	}

	static {
		try {

			// register relationship transform provider
			RelationshipTransformProvider.InstallProvider();

			// assing default origin partname
			defaultOriginPartName = PackagingURIHelper
					.createPartName(defaultOriginPartURL);

			// install bouncy castle security provider
			OPCSignatureHelper.InstallBouncyCastleProvider();

		} catch (InvalidFormatException e) {
			throw new OpenXML4JRuntimeException("");
		}
	}

	public PackageDigitalSignatureManager(Package pContainer) {
		this._container = pContainer;
	}

	/**
	 * Gets a value that indicates whether the package contains any signatures
	 * 
	 * @return true if package has signatures, false otherwise
	 * @throws OpenXML4JException
	 */
	public boolean getIsSigned() throws OpenXML4JException {
		return getSignatures() != null;
	}

	/**
	 * gets the digital signatures contained inside a package if exists
	 * 
	 * @return list of packagedigitalsignature if signature exist in a package,
	 *         null otherwise
	 * @throws OpenXML4JException
	 */
	public List<PackageDigitalSignature> getSignatures()
			throws OpenXML4JException {
		// if there's no origin part in package, there can't be signatures
		if (getOriginPart() == null) {
			this.signatures = null;
			return null;
		}

		if (this.signaturesSearchDone) {
			// already done a search for signatures, so return found results
			return this.signatures;
		} else {
			this.signaturesSearchDone = true;

			// search for digital signatures in a package by following
			// relationships emerging from digital signature origin part
			// getting relationships by type (standard does not mention if
			// origin part can (or cant) have other types of relationships
			for (PackageRelationship rel : this.originPart
					.getRelationshipsByType(PackageRelationshipTypes.DIGITAL_SIGNATURE)) {

				// check if the relationship targetmode is internal.
				// standard does not specify it should be internal, but there's
				// no knowledge on how to handle external signature parts
				if (rel.getTargetMode() != null
						&& rel.getTargetMode() != TargetMode.INTERNAL) {
					throw new OpenXML4JException(
							"TargetMode attribute of relationship pointing to Digital Signature Signature part MUST be INTERNAL");
				}

				// load PackageDigitalSignature from part and add to list
				try {
					PackageDigitalSignature sig = new PackageDigitalSignature(
							this, PackagingURIHelper.createPartName(rel
									.getTargetURI()));

					// ensure we got properly initialized list of signature
					ensureSignatures();

					// add signature to list
					this.signatures.add(sig);
				} catch (Exception e) {
					throw new OpenXML4JException(e);
				}

			}

			return this.signatures;
		}
	}

	/**
	 * gets the digital signature origin part from package if exists
	 * 
	 * @return if exists returns digital signature origin part, otherwise null.
	 * 
	 * @throws OpenXML4JException
	 *             If there are multiple digital signature origin parts (not
	 *             allowed by [M6.1] If target mode of digital signature origin
	 *             part relationship is not INTERNAL
	 */
	public PackagePart getOriginPart() throws OpenXML4JException {

		if (this.originPartSearchDone) {
			return this.originPart;
		} else {

			this.originPartSearchDone = true;

			// relationship to digital signature origin part
			PackageRelationship originPartRel = null;

			PackageRelationshipCollection dsigOriginPartTypeRelationships = this._container
					.getRelationshipsByType(PackageRelationshipTypes.DIGITAL_SIGNATURE_ORIGIN);
			if (dsigOriginPartTypeRelationships == null
					|| dsigOriginPartTypeRelationships.size() == 0) {
				originPartRel = null;
				this.originPart = null;
			} else if (dsigOriginPartTypeRelationships.size() > 0) {
				// multiple relationships with type of DIGITAL_SIGNATURE_ORIGIN
				// found
				// Standard says nothing about multiple relationships pointing
				// to SAME digital signature origin part (TODO : check ?)
				// so loop to check if they all point to same part
				for (PackageRelationship rel : this._container
						.getRelationshipsByType(PackageRelationshipTypes.DIGITAL_SIGNATURE_ORIGIN)) {

					if (originPartRel == null) {
						originPartRel = rel;
						continue;
					}

					if (!originPartRel.getTargetURI()
							.equals(rel.getTargetURI())) {
						// there are multiple relationships of
						// DIGITAL_SIGNATURE_ORIGIN type pointing to different
						// Digital Signature Origin parts
						// by [M6.1] this is not allowed
						throw new OpenXML4JException(
								" [M6.1] There are multiple relationships with DIGITAL_SIGNATURE_ORIGIN type pointing to multiple digital signature origin parts. There can be only one Digital Signature Origin Part in a package");
					}
				}

				// as it appears all relationships point to same digital
				// signature origin part (TODO : check if this is legal)
				// and originPartRel points to relationship (last actually)
				// identifying the part

			} else {
				// there seems to be single digital signature origin part
				originPartRel = dsigOriginPartTypeRelationships.iterator()
						.next();
			}

			/**
			 * if the relationship pointing to digital signature origin part is
			 * found check if the targetmode is internal although ECMA 376-2
			 * does not state it should be internal relationship for digital
			 * signature origin part (version 1 suggested so) there's no
			 * knowledge how to handle the external relationship to digital
			 * signature origin part. NOTE : if targetMode is not specified it
			 * is accepted to be internal
			 */
			if (originPartRel != null) {

				// TODO : what if the targetmode is not specified at all ? check
				if (originPartRel.getTargetMode() != null
						&& originPartRel.getTargetMode() != TargetMode.INTERNAL) {
					throw new InvalidFormatException(
							"TargetMode attribute of relationship pointing to Digital Signature Origin part MUST be INTERNAL");
				}

				this.originPart = this._container.getPart(PackagingURIHelper
						.createPartName(originPartRel.getTargetURI()));
			}

			return this.originPart;
		}
	}

	/**
	 * Verifies the signatures on all signed parts within the package
	 * 
	 * @return
	 * @throws XMLSignatureException
	 * @throws MarshalException
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 * @throws OpenXML4JException
	 */
	public VerifyResult VerifySignatures() throws OpenXML4JException,
			SAXException, IOException, ParserConfigurationException,
			MarshalException, XMLSignatureException {
		for (PackageDigitalSignature sig : getSignatures()) {
			VerifyResult res = sig.Verify();
			if (res != VerifyResult.Success)
				return res;
		}

		return VerifyResult.Success;
	}

	/**
	 * Verifies the signatures on all signed parts within the package with a
	 * given certificate
	 * 
	 * @return
	 * @throws XMLSignatureException
	 * @throws MarshalException
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 * @throws OpenXML4JException
	 */
	public VerifyResult VerifySignatures(X509Certificate pSigningCertificate)
			throws OpenXML4JException, SAXException, IOException,
			ParserConfigurationException, MarshalException,
			XMLSignatureException {

		if (pSigningCertificate == null)
			throw new NullPointerException("Certificate can not be null");

		for (PackageDigitalSignature sig : getSignatures()) {
			VerifyResult res = sig.Verify(pSigningCertificate);
			if (res != VerifyResult.Success)
				return res;
		}

		return VerifyResult.Success;
	}

	/**
	 * 
	 * Adds digital signature to document. This method selects parts and
	 * relationships to be signed by recursively adding singable items ,
	 * beginning from document main part and adding each part and relationship
	 * emerging from that part
	 * 
	 * TODO : write good explanation
	 * 
	 * @param pSigningPrivateKey
	 * @param pSigningCertificate
	 * @throws OpenXML4JException
	 */
	public void SignDocument(PrivateKey pSigningPrivateKey,
			X509Certificate pSigningCertificate) throws OpenXML4JException {
		SignDocumentAllSignableItems(pSigningPrivateKey, pSigningCertificate);
	}

	private void ensureSignatures() {
		if (this.signatures == null) {
			this.signatures = new ArrayList<PackageDigitalSignature>();
		}
	}

	/**
	 * Ensure that the origin digital part exist, if not it's created. Used when
	 * signature is added to the package
	 * 
	 * [M6.2] When creating the first Digital Signature XML Signature part, the
	 * package implementer shall create the Digital Signature Origin part, if it
	 * does not exist, in order to specify a relationship to that Digital
	 * Signature XML Signature part.
	 * 
	 * @throws OpenXML4JException
	 * 
	 */
	private PackagePart ensureOriginPart() throws OpenXML4JException {

		if (getOriginPart() != null) {
			return getOriginPart();
		} else {
			// digital signature origin part does not exist create one and add
			// relationship to package relationships
			PackagePart digSigOriginPart = this._container.createPart(
					defaultOriginPartName,
					ContentTypes.DIGITAL_SIGNATURE_ORIGIN_PART);

			// add digital signature origin relationship to package
			// relationships
			this._container.addRelationship(digSigOriginPart.getPartName(),
					TargetMode.INTERNAL,
					PackageRelationshipTypes.DIGITAL_SIGNATURE_ORIGIN);

			// set origin part
			this.originPart = digSigOriginPart;

			// set origin part search done
			this.originPartSearchDone = true;

			// return origin part
			return this.originPart;
		}
	}

	/**
	 * creates digital signature signature part with content specified If
	 * digital signature origin part does not exist in package, it gots created
	 * too
	 * 
	 * @param pContent
	 * @return
	 * @throws OpenXML4JException
	 */
	private PackagePart CreateDigitalSignatureSignaturePartFromContent(
			ByteArrayOutputStream pContent) throws OpenXML4JException {

		// ensure origin part exists
		ensureOriginPart();

		// create UUID for new signature part
		UUID uuid = UUID.randomUUID();
		String signaturePartURI = "/_xmlsignatures/" + uuid.toString() + ".xml";

		// create digital signature part
		PackagePart digitalSignatureSignaturePart = _container.createPart(
				PackagingURIHelper.createPartName(signaturePartURI),
				ContentTypes.DIGITAL_SIGNATURE_XML_SIGNATURE_PART, pContent);

		// add relationship to digital signature origin part
		this.originPart.addRelationship(digitalSignatureSignaturePart
				.getPartName(), TargetMode.INTERNAL,
				PackageRelationshipTypes.DIGITAL_SIGNATURE);

		return digitalSignatureSignaturePart;
	}

	/**
	 * this method identifies which parts and relationships (individual
	 * relationship items inside each relationship ) should be signed.
	 * 
	 * It starts by getting the document type relationship from package
	 * relationship and adds all parts and relationships recursively
	 * 
	 * Returns : After method exits the opPartsToSign will contain parts to be
	 * signed and opRelationshipsToSign will contain relationships to be signed
	 * 
	 * opPartsToSign and opRelationshipsToSign lists content will be cleared
	 */
	private void SetPartsAndRelationshipsToSign(
			List<PartIdentifier> opPartsToSign,
			List<PackageRelationshipSelector> opRelationshipsToSign)
			throws Exception {

		opPartsToSign.clear();
		opRelationshipsToSign.clear();
		PackageRelationshipCollection coreDocRelationships = _container
				.getRelationshipsByType(PackageRelationshipTypes.CORE_DOCUMENT);
		for (PackageRelationship relationship : coreDocRelationships) {
			RecursivelyAddSignableItems(relationship, opPartsToSign,
					opRelationshipsToSign);
		}

	}

	/**
	 * recursively adds signable items (that is add relationship and target
	 * part, and follow the added parts relationships to find more to add)
	 */
	private void RecursivelyAddSignableItems(PackageRelationship pRelationship,
			List<PartIdentifier> opPartsToSign,
			List<PackageRelationshipSelector> opRelationshipsToSign)
			throws Exception {

		// A special naming convention is used for the Relationships part.
		// First, the Relationships part for a part in a given
		// folder in the name hierarchy is stored in a sub-folder called
		// _rels. Second, the name of the Relationships part
		// is formed by appending .rels to the name of the original part.
		// Package relationships are found in the package
		// relationships part named /_rels/.rels.[M1.30]
		PackagePartName relationshipPartName = null;
		if (pRelationship.getSourceURI().toString() != PackagingURIHelper
				.getPackageRootUri().toString())
			relationshipPartName = PackagingURIHelper
					.getRelationshipPartName(PackagingURIHelper
							.createPartName(pRelationship.getSourceURI()));
		else {
			relationshipPartName = PackagingURIHelper
					.createPartName(pRelationship
							.getContainerPartRelationship());
		}

		// see if this relationship selector is already added to list
		PackageRelationshipSelector selector = null;
		for (PackageRelationshipSelector prs : opRelationshipsToSign) {
			if (prs.getRelationshipPartName().getName().equals(
					relationshipPartName.getName())) {
				// selector already added, add identifier to it
				selector = prs;
				break;
			}
		}
		if (selector == null) {
			// selector is to be newly created and added
			selector = new PackageRelationshipSelector(pRelationship
					.getSourceURI(), relationshipPartName);

			opRelationshipsToSign.add(selector);
		}

		selector.addRelationshipIdentifier(PackageRelationshipSelectorType.Id,
				pRelationship.getId());

		if (pRelationship.getTargetMode() == TargetMode.INTERNAL) {
			PackagePart part = pRelationship.getPackage().getPart(
					PackagingURIHelper.createPartName(PackagingURIHelper
							.resolvePartUri(pRelationship.getSourceURI(),
									pRelationship.getTargetURI())));

			// if this part is already added do not add again, parts and
			// relationships are permitted to be "circular"
			URI partURI = PackagingURIHelper.getURIFromPath(part.getPartName()
					.getName());

			PartIdentifier tempPartIdent = new PartIdentifier(partURI, part
					.getContentType());
			if (!opPartsToSign.contains(tempPartIdent)) {

				opPartsToSign.add(tempPartIdent);
				for (PackageRelationship childRel : part.getRelationships()) {
					RecursivelyAddSignableItems(childRel, opPartsToSign,
							opRelationshipsToSign);
				}
			}
		}
	}

	/**
	 * creates idPackageObject as per ECMA376 , which hold references to all
	 * parts and relationships to be signed
	 */
	private XMLObject CreateIdPackageObject(XMLSignatureFactory fac,
			String pSignatureId, org.w3c.dom.Document pSignatureDoc,
			List<Reference> denManifestReferences) throws Exception {
		// identify parts and relationships to sign
		List<PartIdentifier> partsToSign = new Vector<PartIdentifier>();
		List<PackageRelationshipSelector> relationshipsToSign = new Vector<PackageRelationshipSelector>();
		SetPartsAndRelationshipsToSign(partsToSign, relationshipsToSign);

		// list of references to be included in manifest
		List<Reference> manifestReferences = new Vector<Reference>();

		// c14n transform to be used in all references that refer to
		// relationships (inside manifest (inside idpackageobject))
		CanonicalizationMethod cm = fac.newCanonicalizationMethod(
				CanonicalizationMethod.INCLUSIVE,
				(C14NMethodParameterSpec) null);

		// create relationship references
		for (PackageRelationshipSelector relSel : relationshipsToSign) {
			// identify relationship Ids to include in signature
			List<String> relationShipIdsToInclude = new Vector<String>();
			for (RelationshipIdentifier relIdentifier : relSel
					.getRelationshipIdentifiers()) {
				relationShipIdsToInclude.add(relIdentifier
						.getSelectionCriteria());
			}

			// create relationshiptransform parameters (containing relIds to
			// include)
			RelationshipTransformParameterSpec relTransformParams = new RelationshipTransformParameterSpec(
					relationShipIdsToInclude, null);

			// create relationship transform
			Transform relationShipTransform = fac
					.newTransform(
							RelationshipTransformProvider.RelationShipTransformAlgorithm,
							relTransformParams);

			// add transforms to transforms list (note : relationship transform
			// should be followed by c14n transform)
			List<Transform> transforms = new Vector<Transform>();
			transforms.add(relationShipTransform);
			transforms.add(cm);

			// create relationship reference
			// NOTE : partname in URI should be followed by Content type
			// specification
			Reference refRel = fac.newReference(relSel
					.getRelationshipPartName().toString()
					+ "?ContentType=" + ContentTypes.RELATIONSHIPS_PART, fac
					.newDigestMethod(DigestMethod.SHA1, null), transforms,
					null, null);

			// add to manifest references

			manifestReferences.add(refRel);
		}

		// create package part references
		for (PartIdentifier relPart : partsToSign) {
			// create part reference
			// NOTE : partname in URI should be followed by Content type
			// NOTE 2 : parts have no transformations (signed as octet stream)
			Reference refPart = fac
					.newReference(relPart.getPartURI().toString()
							+ "?ContentType=" + relPart.getContentType(), fac
							.newDigestMethod(DigestMethod.SHA1, null), null,
							null, null);

			// add to manifest references

			manifestReferences.add(refPart);
		}

		// create manifest to hold idpackageobject references (to be included in
		// idpackageobject xml object)
		// Manifest manifestIdPackageObject =
		// fac.newManifest(manifestReferences);

		Manifest manifestIdPackageObject = null;
		if (denManifestReferences == null)
			manifestIdPackageObject = fac.newManifest(manifestReferences);
		else
			manifestIdPackageObject = fac.newManifest(denManifestReferences);

		// create Signature Properties
		SignatureProperties signatureProperties = createSignaturePropertiesForIdPackageObject(
				fac, pSignatureId, pSignatureDoc);

		List<XMLStructure> idPackageObjectContent = new ArrayList<XMLStructure>();
		idPackageObjectContent.add(manifestIdPackageObject);

		idPackageObjectContent.add(signatureProperties);

		// create idpackageobject xml object
		XMLObject idPackageObject = fac.newXMLObject(idPackageObjectContent,
				PackageDigitalSignature.PackageObjectIdentifier, null, null);

		return idPackageObject;
	}

	/**
	 * creates signature properties to be included in idPackageObject
	 */
	private SignatureProperties createSignaturePropertiesForIdPackageObject(
			XMLSignatureFactory fac, String pSignatureId,
			org.w3c.dom.Document pSignatureDoc) {

		Calendar now = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
		Date signingTime = now.getTime();

		String signatureDateTimeFormatString = "yyyy-MM-dd'T'HH:mm:ss";
		SimpleDateFormat sdf = new SimpleDateFormat(
				signatureDateTimeFormatString);
		sdf.setTimeZone(TimeZone.getTimeZone("GMT"));

		String dateFriendly = sdf.format(signingTime);

		// set as date format as MS office produces it ?
		// TODO : needs and cries for better handling
		dateFriendly = dateFriendly + "Z";
		signatureDateTimeFormatString = "YYYY-MM-DDThh:mm:ssTZD";

		// signature time
		Element signDateTimeElement = pSignatureDoc.createElementNS(
				PackageNamespaces.DIGITAL_SIGNATURE,
				PackageDigitalSignature.SignatureTimeElementName);
		signDateTimeElement.setPrefix("mdssi");
		// explicitly add namespace so it is not omitted during c18n
		signDateTimeElement.setAttributeNS("http://www.w3.org/2000/xmlns/",
				"xmlns:mdssi", PackageNamespaces.DIGITAL_SIGNATURE);
		// format node
		Element signDateTimeFormat = pSignatureDoc.createElementNS(
				PackageNamespaces.DIGITAL_SIGNATURE,
				PackageDigitalSignature.SignatureTimeFormatElementName);
		signDateTimeFormat.setPrefix("mdssi");
		// explicitly add namespace so it is not omitted during c18n
		signDateTimeFormat.setAttributeNS("http://www.w3.org/2000/xmlns/",
				"xmlns:mdssi", PackageNamespaces.DIGITAL_SIGNATURE);
		signDateTimeFormat.appendChild(pSignatureDoc
				.createTextNode(signatureDateTimeFormatString));

		// value node
		Element signDateTimeValue = pSignatureDoc.createElementNS(
				PackageNamespaces.DIGITAL_SIGNATURE,
				PackageDigitalSignature.SignatureTimeValueElementName);
		signDateTimeValue.setPrefix("mdssi");
		// explicitly add namespace so it is not omitted during c18n
		signDateTimeValue.setAttributeNS("http://www.w3.org/2000/xmlns/",
				"xmlns:mdssi", PackageNamespaces.DIGITAL_SIGNATURE);
		signDateTimeValue.appendChild(pSignatureDoc
				.createTextNode(dateFriendly));

		signDateTimeElement.appendChild(signDateTimeFormat);
		signDateTimeElement.appendChild(signDateTimeValue);

		List<DOMStructure> signaturePropertiesElems = new ArrayList<DOMStructure>();
		signaturePropertiesElems.add(new DOMStructure(signDateTimeElement));
		SignatureProperty signatureProperty = fac.newSignatureProperty(
				signaturePropertiesElems, "#" + pSignatureId,
				PackageDigitalSignature.SignatureTimeIdentifier);

		SignatureProperties signatureProperties = fac.newSignatureProperties(
				Collections.singletonList(signatureProperty), null);
		return signatureProperties;
	}

	/**
	 * create idOfficeObject that is required by the ms office document
	 * signature
	 */
	private XMLObject CreateIdOfficeObject(XMLSignatureFactory fac,
			String pSignatureId, org.w3c.dom.Document pSignatureDoc) {
		Element signatureInfoV1 = pSignatureDoc.createElementNS(
				"http://schemas.microsoft.com/office/2006/digsig",
				"SignatureInfoV1");

		// explicitly add namespace so it is not omitted during c18n
		signatureInfoV1.setAttributeNS("http://www.w3.org/2000/xmlns/",
				"xmlns", "http://schemas.microsoft.com/office/2006/digsig");

		Element manifestHashAlgorithm = pSignatureDoc
				.createElement("ManifestHashAlgorithm");

		manifestHashAlgorithm.appendChild(pSignatureDoc
				.createTextNode("http://www.w3.org/2000/09/xmldsig#sha1"));
		signatureInfoV1.appendChild(manifestHashAlgorithm);

		List<DOMStructure> signaturePropertiesElems = new ArrayList<DOMStructure>();
		signaturePropertiesElems.add(new DOMStructure(signatureInfoV1));

		SignatureProperty signatureProperty = fac.newSignatureProperty(
				signaturePropertiesElems, "#" + pSignatureId,
				"idOfficeV1Details");

		SignatureProperties signatureProperties = fac.newSignatureProperties(
				Collections.singletonList(signatureProperty), null);

		XMLObject idOfficeObject = fac.newXMLObject(Collections
				.singletonList(signatureProperties), "idOfficeObject", null,
				null);

		return idOfficeObject;
	}

	/**
	 * This method is signing the idPackageObject <Object>. This is workaraound
	 * to bug in java XML DSig API, which processes Reference objects inside
	 * Manifest of xmlobject AFTER References in SignedInfo are processed (thus
	 * failing validation). BUG Id : 6867348 (sun internal bug tracking system)
	 * 
	 * @param docxPackage
	 * @return
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
	private List<Reference> CalculateIdPackageObjectReferences(
			PrivateKey pSigningPrivateKey, X509Certificate pSigningCertificate)
			throws Exception {

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);

                dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
                dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

		org.w3c.dom.Document doc = dbf.newDocumentBuilder().newDocument();

		final XMLSignatureFactory fac = OPCSignatureHelper
				.CreateXMLSignatureFactory();

		XMLObject idPackageObject = CreateIdPackageObject(fac,
				PackageDigitalSignature.DefaultSignatureId, doc, null);

		List<Reference> signedInfoReferences = ((Manifest) idPackageObject
				.getContent().get(0)).getReferences();

		SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(
				CanonicalizationMethod.INCLUSIVE,
				(C14NMethodParameterSpec) null), fac.newSignatureMethod(
				SignatureMethod.RSA_SHA1, null), signedInfoReferences);

		KeyInfo ki = null;
		KeyInfoFactory kif = fac.getKeyInfoFactory();

		KeyValue kv = kif.newKeyValue(pSigningCertificate.getPublicKey());

		X509Data x509d = kif.newX509Data(Collections
				.singletonList(pSigningCertificate));

		List<XMLStructure> keyInfoContents = new Vector<XMLStructure>();
		keyInfoContents.add(kv);
		keyInfoContents.add(x509d);
		ki = kif.newKeyInfo(keyInfoContents);

		XMLSignature signature = fac.newXMLSignature(si, ki, null,
				PackageDigitalSignature.DefaultSignatureId, null);

		DOMSignContext dsc = new DOMSignContext(pSigningPrivateKey, doc);

		// set OPC URI dereferencer as default URI dereferencer with fallback to
		// original dereferencer
		dsc.setURIDereferencer(new OPCURIDereferencer(_container, fac
				.getURIDereferencer()));

		// actually sign
		signature.sign(dsc);

		return signature.getSignedInfo().getReferences();
	}

	private void SignDocumentAllSignableItems(PrivateKey pSigningPrivateKey,
			X509Certificate pSigningCertificate) throws OpenXML4JException {

		if (this._container.getPackageAccess() != PackageAccess.READ_WRITE) {
			throw new OpenXML4JException(
					"To sign a document package must be open with read write package access");
		}

		// openxml4j formats document when writing parts to zip, which affects
		// the signature (breaks it).
		// TODO : talk to Julien why
		// First "normalize" document by opening and saving, then reopen the
		// saved document to sign.

		// save output to package
		ByteArrayOutputStream boutTemp = new ByteArrayOutputStream();
		try {
			_container.save(boutTemp);
		} catch (IOException e) {
			throw new OpenXML4JException(
					"Error saving pre-formatted data to output", e);
		}

		ByteArrayInputStream binTemp = new ByteArrayInputStream(boutTemp
				.toByteArray());

		// open saved docxpackage and sign
		try {
			_container = Package.open(binTemp, PackageAccess.READ_WRITE);
		} catch (InvalidFormatException e) {
			throw new OpenXML4JException(
					"Pre-formatted data is not in valid openxml package format",
					e);
		} catch (IOException e) {
			throw new OpenXML4JException("Error opening pre-formatted data", e);
		}

		// ensure origin part exists
		ensureOriginPart();

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		org.w3c.dom.Document doc;
		try {
                    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
                    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

			doc = dbf.newDocumentBuilder().newDocument();
		} catch (ParserConfigurationException e) {
			throw new OpenXML4JException("Document parsing error", e);
		}

		// create XML signature factory (JSR-105)
		final XMLSignatureFactory fac = OPCSignatureHelper
				.CreateXMLSignatureFactory();

		// create idpackageobject and idofficeobject reference (to add to
		// signedinfo)
		List<Reference> signedInfoReferences = new Vector<Reference>();
		Reference refIdPackageObject;
		Reference refIdOfficeObject;
		try {
			refIdPackageObject = fac.newReference("#"
					+ PackageDigitalSignature.PackageObjectIdentifier, fac
					.newDigestMethod(DigestMethod.SHA1, null), null,
					"http://www.w3.org/2000/09/xmldsig#Object", null);

			refIdOfficeObject = fac.newReference("#"
					+ PackageDigitalSignature.OfficeObjectIdentifier, fac
					.newDigestMethod(DigestMethod.SHA1, null), null,
					"http://www.w3.org/2000/09/xmldsig#Object", null);

		} catch (NoSuchAlgorithmException e) {
			throw new OpenXML4JException("XML signing algorithm error", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new OpenXML4JException(
					"XML signing algorithm parameters error", e);
		}

		signedInfoReferences.add(refIdPackageObject);
		signedInfoReferences.add(refIdOfficeObject);

		List<XMLObject> signatureObjects = new Vector<XMLObject>();

		XMLObject idPackageObject;
		try {
			idPackageObject = CreateIdPackageObject(fac,
					PackageDigitalSignature.DefaultSignatureId, doc,
					CalculateIdPackageObjectReferences(pSigningPrivateKey,
							pSigningCertificate));
		} catch (Exception e) {
			throw new OpenXML4JException("Error constructing idPackageObject",
					e);
		}

		XMLObject idOfficeObject = CreateIdOfficeObject(fac,
				PackageDigitalSignature.DefaultSignatureId, doc);

		signatureObjects.add(idPackageObject);
		signatureObjects.add(idOfficeObject);

		SignedInfo si;
		try {
			si = fac.newSignedInfo(fac.newCanonicalizationMethod(
					CanonicalizationMethod.INCLUSIVE,
					(C14NMethodParameterSpec) null), fac.newSignatureMethod(
					SignatureMethod.RSA_SHA1, null), signedInfoReferences);
		} catch (NoSuchAlgorithmException e) {
			throw new OpenXML4JException("XML signing algorithm error", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new OpenXML4JException(
					"XML signing algorithm parameters error", e);
		}

		KeyInfo ki = null;
		KeyInfoFactory kif = fac.getKeyInfoFactory();

		KeyValue kv;

		try {
			kv = kif.newKeyValue(pSigningCertificate.getPublicKey());
		} catch (KeyException e) {
			throw new OpenXML4JException(
					"Problem obtaining public key from certificate", e);
		}

		X509Data x509d = kif.newX509Data(Collections
				.singletonList(pSigningCertificate));

		List<XMLStructure> keyInfoContents = new Vector<XMLStructure>();
		keyInfoContents.add(kv);
		keyInfoContents.add(x509d);
		ki = kif.newKeyInfo(keyInfoContents);

		XMLSignature signature = fac.newXMLSignature(si, ki, signatureObjects,
				PackageDigitalSignature.DefaultSignatureId, null);

		DOMSignContext dsc = new DOMSignContext(pSigningPrivateKey, doc);

		// set OPC URI dereferencer as default URI dereferencer with fallback to
		// original dereferencer
		dsc.setURIDereferencer(new OPCURIDereferencer(_container, fac
				.getURIDereferencer()));

		// actually sign
		try {
			signature.sign(dsc);
		} catch (MarshalException e) {
			throw new OpenXML4JException("Error signing XML", e);
		} catch (XMLSignatureException e) {
			throw new OpenXML4JException("XMLSignature Exception when signing",
					e);
		}

		// Materialize into an xml document
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans;
		try {
			trans = tf.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new OpenXML4JException(
					"Problem creating Transformer for output", e);
		}
		trans.setOutputProperty(OutputKeys.INDENT, "no");
		trans.setOutputProperty(OutputKeys.STANDALONE, "yes");

		// save to bytearrayoutputstream to be used as content for signature
		// part

		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		try {
			trans.transform(new DOMSource(doc), new StreamResult(bout));
		} catch (TransformerException e) {
			throw new OpenXML4JException(
					"Problem transforming output to output stream", e);
		}

		// create digital signature signature part
		CreateDigitalSignatureSignaturePartFromContent(bout);

	}
}
