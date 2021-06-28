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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.jcp.xml.dsig.internal.dom.DOMReference;
import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.exceptions.OpenXML4JException;
import org.openxml4j.opc.ContentTypes;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackagePartName;
import org.openxml4j.opc.PackagingURIHelper;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Class representing digital signature inside the package
 * 
 * @author aziz.goktepe (aka rayback_2)
 * 
 *         patch originally created for SignServer project {@link http
 *         ://www.signserver.org}
 * 
 */
public class PackageDigitalSignature {

	protected PackageDigitalSignatureManager manager;

	protected PackagePart signaturePart;

	protected XMLSignature signature;

	protected X509Certificate signer;

	protected PublicKey signingPublicKey;

	protected boolean isSignatureValid;

	protected List<PartIdentifier> signedParts;

	protected List<PackageRelationshipSelector> signedRelationshipSelectors;

	protected String signingTimeStringValue;

	protected String timeFormat;

	public static String PackageObjectIdentifier = "idPackageObject";
	public static String SignatureTimeIdentifier = "idSignatureTime";
	public static String SignatureTimeElementName = "SignatureTime";
	public static String SignatureTimeFormatElementName = "Format";
	public static String SignatureTimeValueElementName = "Value";
	public static String DefaultSignatureId = "idPackageSignature";
	public static String OfficeObjectIdentifier = "idOfficeObject";

	/**
	 * 
	 * NOTE : if any overload of Verify has not been called yet , this getter
	 * will call Verify() to try to verify signature using certificate (public
	 * key) found in a package
	 * 
	 * internal flag to keep track if signature has been verified at least once
	 * note : signature can be verified using supplied certificate or using
	 * certificate or key from package (if can be found)
	 */
	protected boolean isVerified = false;

	/**
	 * NOTE : if any overload of Verify has not been called yet , this getter
	 * will call Verify() to try to verify signature using certificate (public
	 * key) found in a package
	 * 
	 * @return the time in string format at which signature is applied
	 * @throws XMLSignatureException
	 * @throws MarshalException
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 * @throws OpenXML4JException
	 */
	public String getSigningTimeStringValue() throws OpenXML4JException,
			SAXException, IOException, ParserConfigurationException,
			MarshalException, XMLSignatureException {
		if (!isVerified) {
			Verify();
		}
		return this.signingTimeStringValue;
	}

	/**
	 * NOTE : if any overload of Verify has not been called yet , this getter
	 * will call Verify() to try to verify signature using certificate (public
	 * key) found in a package
	 * 
	 * @return time format of the signing time
	 * @throws OpenXML4JException
	 * @throws SAXException
	 * @throws IOException
	 * @throws ParserConfigurationException
	 * @throws MarshalException
	 * @throws XMLSignatureException
	 */
	public String getTimeFormat() throws OpenXML4JException, SAXException,
			IOException, ParserConfigurationException, MarshalException,
			XMLSignatureException {
		if (!isVerified) {
			Verify();
		}
		return this.timeFormat;
	}

	/**
	 * NOTE : if any overload of Verify has not been called yet , this getter
	 * will call Verify() to try to verify signature using certificate (public
	 * key) found in a package
	 * 
	 * @return parts that are signed by this signature. Note : relationship
	 *         parts are not included. To get signed relationships (and filters)
	 *         use getSignedRelationshipSelectors
	 * @throws XMLSignatureException
	 * @throws MarshalException
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 * @throws OpenXML4JException
	 */
	public List<PartIdentifier> getSignedParts() throws OpenXML4JException,
			SAXException, IOException, ParserConfigurationException,
			MarshalException, XMLSignatureException {
		if (!isVerified) {
			Verify();
		}

		return this.signedParts;
	}

	/**
	 * NOTE : if any overload of Verify has not been called yet , this getter
	 * will call Verify() to try to verify signature using certificate (public
	 * key) found in a package
	 * 
	 * @return relationships that are signed by this signature. Each
	 *         PackageRelationshipSelector corresponds to one relationship part
	 *         signed (Reference) and each RelationshipIdentifier returned by
	 *         call to getRelationshipIdentifiers corresponds to identifier that
	 *         identifies(by sourceid or by sourcetype attribute), that this
	 *         specific relationship is included in signature (for details see
	 *         ECMA376-2 13.2.4.24)
	 * @throws XMLSignatureException
	 * @throws MarshalException
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 * @throws OpenXML4JException
	 */
	public List<PackageRelationshipSelector> getSignedRelationshipSelectors()
			throws OpenXML4JException, SAXException, IOException,
			ParserConfigurationException, MarshalException,
			XMLSignatureException {
		if (!isVerified) {
			Verify();
		}
		return this.signedRelationshipSelectors;
	}

	/**
	 * NOTE : if any overload of Verify has not been called yet , this getter
	 * will call Verify() to try to verify signature using certificate (public
	 * key) found in a package
	 * 
	 * @return true if signature passed CORE VALIDATION , false otherwise
	 * @throws MarshalException
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 * @throws OpenXML4JException
	 * @throws XMLSignatureException
	 */
	public boolean getIsSignatureValid() throws OpenXML4JException,
			SAXException, IOException, ParserConfigurationException,
			MarshalException, XMLSignatureException {
		if (!isVerified) {
			Verify();
		}

		return isSignatureValid;
	}

	/**
	 * NOTE : if any overload of Verify has not been called yet , this getter
	 * will call Verify() to try to verify signature using certificate (public
	 * key) found in a package
	 * 
	 * @return xmlsignature object
	 * @throws MarshalException
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 * @throws OpenXML4JException
	 * @throws XMLSignatureException
	 */
	public XMLSignature getSignature() throws OpenXML4JException, SAXException,
			IOException, ParserConfigurationException, MarshalException,
			XMLSignatureException {
		if (!isVerified) {
			Verify();
		}

		return signature;
	}

	/**
	 * 
	 * @return package part that holds signature
	 */
	public PackagePart getSignaturePart() {
		return signaturePart;
	}

	/**
	 * gets PackageDigitalSignatureManager object associated with this signature
	 * 
	 * @return
	 */
	public PackageDigitalSignatureManager getManager() {
		return this.manager;
	}

	/**
	 * gets the signer certificate.
	 * 
	 * If last verification was done using call to Verify(X509Certificate)
	 * method it will return passed in certificate to Verify(X509Certificate)
	 * method iff certificate passed validates signature. Otherwise it will
	 * return certificate found in a package.
	 * 
	 * NOTE : if any overload of Verify has not been called yet , this getter
	 * will call Verify() to try to verify signature using certificate (public
	 * key) found in a package
	 * 
	 * @return
	 * @throws MarshalException
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 * @throws OpenXML4JException
	 * @throws XMLSignatureException
	 */
	public X509Certificate getSigner() throws OpenXML4JException, SAXException,
			IOException, ParserConfigurationException, MarshalException,
			XMLSignatureException {
		if (!isVerified) {
			Verify();
		}

		return signer;
	}

	/**
	 * NOTE : if any overload of Verify has not been called yet , this getter
	 * will call Verify() to try to verify signature using certificate (public
	 * key) found in a package
	 * 
	 * @return
	 * @throws OpenXML4JException
	 * @throws SAXException
	 * @throws IOException
	 * @throws ParserConfigurationException
	 * @throws MarshalException
	 * @throws XMLSignatureException
	 */
	public PublicKey getSigningPublicKey() throws OpenXML4JException,
			SAXException, IOException, ParserConfigurationException,
			MarshalException, XMLSignatureException {
		if (!isVerified) {
			Verify();
		}

		return signingPublicKey;
	}

	/**
	 * gets signature value as byte array
	 * 
	 * Note : this method will internally call getSignature() , so verify method
	 * if not called will be called implicitly
	 * 
	 * @return
	 * @throws MarshalException
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 * @throws OpenXML4JException
	 * @throws XMLSignatureException
	 */
	public byte[] getSignatureValue() throws OpenXML4JException, SAXException,
			IOException, ParserConfigurationException, MarshalException,
			XMLSignatureException {
		return this.getSignature().getSignatureValue().getValue();
	}

	static {
		// register relationship transform provider
		RelationshipTransformProvider.InstallProvider();

		// install bouncy castle security provider
		OPCSignatureHelper.InstallBouncyCastleProvider();
	}

	/**
	 * constructs the packagedigitalsignature object from given partname ponting
	 * to package digital signature.
	 * 
	 * @param pManager
	 *            PackageDigitalSignatureManager object associated with this
	 *            signature
	 * @param pPartName
	 *            partName of the signature to construct object from
	 * @throws InvalidFormatException
	 * @throws OpenXML4JException
	 *             if object can't be constructed for any reason
	 * @throws MarshalException
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 */
	public PackageDigitalSignature(PackageDigitalSignatureManager pManager,
			PackagePartName pPartName) throws InvalidFormatException,
			OpenXML4JException, SAXException, IOException,
			ParserConfigurationException, MarshalException {

		this.manager = pManager;
		this.signaturePart = pManager.getContainer().getPart(pPartName);
	}

	/**
	 * This method verifies the signature against an embedded X.509 certificate
	 * stored in the Package. CORE VALIDATION is performed.
	 * 
	 * @return VerifyResult.Success if the verification succeeded; otherwise,
	 *         one of the VerifyResult values that identifies a problem.
	 * @throws MarshalException
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 * @throws OpenXML4JException
	 * @throws XMLSignatureException
	 */
	public VerifyResult Verify() throws OpenXML4JException, SAXException,
			IOException, ParserConfigurationException, MarshalException,
			XMLSignatureException {
		return verifySignatureAndFillProperties(null);
	}

	/**
	 * Verifies the digital signature against a given X.509 certificate. CORE
	 * VALIDATION is performed
	 * 
	 * @param pSigningCertificate
	 *            The signer's X.509 certificate to verify the digital signature
	 *            against.
	 * @return VerifyResult.Success if the verification succeeded; otherwise,
	 *         one of the VerifyResult values that identifies a problem.
	 * @throws MarshalException
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 * @throws OpenXML4JException
	 * @throws XMLSignatureException
	 */
	public VerifyResult Verify(X509Certificate pSigningCertificate)
			throws OpenXML4JException, SAXException, IOException,
			ParserConfigurationException, MarshalException,
			XMLSignatureException {
		if (pSigningCertificate == null)
			throw new NullPointerException("Certificate can not be null");

		return verifySignatureAndFillProperties(pSigningCertificate);
	}

	/**
	 * parses signature part and fills values of the properties
	 * 
	 * @param pSigningCertificate
	 *            null if signing certificate is to be fetched from the package,
	 *            x509certificate if provided.
	 * @throws OpenXML4JException
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 * @throws MarshalException
	 * @throws XMLSignatureException
	 * 
	 */
	private VerifyResult verifySignatureAndFillProperties(
			X509Certificate pSigningCertificate) throws OpenXML4JException,
			SAXException, IOException, ParserConfigurationException,
			MarshalException, XMLSignatureException {

		this.isVerified = true;
		// read signature object
		XMLSignatureFactory fac = OPCSignatureHelper
				.CreateXMLSignatureFactory();

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);

                dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
                dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

		org.w3c.dom.Document doc = dbf.newDocumentBuilder().parse(
				this.signaturePart.getInputStream());

		// Find Signature element.
		NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS,
				"Signature");
		if (nl.getLength() == 0) {
			throw new OpenXML4JException("Cannot find Signature element");
		}

		Node signatureNode = nl.item(0);

		// Create a DOMValidateContext
		// if validation certificate is given try to validate using given
		// certificate
		// otherwise specify a KeySelector that will search for signing key
		// inside the signature and package
		DOMValidateContext dvc;
		if (pSigningCertificate == null) {
			OPCKeySelector keySelector = new OPCKeySelector(this);
			dvc = new DOMValidateContext(keySelector, signatureNode);
		} else {
			dvc = new DOMValidateContext(pSigningCertificate.getPublicKey(),
					signatureNode);
		}

		// set validateManifests to true to validate references inside manifests
		dvc.setProperty("org.jcp.xml.dsig.validateManifests", Boolean.TRUE);

		// set uri dereferencer to be our opc dereferencer with fallback to
		// default dereferencer
		dvc.setURIDereferencer(new OPCURIDereferencer(this.getSignaturePart()
				.getPackage(), fac.getURIDereferencer()));

		// Unmarshal the XMLSignature.
		XMLSignature sig = fac.unmarshalXMLSignature(dvc);
		if (sig != null) {
			this.signature = sig;
		}

		// validate signature
		this.isSignatureValid = sig.validate(dvc);

		// if signature is valid set signer certificate and key
		if (this.isSignatureValid) {
			// set signer certificate and public key (or just public key if
			// certificate could not be found but key is from package)
			// if we were passed signer certificate set it as it is, otherwise
			// get signer from keyselector
			if (pSigningCertificate == null) {
				OPCKeySelector keySelector = (OPCKeySelector) sig
						.getKeySelectorResult();
				this.signer = keySelector.getSigningCertificate();
				this.signingPublicKey = keySelector.getSigningPublicKey();

			} else {
				this.signer = pSigningCertificate;
				this.signingPublicKey = pSigningCertificate.getPublicKey();
			}
		}

		// get relationships and parts that are signed
		fillSignedPartsAndRelationshipsAndTimeData(this.signature);

		// TODO : needs detailed result of failure in case signature hasn't
		// passed core validation
		// return verification result
		if (this.isSignatureValid) {
			return VerifyResult.Success;
		} else {
			return VerifyResult.InvalidSignature;
		}
	}

	private void fillSignedPartsAndRelationshipsAndTimeData(
			XMLSignature pSignature) throws OpenXML4JException {
		XMLObject idPackageObject = null;
		Manifest idPackageObjectManifest = null;
		SignatureProperties idPackageObjectSignatureProperties = null;

		// find package object
		for (Object o : pSignature.getObjects()) {
			if (o instanceof XMLObject) {
				XMLObject xmlObj = (XMLObject) o;
				if (xmlObj.getId().equalsIgnoreCase(
						PackageDigitalSignature.PackageObjectIdentifier)) {
					// found package object

					// check if we already have package object, throw exception
					// if we do by [M6.7]
					if (idPackageObject != null) {
						throw new OpenXML4JException(
								"found multiple package objects");
					}

					idPackageObject = xmlObj;
				}
			}
		}

		if (idPackageObject == null) {
			// [M6.8]. Package specific object not found
			throw new OpenXML4JException(
					PackageDigitalSignature.PackageObjectIdentifier
							+ " not found.");
		}

		// get manifest and signature properties from package object
		for (Object o1 : idPackageObject.getContent()) {
			// get manifest

			// if we already found signature properties and encounter second
			// signature properties object
			// or if we already found manifest and encounter second manifest
			// throw exception by [M6.8]
			if (o1 instanceof Manifest) {
				// found manifest

				// check if we already have found manifest, throw exception if
				// true
				if (idPackageObjectManifest != null) {
					throw new OpenXML4JException(
							"multiple Manifest found in package object.");
				}

				idPackageObjectManifest = (Manifest) o1;

			} else if (o1 instanceof SignatureProperties) {
				// found signatureproperties

				// check if we already have found manifest, throw exception if
				// true
				if (idPackageObjectSignatureProperties != null) {
					throw new OpenXML4JException(
							"multiple SignatureProperties found in package object.");
				}

				idPackageObjectSignatureProperties = (SignatureProperties) o1;
			} else {
				// we found something that is not signatureproperties nor
				// manifest
				// throw exception by [M6.8]
				throw new OpenXML4JException(
						"package object contains element that is not manifest nor signatureproperties");
			}
		}

		if (idPackageObjectManifest == null) {
			// [M6.8]. Package specific object should contain manifest
			throw new OpenXML4JException("Manifest not found in package object");
		}

		if (idPackageObjectSignatureProperties == null) {
			// [M6.8]. Package specific object should contain
			// SignatureProperties
			throw new OpenXML4JException(
					"SignatureProperties not found in package object");
		}

		// now we have manifest and signature properties, parse manifest to find
		// relationships and parts signed
		// parse signatureproperties to find time and time format
		fillSignedPartsAndRelationships(idPackageObjectManifest);
		fillTimeData(idPackageObjectSignatureProperties);
	}

	/**
	 * find and fill signed parts and relationships from given package object
	 * manifest TODO : very large method, needs refactoring
	 * 
	 * @param pPackageObjectManifest
	 * 
	 * @throws OpenXML4JException
	 */
	private void fillSignedPartsAndRelationships(Manifest pPackageObjectManifest)
			throws OpenXML4JException {

		URI partURI;
		String contentType;
		PackagePart currentPart;

		for (Object o : pPackageObjectManifest.getReferences()) {
			partURI = null;
			contentType = null;
			currentPart = null;

			Reference ref = (Reference) o;
			if (!ref.getURI().startsWith("/")) {
				// reference URI points to resource outside package. throw
				// exception by [M.9]
				throw new OpenXML4JException(
						"Reference inside Manifest of package object references to resource outside the package");
			}

			// parse URI to get part name and part content type
			String[] splittedURI = ref.getURI().split("\\?");
			if (splittedURI.length != 2) {
				// we should have 2 parts after splitting uri, first for part
				// name, the second for contenttype [M6.10]
				throw new OpenXML4JException(
						"Reference inside Manifest of package object is not well formed. URI is : "
								+ ref.getURI());
			}

			// check if part URI has fragment identifier, throw exception if
			// does by [M6.18]
			if (splittedURI[0].contains("#")) {
				throw new OpenXML4JException(
						"Reference inside of package object can't contain fragment identifier. URI is : "
								+ ref.getURI());
			}

			// construct part URI
			try {
				partURI = new URI(splittedURI[0]);
			} catch (URISyntaxException e) {
				throw new OpenXML4JException(
						"package part URI specified in reference is not valid URI. URI is : "
								+ ref.getURI());
			}

			// construct contenttype by splitting second part of reference URI
			// on "="
			String[] splittedContentTypePart = splittedURI[1].split("=");
			if (splittedContentTypePart.length != 2) {
				// we should have 2 parts after splitting content type part of
				// reference uri, first for ContentType word, second for value
				// of contenttype [M6.10]
				throw new OpenXML4JException(
						"package part URI specified in reference does not have valid ContentType. URI is : "
								+ ref.getURI());
			}

			// check if first part is equal to ContentType [M6.10]
			if (!splittedContentTypePart[0].equalsIgnoreCase("ContentType")) {
				throw new OpenXML4JException(
						"package part URI specified in reference does not have valid ContentType. URI is : "
								+ ref.getURI());
			}

			// now get contenttype
			contentType = splittedContentTypePart[1];

			// get current part we aare dealing with
			currentPart = this.signaturePart.getPackage().getPart(
					PackagingURIHelper.createPartName(partURI));

			// check if contenttype of a part is equal to specified content type
			// in case sensitive manner
			// throw exception if does not by [M6.11]
			if (!currentPart.getContentType().equals(contentType)) {
				throw new OpenXML4JException(
						"content type specified in reference does not match the actual content type of a part. Reference URI is : "
								+ ref.getURI());
			}

			// if it's relationship part add to signed relationships
			// otherwise add it to signed parts
			if (contentType.equals(ContentTypes.RELATIONSHIPS_PART)) {
				// we are dealing with reference to relationship part

				// first validate transforms according to [M6.12], [M6.13],
				// [M6.26], [M6.35]
				boolean isRelationshipTransformFound = false;
				boolean isC14NTransformFound = false;
				for (Object oT : ref.getTransforms()) {
					Transform tran = (Transform) oT;

					// note : [M6.26]'s "immediately" clause is ensured by the
					// fact that after we found
					// relationship transform the only clause that
					// will not throw exception is the c14n transform.

					if (tran
							.getAlgorithm()
							.equalsIgnoreCase(
									RelationshipTransformProvider.RelationShipTransformAlgorithm)) {

						// we found relationship transform

						// check if we already had found relationship transform
						// throw exception if this is second relationship
						// transform by [M6.35].
						if (isRelationshipTransformFound) {
							throw new OpenXML4JException(
									"Reference contains multiple relationship transforms for single part "
											+ partURI.toString());
						}

						// set flag
						isRelationshipTransformFound = true;

					} else if (tran.getAlgorithm().equalsIgnoreCase(
							CanonicalizationMethod.INCLUSIVE)
							|| tran
									.getAlgorithm()
									.equalsIgnoreCase(
											CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS)
							|| tran.getAlgorithm().equalsIgnoreCase(
									CanonicalizationMethod.EXCLUSIVE)
							|| tran
									.getAlgorithm()
									.equalsIgnoreCase(
											CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS)) {

						// we found c14n transform, set flag
						isC14NTransformFound = true;

					} else {
						// we found some transform that is not c14n or
						// relationship transform, throw
						// exception by [M6.12]
						throw new OpenXML4JException(
								"Reference element inside Manifest specifies transform that is not supported. Transform algorithm : "
										+ tran.getAlgorithm());
					}
				}

				// check if we found relationship transform and not c14n
				// transform
				// if that's the case throw exception by [M6.13]
				if (isRelationshipTransformFound && !isC14NTransformFound) {
					throw new OpenXML4JException(
							"Reference contains Relationship transform not followed by c14n transform. Reference URI is : "
									+ ref.getURI());
				}

				// find the relationship source part (that is : to which
				// part this relationship is attached)
				// A special naming convention is used for the
				// Relationships part.
				// First, the Relationships part for a part in a given
				// folder in the name hierarchy is stored in a
				// sub-folder called
				// _rels. Second, the name of the Relationships part
				// is formed by appending .rels to the name of the
				// original part.
				// Package relationships are found in the package
				// relationships part named /_rels/.rels. [M1.30]
				String sourceUriString = currentPart.getPartName().getName()
						.replace("/_rels", "").replace(".rels", "");

				// if we found relationship transform, it must be unique and it
				// must be the first in transforms (asserted above)
				// parse to get transform element and parameters.
				// unfortunately this has to be done by parsing xml not as
				// xmlsignature structure, but as a dom since transform does not
				// let access subnodes (or maybe better way ?)
				if (isRelationshipTransformFound) {
					// get attribute (URI)
					Attr refURIAttrNode = (Attr) ((DOMReference) ref).getHere();
					// get reference (element owning URI attr)
					Element refElem = refURIAttrNode.getOwnerElement();
					// get first child (which is transforms)
					Element allTransforms = (Element) refElem.getFirstChild();
					// get first child of transforms (which is relationship
					// transform by above)
					Element relTransfElem = (Element) allTransforms
							.getFirstChild();

					NodeList transformparams = relTransfElem.getChildNodes();
					if (transformparams == null
							|| transformparams.getLength() == 0) {
						// relationship transform does not have any subnodes
						// (transform element), so there's no parameter !! throw
						// exception
						throw new OpenXML4JException(
								"Relationship transform specified , but no parameters given to relationship transform. Reference URI is : "
										+ ref.getURI());
					}

					// create package relationship selector for this
					// reference
					PackageRelationshipSelector pkgRelSel = null;
					try {
						pkgRelSel = new PackageRelationshipSelector(new URI(
								sourceUriString), currentPart.getPartName());
					} catch (URISyntaxException e) {
						throw new OpenXML4JException(
								"Relationship part name does not follow relationships part naming conventions. Relationship part name : "
										+ currentPart.getPartName().toString());
					}

					// now get all childnodes of transform and add to
					// packagerelationshipselector's identifiers

					for (int i = 0; i < transformparams.getLength(); i++) {

						RelationshipIdentifier relIdent = null;
						Node tempNode = null;

						// either SourceId or SourceType should be present as
						// attribute
						NamedNodeMap nl = transformparams.item(i)
								.getAttributes();
						tempNode = nl
								.getNamedItem(RelationshipTransformService.RELATIONSHIP_REFERENCE_SOURCE_ID_ATTR_NAME);

						if (tempNode != null) {
							// found sourceId
							// create RelationshipIdentifier filtered by
							// sourceId
							relIdent = new RelationshipIdentifier(
									PackageRelationshipSelectorType.Id,
									tempNode.getNodeValue());
							pkgRelSel.addRelationshipIdentifier(relIdent);
							continue;
						}

						// if sourceId not found search for SourceType
						tempNode = nl
								.getNamedItem(RelationshipTransformService.RELATIONSHIP_REFERENCE_SOURCE_TYPE_ATTR_NAME);
						if (tempNode != null) {
							// found SourceType
							// create RelationshipIdentifier filtered by
							// SourceType
							relIdent = new RelationshipIdentifier(
									PackageRelationshipSelectorType.Type,
									tempNode.getNodeValue());
							pkgRelSel.addRelationshipIdentifier(relIdent);
							continue;
						}

						// if neither sourceId nor SourceType found , something
						// is wrong throw exception
						throw new OpenXML4JException(
								"Relationship transform parameter found but neither SourceId nor SourceType is not specified.");
					}

					// add package relationship selector to list
					ensureSignedRelationshipSelectors();
					this.signedRelationshipSelectors.add(pkgRelSel);
				} else {
					// no relationship transform is found, which would mean that
					// all relationships in relationship part referenced
					// are included
					// create package relationship selector for this
					// reference that with isAllRelationshipsIncluded flag set
					// to true
					PackageRelationshipSelector pkgRelSel = null;
					try {
						pkgRelSel = new PackageRelationshipSelector(new URI(
								sourceUriString), currentPart.getPartName(),
								true);
					} catch (URISyntaxException e) {
						throw new OpenXML4JException(
								"Relationship part name does not follow relationships part naming conventions. Relationship part name : "
										+ currentPart.getPartName().toString());
					}

					// add package relationship selector to list
					ensureSignedRelationshipSelectors();
					this.signedRelationshipSelectors.add(pkgRelSel);
				}
			} else {
				// we are dealing with reference to part
				PartIdentifier currentPartIdentifier = new PartIdentifier(
						partURI, contentType);

				// make sure signed parts collection is initialized
				ensureSignedParts();

				this.signedParts.add(currentPartIdentifier);
			}

		}
	}

	/**
	 * find and fill time and time format from given package object
	 * signatureproperties
	 * 
	 * @param pPackageSignatureProperties
	 * 
	 * @throws OpenXML4JException
	 */
	private void fillTimeData(SignatureProperties pPackageSignatureProperties)
			throws OpenXML4JException {

		SignatureProperty idSignatureTimeProperty = null;
		Node signatureTimeNode = null;

		// check constraints by [M6.14]
		// NOTE : SignatureProperties can contain multiple SignatureProperty
		// elements by [M6.8]
		List propList = pPackageSignatureProperties.getProperties();
		for (Object o : propList) {
			SignatureProperty sigProp = (SignatureProperty) o;
			if (sigProp.getId().equalsIgnoreCase(
					PackageDigitalSignature.SignatureTimeIdentifier)) {
				// we found our signature time property
				idSignatureTimeProperty = sigProp;
				break;
			}
		}

		// check if we have found signature time property, throw exception
		// otherwise by [M6.14]
		if (idSignatureTimeProperty == null) {
			throw new OpenXML4JException(
					"SignatureProperties does not contain SignatureProperty with id : "
							+ PackageDigitalSignature.SignatureTimeIdentifier);
		}

		// check if our found signature properties target is either empty or
		// contain a fragment reference to the value of the root
		// signatureelement , throw exception if neither by [M6.14]
		if (!idSignatureTimeProperty.getTarget().equals("")
				&& !idSignatureTimeProperty.getTarget().equalsIgnoreCase(
						"#" + this.signature.getId())) {
			throw new OpenXML4JException(
					"Target attribute of Signature Time Property should be either empty or contain a fragment reference to the value of id attribute of the root Signature Element. Found target is : "
							+ idSignatureTimeProperty.getTarget());
		}

		// check if it has exactly one child, throw exception if not by [M6.14]
		if (idSignatureTimeProperty.getContent().size() != 1) {
			throw new OpenXML4JException(
					"Signature Time Property should contain exactly one SignatureTime child element. Multiple child elements foind for signature property");
		}

		// get signature time
		signatureTimeNode = ((DOMStructure) idSignatureTimeProperty
				.getContent().get(0)).getNode();

		// check if its SignatureTime element, throw exception if not by [M6.14]
		if (!signatureTimeNode.getLocalName().equalsIgnoreCase(
				PackageDigitalSignature.SignatureTimeElementName)) {
			throw new OpenXML4JException(
					"Signature Time Property should contain exactly one SignatureTime child element. SignatureTime element not found as a child to property");
		}

		// [M6.23] conformance check ?
		// [M6.24] conformance check ?

		// retrieve format and value of signature time
		for (int i = 0; i < signatureTimeNode.getChildNodes().getLength(); i++) {
			Node tempNode = signatureTimeNode.getChildNodes().item(i);
			if (tempNode.getLocalName().equalsIgnoreCase(
					PackageDigitalSignature.SignatureTimeFormatElementName)) {
				// we got format,get text content and assing to property
				this.timeFormat = tempNode.getTextContent();
			}
			if (tempNode.getLocalName().equalsIgnoreCase(
					PackageDigitalSignature.SignatureTimeValueElementName)) {
				// we got format,get text content and assing to property
				this.signingTimeStringValue = tempNode.getTextContent();
			}
		}
	}

	/**
	 * makes sure signedparts collection is initialized
	 */
	private void ensureSignedParts() {
		if (this.signedParts == null) {
			this.signedParts = new ArrayList<PartIdentifier>();
		}
	}

	/**
	 * makes sure signedrelationshipselectors collection is initialized
	 */
	private void ensureSignedRelationshipSelectors() {
		if (this.signedRelationshipSelectors == null) {
			this.signedRelationshipSelectors = new ArrayList<PackageRelationshipSelector>();
		}
	}

}
