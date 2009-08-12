package org.openxml4j.signaturehelpers;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.Vector;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;

import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.opc.ContentTypes;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackageNamespaces;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackagePartName;
import org.openxml4j.opc.PackageRelationship;
import org.openxml4j.opc.PackageRelationshipCollection;
import org.openxml4j.opc.PackageRelationshipTypes;
import org.openxml4j.opc.PackagingURIHelper;
import org.openxml4j.opc.TargetMode;
import org.w3c.dom.Element;

public class OPCSignatureHelper {

	/*
	 * creates digital signature origin part and adds it to the package. Also
	 * adds relationship to package relationship. Returns part created
	 */
	public static PackagePart CreateDigitalSignatureOriginPart(Package p)
			throws Exception {

		PackagePart digSigOriginPart = p.createPart(PackagingURIHelper
				.createPartName("/_xmlsignatures/origin.sigs"),
				ContentTypes.DIGITAL_SIGNATURE_ORIGIN_PART);

		// add digital signature origin relationship to package relationships
		p.addRelationship(digSigOriginPart.getPartName(), TargetMode.INTERNAL,
				PackageRelationshipTypes.DIGITAL_SIGNATURE_ORIGIN);

		return digSigOriginPart;
	}

	public static PackagePart CreateDigitalSignatureSignaturePart(Package p,
			PackagePart pDigSigOriginPart, ByteArrayOutputStream pContent)
			throws InvalidFormatException {
		// create digital signature part
		PackagePart digitalSignatureSignaturePart = p.createPart(
				PackagingURIHelper.createPartName("/_xmlsignatures/sig1.xml"),
				ContentTypes.DIGITAL_SIGNATURE_XML_SIGNATURE_PART, pContent);

		// add relationship to digital signature origin part
		pDigSigOriginPart.addRelationship(
				digitalSignatureSignaturePart.getPartName(), TargetMode.INTERNAL,
				PackageRelationshipTypes.DIGITAL_SIGNATURE);

		return digitalSignatureSignaturePart;
	}

	/*
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
	public static void SetPartsAndRelationshipsToSign(Package pPackage,
			List<PartIdentifier> opPartsToSign,
			List<PackageRelationshipSelector> opRelationshipsToSign)
			throws Exception {

		opPartsToSign.clear();
		opRelationshipsToSign.clear();
		PackageRelationshipCollection coreDocRelationships = pPackage
				.getRelationshipsByType(PackageRelationshipTypes.CORE_DOCUMENT);
		for (PackageRelationship relationship : coreDocRelationships) {
			RecursivelyAddSignableItems(relationship, opPartsToSign,
					opRelationshipsToSign);
		}

	}

	/*
	 * recursively adds signable items (that is add relationship and target
	 * part, and follow the added parts relationships to find more to add)
	 */
	public static void RecursivelyAddSignableItems(
			PackageRelationship pRelationship,
			List<PartIdentifier> opPartsToSign,
			List<PackageRelationshipSelector> opRelationshipsToSign)
			throws Exception {

		// A special naming convention is used for the Relationships part.
		// First, the Relationships part for a part in a given
		// folder in the name hierarchy is stored in a sub-folder called
		// “_rels”. Second, the name of the Relationships part
		// is formed by appending “.rels” to the name of the original part.
		// Package relationships are found in the package
		// relationships part named “/_rels/.rels”.
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

	/*
	 * creates idPackageObject as per ECMA372 , which hold references to all
	 * parts and relationships to be signed
	 */
	public static XMLObject CreateIdPackageObject(Package p,
			XMLSignatureFactory fac, String pSignatureId,
			org.w3c.dom.Document pSignatureDoc,
			List<Reference> denManifestReferences) throws Exception {
		// identify parts and relationships to sign
		List<PartIdentifier> partsToSign = new Vector<PartIdentifier>();
		List<PackageRelationshipSelector> relationshipsToSign = new Vector<PackageRelationshipSelector>();
		OPCSignatureHelper.SetPartsAndRelationshipsToSign(p, partsToSign,
				relationshipsToSign);

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
					relationShipIdsToInclude);

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
				"idPackageObject", null, null);

		return idPackageObject;
	}

	/*
	 * creates signature properties to be included in idPackageObject
	 */
	private static SignatureProperties createSignaturePropertiesForIdPackageObject(
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
				PackageNamespaces.DIGITAL_SIGNATURE, "SignatureTime");
		signDateTimeElement.setPrefix("mdssi");
		// explicitly add namespace so it is not omitted during c18n
		signDateTimeElement.setAttributeNS("http://www.w3.org/2000/xmlns/",
				"xmlns:mdssi", PackageNamespaces.DIGITAL_SIGNATURE);
		// format node
		Element signDateTimeFormat = pSignatureDoc.createElementNS(
				PackageNamespaces.DIGITAL_SIGNATURE, "Format");
		signDateTimeFormat.setPrefix("mdssi");
		// explicitly add namespace so it is not omitted during c18n
		signDateTimeFormat.setAttributeNS("http://www.w3.org/2000/xmlns/",
				"xmlns:mdssi", PackageNamespaces.DIGITAL_SIGNATURE);
		signDateTimeFormat.appendChild(pSignatureDoc.createTextNode(signatureDateTimeFormatString));

		// value node
		Element signDateTimeValue = pSignatureDoc.createElementNS(
				PackageNamespaces.DIGITAL_SIGNATURE, "Value");
		signDateTimeValue.setPrefix("mdssi");
		// explicitly add namespace so it is not omitted during c18n
		signDateTimeValue.setAttributeNS("http://www.w3.org/2000/xmlns/",
				"xmlns:mdssi", PackageNamespaces.DIGITAL_SIGNATURE);
		signDateTimeValue.appendChild(pSignatureDoc.createTextNode(dateFriendly));

		signDateTimeElement.appendChild(signDateTimeFormat);
		signDateTimeElement.appendChild(signDateTimeValue);

		List<DOMStructure> signaturePropertiesElems = new ArrayList<DOMStructure>();
		signaturePropertiesElems.add(new DOMStructure(signDateTimeElement));
		SignatureProperty signatureProperty = fac
				.newSignatureProperty(signaturePropertiesElems, "#"
						+ pSignatureId, "idSignatureTime");

		SignatureProperties signatureProperties = fac.newSignatureProperties(
				Collections.singletonList(signatureProperty), null);
		return signatureProperties;
	}

	/*
	 * create idOfficeObject that is required by the ms office document
	 * signature
	 */
	public static XMLObject CreateIdOfficeObject(XMLSignatureFactory fac,
			String pSignatureId, org.w3c.dom.Document pSignatureDoc) {
		Element signatureInfoV1 = pSignatureDoc.createElementNS(
				"http://schemas.microsoft.com/office/2006/digsig",
				"SignatureInfoV1");

		// explicitly add namespace so it is not omitted during c18n
		signatureInfoV1.setAttributeNS("http://www.w3.org/2000/xmlns/",
				"xmlns", "http://schemas.microsoft.com/office/2006/digsig");

		Element manifestHashAlgorithm = pSignatureDoc
				.createElement("ManifestHashAlgorithm");

		manifestHashAlgorithm.appendChild(pSignatureDoc.createTextNode("http://www.w3.org/2000/09/xmldsig#sha1"));
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

}
