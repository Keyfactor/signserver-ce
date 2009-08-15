/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.signserver.module.odfsigner;

import java.security.PrivateKey;
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
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;

import org.odftoolkit.odfdom.doc.OdfDocument;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Helper class for odf reference and signature generation
 * 
 * @author Aziz Göktepe
 *
 */
public class ODFSignatureHelper {

	/**
	 * creates documentsignatres.xml documents content.
	 * 
	 * @param fac
	 *            - XMLSignatureFactory to use (to avoid recreation)
	 * @param pOdfDocument
	 *            - document to sign
	 * @param pKeyInfo
	 *            - keyinfo to include in signature
	 * @param pPrivateKey
	 *            - private key signing document
	 * 
	 * @return
	 * @throws Exception
	 */
	public static Document CreateDigitalSignatureDocument(
			XMLSignatureFactory fac, OdfDocument pOdfDocument,
			KeyInfo pKeyInfo, PrivateKey pPrivateKey) throws Exception {
		// identify parts to be signed
		List<ODFPartIdentifier> partsToSign = IdentifyPartsToBeSigned(pOdfDocument);

		// create document to hold signature document
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		org.w3c.dom.Document signatureDoc = dbf.newDocumentBuilder()
				.newDocument();

		// c14n transform to be used in all references that refer to media-type
		// text/xml
		CanonicalizationMethod cm = fac.newCanonicalizationMethod(
				CanonicalizationMethod.INCLUSIVE,
				(C14NMethodParameterSpec) null);

		// list of references to be included in manifest
		List<Reference> signedInfoReferences = new Vector<Reference>();

		// add references to parts
		// if part's media type is text/xml add c14n transform, otherwise not
		// (for example pictures will be digested as raw octet stream)
		for (ODFPartIdentifier tempPart : partsToSign) {

			List<Transform> transforms = null;
			if (tempPart.getMediaType()
					.equals(ODFConstants.MEDIA_TYPE_TEXT_XML)) {
				transforms = new Vector<Transform>();
				transforms.add(cm);
			}

			Reference refPart = fac.newReference(tempPart.getFullPath(), fac
					.newDigestMethod(DigestMethod.SHA1, null), transforms,
					null, null);

			// add to signedInfo references
			signedInfoReferences.add(refPart);
		}

		// create Signature Properties
		SignatureProperties signatureProperties = createSignatureProperties(
				fac, signatureDoc);

		// add object to hold signatureproperties
		List<XMLStructure> signaturePropertiesObjectContent = new ArrayList<XMLStructure>();
		signaturePropertiesObjectContent.add(signatureProperties);

		XMLObject signaturePropertiesObject = fac.newXMLObject(
				signaturePropertiesObjectContent, null, null, null);

		List<XMLObject> signatureObjects = new Vector<XMLObject>();
		signatureObjects.add(signaturePropertiesObject);

		// create signature properties reference
		Reference refSignatureProperties = fac.newReference("#"
				+ ODFConstants.ID_SIGNATURE_PROPERTY_DATETIME, fac
				.newDigestMethod(DigestMethod.SHA1, null), null, null, null);

		signedInfoReferences.add(refSignatureProperties);

		// construct signedinfo
		SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(
				CanonicalizationMethod.INCLUSIVE,
				(C14NMethodParameterSpec) null), fac.newSignatureMethod(
				SignatureMethod.RSA_SHA1, null), signedInfoReferences);

		XMLSignature signature = fac.newXMLSignature(si, pKeyInfo,
				signatureObjects, ODFConstants.ID_SIGNATIRE, null);

		DOMSignContext dsc = new DOMSignContext(pPrivateKey, signatureDoc);

		// set ODF URI dereferencer as default URI dereferencer with fallback to
		// original dereferencer
		dsc.setURIDereferencer(new ODFURIDereferencer(pOdfDocument, fac
				.getURIDereferencer()));

		// actually sign
		signature.sign(dsc);

		// create document signature Document
		// observed : signature xml is contained within this document, under
		// document-signatures node
		org.w3c.dom.Document documentSignaturesDoc = dbf.newDocumentBuilder()
				.newDocument();

		Element documentSignaturesElement = documentSignaturesDoc
				.createElementNS(ODFConstants.NMS_URI_DOCUMENT_SIGNATURES,
						ODFConstants.NODE_NAME_DOCUMENT_SIGNATURES);

		// import signatureDoc into the newly documentsignatures doc
		Node tempNode = documentSignaturesDoc.importNode(signatureDoc
				.getFirstChild(), true);
		documentSignaturesElement.appendChild(tempNode);

		documentSignaturesDoc.appendChild(documentSignaturesElement);

		return documentSignaturesDoc;
	}

	/**
	 * this method identifies which parts (in OPC terminology) should be
	 * included in signature creation. observe : Each part that is not a
	 * directory should be included.
	 * 
	 * Each included part's reference is calculated by looking at the media-type
	 * of the part.if media-type says it is text/xml then x14n transform is
	 * applied. Otherwise it is digested as octet-data
	 * 
	 * 
	 * @param pOdfDoc
	 *            - OdfTextDocument to be signed
	 * @return
	 * @throws Exception
	 */
	public static List<ODFPartIdentifier> IdentifyPartsToBeSigned(
			OdfDocument pOdfDoc) throws Exception {

		List<ODFPartIdentifier> partsToSign = new Vector<ODFPartIdentifier>();

		// trying to identify parts to sign
		// as is observed the parts to be signed are all parts that are not
		// directory (that is the full-path attribute not ending with /)
		// also do not include the documentsignatures.xml
		Document doc = pOdfDoc.getPackage().getDom(
				ODFConstants.PATH_TO_MANIFEST_XML);

		// 1st dimension is enough do not recurse
		NodeList childNodes = doc.getFirstChild().getChildNodes();
		for (int i = 0, size = childNodes.getLength(); i < size; i++) {
			Node tempNode = childNodes.item(i);

			NamedNodeMap attrNodeList = tempNode.getAttributes();
			if (attrNodeList != null) {
				Node fullPathAttrNode = attrNodeList.getNamedItemNS(
						ODFConstants.NMS_URI_MANIFEST,
						ODFConstants.ATTR_NAME_FULL_PATH);
				Node mediaTypeAttrNode = attrNodeList.getNamedItemNS(
						ODFConstants.NMS_URI_MANIFEST,
						ODFConstants.ATTR_NAME_MEDIA_TYPE);
				if (fullPathAttrNode != null) {
					if (!fullPathAttrNode.getNodeValue().endsWith("/")
							&& !fullPathAttrNode
									.getNodeValue()
									.equalsIgnoreCase(
											ODFConstants.PATH_TO_DOCUMENT_SIGNATURE)) {
						ODFPartIdentifier tempPart = new ODFPartIdentifier(
								fullPathAttrNode.getNodeValue(),
								mediaTypeAttrNode.getNodeValue());
						partsToSign.add(tempPart);
					}
				}
			}
		}

		return partsToSign;
	}

	/**
	 * Adds document signature part to package. Also adds required file entries
	 * into the manifest file
	 * 
	 * @param pOdfDoc
	 * @param pDocumentSignaturePartContent
	 * @throws Exception
	 */
	public static void AddDocumentSignaturePart(OdfDocument pOdfDoc,
			Document pDocumentSignaturePartContent) throws Exception {

		// add part to package

		pOdfDoc.getPackage().insert(pDocumentSignaturePartContent,
				ODFConstants.PATH_TO_DOCUMENT_SIGNATURE, null);

		// add file entry to manifest to point to newly added part
		// observed : media-type is empty string (why not txt/xml ?)
		addEntryToManifest(pOdfDoc, ODFConstants.PATH_TO_DOCUMENT_SIGNATURE, "");

		// add file entry to manifest to point to manifest directory
		addEntryToManifest(pOdfDoc, ODFConstants.PATH_TO_META_INF_DIR, "");
	}

	/**
	 * Adds file entry to manifest for the specified part with specified
	 * media-type
	 * 
	 * if file entry already exists (same path and media type) it is not added
	 * 
	 * @param pOdfDoc
	 *            - Odf document to be signed
	 * @param pPartPath
	 *            - full path of file entry
	 * @param pMediaType
	 *            - media type of file entry to add
	 * @throws Exception
	 */
	private static void addEntryToManifest(OdfDocument pOdfDoc,
			String pPartPath, String pMediaType) throws Exception {

		Document doc = pOdfDoc.getPackage().getDom(
				ODFConstants.PATH_TO_MANIFEST_XML);
		Node firstChild = doc.getFirstChild();

		NodeList childNodes = firstChild.getChildNodes();
		for (int i = 0, size = childNodes.getLength(); i < size; i++) {
			Node tempNode = childNodes.item(i);
			NamedNodeMap attrNodeList = tempNode.getAttributes();
			if (attrNodeList != null) {
				Node fullPathAttrNode = attrNodeList.getNamedItemNS(
						ODFConstants.NMS_URI_MANIFEST,
						ODFConstants.ATTR_NAME_FULL_PATH);
				Node mediaTypeAttrNode = attrNodeList.getNamedItemNS(
						ODFConstants.NMS_URI_MANIFEST,
						ODFConstants.ATTR_NAME_MEDIA_TYPE);
				if (fullPathAttrNode != null) {
					if (fullPathAttrNode.getNodeValue().equalsIgnoreCase(
							pPartPath)
							&& mediaTypeAttrNode.getNodeValue()
									.equalsIgnoreCase(pMediaType)) {
						return;
					}
				}
			}
		}

		Element newElement = doc.createElementNS(ODFConstants.NMS_URI_MANIFEST,
				ODFConstants.NODE_NAME_FILE_ENTRY);
		newElement.setPrefix(ODFConstants.NMS_PREFIX_MANIFEST);
		newElement.setAttributeNS(ODFConstants.NMS_URI_MANIFEST,
				ODFConstants.ATTR_NAME_MEDIA_TYPE, pMediaType);
		newElement.setAttributeNS(ODFConstants.NMS_URI_MANIFEST,
				ODFConstants.ATTR_NAME_FULL_PATH, pPartPath);

		firstChild.appendChild(newElement);
	}

	/**
	 * TODO: BETTER HANDLING NEEDED
	 * 
	 * creates signature properties to be included in signature document.
	 * signature properties element has single signature property element
	 * holding date and time of signature
	 * 
	 * @param fac
	 *            - XMLSignatureFactory to be used (not to create again and
	 *            again)
	 * @param pSignatureDoc
	 *            - document containing signature data (constructed so far)
	 * @return
	 */
	private static SignatureProperties createSignatureProperties(
			XMLSignatureFactory fac, Document pSignatureDoc) {

		Calendar now = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
		Date signingTime = now.getTime();

		String signatureDateTimeFormatString = "yyyy-MM-dd'T'HH:mm:ss";
		SimpleDateFormat sdf = new SimpleDateFormat(
				signatureDateTimeFormatString);

		String dateFriendly = sdf.format(signingTime);

		// signature time
		Element signDateTimeElement = pSignatureDoc.createElementNS(
				ODFConstants.NMS_URI_SIGNATURE_PROPERTY_DATETIME_DATE_ELEM,
				ODFConstants.NODE_NAME_SIGNATURE_PROPERTY_DATETIME_DATE);

		signDateTimeElement
				.setPrefix(ODFConstants.NMS_PREFIX_SIGNATURE_PROPERTY_DATETIME_DATE_ELEM);

		// explicitly add namespace so it is not omitted during c18n
		signDateTimeElement
				.setAttributeNS(
						"http://www.w3.org/2000/xmlns/",
						"xmlns:"
								+ ODFConstants.NMS_PREFIX_SIGNATURE_PROPERTY_DATETIME_DATE_ELEM,
						ODFConstants.NMS_URI_SIGNATURE_PROPERTY_DATETIME_DATE_ELEM);

		signDateTimeElement.appendChild(pSignatureDoc
				.createTextNode(dateFriendly));

		List<DOMStructure> signaturePropertiesElems = new ArrayList<DOMStructure>();
		signaturePropertiesElems.add(new DOMStructure(signDateTimeElement));

		SignatureProperty signatureProperty = fac.newSignatureProperty(
				signaturePropertiesElems, "#" + ODFConstants.ID_SIGNATIRE,
				ODFConstants.ID_SIGNATURE_PROPERTY_DATETIME);

		SignatureProperties signatureProperties = fac.newSignatureProperties(
				Collections.singletonList(signatureProperty), null);

		return signatureProperties;
	}
}
