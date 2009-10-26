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

package org.signserver.module.ooxmlsigner;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.List;
import java.util.Vector;

import javax.persistence.EntityManager;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
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

import org.bouncycastle.util.encoders.Hex;
import org.ejbca.util.CertTools;
import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackageAccess;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.signaturehelpers.OPCSignatureHelper;
import org.openxml4j.signaturehelpers.OPCURIDereferencer;
import org.openxml4j.signaturehelpers.RelationshipTransformProvider;
import org.signserver.common.ArchiveData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericServletRequest;
import org.signserver.common.GenericServletResponse;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.ISignRequest;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.signers.BaseSigner;

/**
 * A Signer signing Open Office XML files (ECMA 376) using the openxml4j library
 * (signature patched version. Patch applied to revision 534 to
 * https://openxml4j.svn.sourceforge.net. Patched version is available at :
 * TODO: fill in temporary address in signserver svn.). 
 * 
 * Adds invisible singature to docx, xlsx, pptx files (created using MS Office 2007, or other ECMA 376 comformant application)
 *  
 * @see http://www.ecma-international.org/publications/standards/Ecma-376.htm
 * @see http://sourceforge.net/projects/openxml4j/
 * 
 * @author Aziz Göktepe
 * @version $Id$
 */
public class OOXMLSigner extends BaseSigner {

	private String signatureId = "idPackageSignature";

	@Override
	public void init(int workerId, WorkerConfig config,
			WorkerContext workerContext, EntityManager workerEM) {

		// add opc relationship transform provider
		Security.addProvider(new RelationshipTransformProvider());

		super.init(workerId, config, workerContext, workerEM);
	}

	@Override
	public ProcessResponse processData(ProcessRequest signRequest,
			RequestContext requestContext) throws IllegalRequestException,
			CryptoTokenOfflineException, SignServerException {

		ProcessResponse signResponse;
		ISignRequest sReq = (ISignRequest) signRequest;

		// Check that the request contains a valid GenericSignRequest object
		// with a byte[].
		if (!(signRequest instanceof GenericSignRequest)) {
			throw new IllegalRequestException(
					"Recieved request wasn't a expected GenericSignRequest.");
		}
		if (!(sReq.getRequestData() instanceof byte[])) {
			throw new IllegalRequestException(
					"Recieved request data wasn't a expected byte[].");
		}

		byte[] data = (byte[]) sReq.getRequestData();

		byte[] fpbytes = CertTools.generateSHA1Fingerprint(data);
		String fp = new String(Hex.encode(fpbytes));

		ByteArrayOutputStream boutTemp = new ByteArrayOutputStream();
		Package docxPackage;
		try {
			docxPackage = Package.open(new ByteArrayInputStream(data),
					PackageAccess.READ_WRITE);
		} catch (InvalidFormatException e) {
			throw new SignServerException(
					"Data received is not in valid openxml package format", e);
		} catch (IOException e) {
			throw new SignServerException("Error opening received data", e);
		}

		// openxml4j formats document when writing parts to zip, which affects
		// the signature (breaks it).
		// First "normalize" document by opening and saving, then reopen the
		// saved document to sign.

		// save output to package
		try {
			docxPackage.save(boutTemp);
		} catch (IOException e) {
			throw new SignServerException(
					"Error saving pre-formatted data to output", e);
		}

		ByteArrayInputStream binTemp = new ByteArrayInputStream(boutTemp
				.toByteArray());

		// open saved docxpackage and sign
		try {
			docxPackage = Package.open(binTemp, PackageAccess.READ_WRITE);
		} catch (InvalidFormatException e) {
			throw new SignServerException(
					"Pre-formatted data is not in valid openxml package format",
					e);
		} catch (IOException e) {
			throw new SignServerException("Error opening pre-formatted data", e);
		}

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		org.w3c.dom.Document doc;
		try {
			doc = dbf.newDocumentBuilder().newDocument();
		} catch (ParserConfigurationException e) {
			throw new SignServerException("Document parsing error", e);
		}

        // create XML signature factory (JSR-105)
        final XMLSignatureFactory fac = createXMLSignatureFactory();

		// create idpackageobject and idofficeobject reference (to add to
		// signedinfo)
		List<Reference> signedInfoReferences = new Vector<Reference>();
		Reference refIdPackageObject;
		Reference refIdOfficeObject;
		try {
			refIdPackageObject = fac.newReference("#idPackageObject", fac
					.newDigestMethod(DigestMethod.SHA1, null), null,
					"http://www.w3.org/2000/09/xmldsig#Object", null);

			refIdOfficeObject = fac.newReference("#idOfficeObject", fac
					.newDigestMethod(DigestMethod.SHA1, null), null,
					"http://www.w3.org/2000/09/xmldsig#Object", null);

		} catch (NoSuchAlgorithmException e) {
			throw new SignServerException("XML signing algorithm error", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new SignServerException(
					"XML signing algorithm parameters error", e);
		}

		signedInfoReferences.add(refIdPackageObject);
		signedInfoReferences.add(refIdOfficeObject);

		List<XMLObject> signatureObjects = new Vector<XMLObject>();

		XMLObject idPackageObject;
		try {
			idPackageObject = OPCSignatureHelper.CreateIdPackageObject(
					docxPackage, fac, signatureId, doc,
					CalculateIdPackageObjectReferences(docxPackage));
		} catch (Exception e) {
			throw new SignServerException("Error constructing idPackageObject",
					e);
		}

		XMLObject idOfficeObject = OPCSignatureHelper.CreateIdOfficeObject(fac,
				signatureId, doc);

		signatureObjects.add(idPackageObject);
		signatureObjects.add(idOfficeObject);

		PrivateKey privateKey = getCryptoToken().getPrivateKey(
				ICryptoToken.PURPOSE_SIGN);

		SignedInfo si;
		try {
			si = fac.newSignedInfo(fac.newCanonicalizationMethod(
					CanonicalizationMethod.INCLUSIVE,
					(C14NMethodParameterSpec) null), fac.newSignatureMethod(
					SignatureMethod.RSA_SHA1, null), signedInfoReferences);
		} catch (NoSuchAlgorithmException e) {
			throw new SignServerException("XML signing algorithm error", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new SignServerException(
					"XML signing algorithm parameters error", e);
		}

		KeyInfo ki = null;
		KeyInfoFactory kif = fac.getKeyInfoFactory();

		KeyValue kv;
		try {
			kv = kif.newKeyValue(getCryptoToken().getPublicKey(
					ICryptoToken.PURPOSE_SIGN));
		} catch (KeyException e) {
			throw new SignServerException(
					"Problem obtaining public key from crypto token", e);
		}

		X509Data x509d = kif.newX509Data(Collections
				.singletonList(getSigningCertificate()));

		List<XMLStructure> keyInfoContents = new Vector<XMLStructure>();
		keyInfoContents.add(kv);
		keyInfoContents.add(x509d);
		ki = kif.newKeyInfo(keyInfoContents);

		XMLSignature signature = fac.newXMLSignature(si, ki, signatureObjects,
				signatureId, null);

		DOMSignContext dsc = new DOMSignContext(privateKey, doc);

		// set OPC URI dereferencer as default URI dereferencer with fallback to
		// original dereferencer
		dsc.setURIDereferencer(new OPCURIDereferencer(docxPackage, fac
				.getURIDereferencer()));

		// actually sign
		try {
			signature.sign(dsc);
		} catch (MarshalException e) {
			throw new SignServerException("Error signing XML", e);
		} catch (XMLSignatureException e) {
			throw new SignServerException(
					"XMLSignature Exception when signing", e);
		}

		// Materialize into an xml document
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans;
		try {
			trans = tf.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new SignServerException(
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
			throw new SignServerException(
					"Problem transforming output to output stream", e);
		}

		// create digital signature origin part
		PackagePart digSigOriginPart;
		try {
			digSigOriginPart = OPCSignatureHelper
					.CreateDigitalSignatureOriginPart(docxPackage);
		} catch (Exception e) {
			throw new SignServerException(
					"Problem creating Digital Signature Origin part", e);
		}

		// create digital signature signature part
		try {
			OPCSignatureHelper.CreateDigitalSignatureSignaturePart(docxPackage,
					digSigOriginPart, bout);
		} catch (InvalidFormatException e) {
			throw new SignServerException(
					"Problem creating Digital Signature Signature Part", e);
		}

		// save output to package
		ByteArrayOutputStream boutFinal = new ByteArrayOutputStream();
		try {
			docxPackage.save(boutFinal);
		} catch (IOException e) {
			throw new SignServerException(
					"Error saving final output data to output", e);
		}

		byte[] signedbytes = boutFinal.toByteArray();

		if (signRequest instanceof GenericServletRequest) {
			signResponse = new GenericServletResponse(sReq.getRequestID(),
					signedbytes, getSigningCertificate(), fp, new ArchiveData(
							signedbytes), "application/octet-stream");
		} else {
			signResponse = new GenericSignResponse(sReq.getRequestID(),
					signedbytes, getSigningCertificate(), fp, new ArchiveData(
							signedbytes));
		}
		return signResponse;

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
	public List<Reference> CalculateIdPackageObjectReferences(
			Package docxPackage) throws Exception {

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		org.w3c.dom.Document doc = dbf.newDocumentBuilder().newDocument();

            final XMLSignatureFactory fac = createXMLSignatureFactory();

		XMLObject idPackageObject = OPCSignatureHelper.CreateIdPackageObject(
				docxPackage, fac, signatureId, doc, null);

		List<Reference> signedInfoReferences = ((Manifest) idPackageObject
				.getContent().get(0)).getReferences();

		PrivateKey privateKey = getCryptoToken().getPrivateKey(
				ICryptoToken.PURPOSE_SIGN);

		SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(
				CanonicalizationMethod.INCLUSIVE,
				(C14NMethodParameterSpec) null), fac.newSignatureMethod(
				SignatureMethod.RSA_SHA1, null), signedInfoReferences);

		KeyInfo ki = null;
		KeyInfoFactory kif = fac.getKeyInfoFactory();

		KeyValue kv = kif.newKeyValue(getCryptoToken().getPublicKey(
				ICryptoToken.PURPOSE_SIGN));

		X509Data x509d = kif.newX509Data(Collections
				.singletonList(getSigningCertificate()));

		List<XMLStructure> keyInfoContents = new Vector<XMLStructure>();
		keyInfoContents.add(kv);
		keyInfoContents.add(x509d);
		ki = kif.newKeyInfo(keyInfoContents);

		XMLSignature signature = fac.newXMLSignature(si, ki, null, signatureId,
				null);

		DOMSignContext dsc = new DOMSignContext(privateKey, doc);

		// set OPC URI dereferencer as default URI dereferencer with fallback to
		// original dereferencer
		dsc.setURIDereferencer(new OPCURIDereferencer(docxPackage, fac
				.getURIDereferencer()));

		// actually sign
		signature.sign(dsc);

		return signature.getSignedInfo().getReferences();
	}

        public static XMLSignatureFactory createXMLSignatureFactory() throws
                SignServerException {
            final String providerName = System.getProperty("jsr105Provider",
                    "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
            try {
                return XMLSignatureFactory.getInstance("DOM",
                        (Provider) Class.forName(providerName).newInstance());
            } catch (InstantiationException e) {
                throw new SignServerException("Problem with JSR105 provider",
                        e);
            } catch (IllegalAccessException e) {
                throw new SignServerException("Problem with JSR105 provider",
                        e);
            } catch (ClassNotFoundException e) {
                throw new SignServerException("Problem with JSR105 provider",
                        e);
            }
        }
}
