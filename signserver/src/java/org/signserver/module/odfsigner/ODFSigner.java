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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyException;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.Collections;
import java.util.List;
import java.util.Vector;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.bouncycastle.util.encoders.Hex;
import org.ejbca.util.CertTools;
import org.odftoolkit.odfdom.doc.OdfDocument;
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
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.signers.BaseSigner;
import org.w3c.dom.Document;

/**
 * A signer signing Open Document Format documents (ODF 1.1) .Using odfdom
 * library to parse and modify odf documents.
 * 
 * Implementation is based on analysis of output from signature operation
 * performed by Open Office 3.1. This is due to fact that there's no place in
 * ODF standard detailing document signatures.
 * 
 * Adds invisible signature to odt,ods,odp,odg.. files (created with Open Office
 * 3.1 and respecting ODF standard)
 * 
 * @author Aziz Göktepe
 * @version $Id$
 * 
 */
public class ODFSigner extends BaseSigner {

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

		OdfDocument odfDoc;
		try {
			odfDoc = OdfDocument.loadDocument(new ByteArrayInputStream(data));
		} catch (Exception e) {
			throw new SignServerException(
					"Data received is not in valid openxml package format", e);
		}

        // create XML signature factory (JSR-105)
        final String providerName = System.getProperty("jsr105Provider",
                "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        XMLSignatureFactory fac;
        try {
            fac = XMLSignatureFactory.getInstance("DOM",
                    (Provider) Class.forName(providerName).newInstance());
        } catch (InstantiationException e) {
            throw new SignServerException("Problem with JSR105 provider", e);
        } catch (IllegalAccessException e) {
            throw new SignServerException("Problem with JSR105 provider", e);
        } catch (ClassNotFoundException e) {
            throw new SignServerException("Problem with JSR105 provider", e);
        }

		// Since ODFDOM is formatting document after a new part is added
		// (content.xml and other parts)
		// we are adding documentsignature part with trash content first, save
		// it to the output stream. Then we reopen file from stream and fill in
		// the
		// documentsignature part of the package

		// create temporary place holder content for documentsignature.xml
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		org.w3c.dom.Document doc;
		try {
			doc = dbf.newDocumentBuilder().newDocument();
		} catch (ParserConfigurationException e) {
			throw new SignServerException("Error parsing document", e);
		}

		doc.appendChild(doc.createElement("TEMP_PLACE_HOLDER"));

		// add part to package (adding necessary entries to manifes.xml too)
		try {
			ODFSignatureHelper.AddDocumentSignaturePart(odfDoc, doc);
		} catch (Exception e) {
			throw new SignServerException(
					"Error adding temporary signature part to document", e);
		}
		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		// save to output stream so all formatting by ODFDOM completes
		try {
			odfDoc.save(bos);
		} catch (Exception e) {
			throw new SignServerException(
					"Error saving document to temporary output stream", e);
		}
		odfDoc.close();

		// reopen stream to fill in documentsignatures.xml part content with
		// real content
		ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
		try {
			odfDoc = OdfDocument.loadDocument(bis);
		} catch (Exception e) {
			throw new SignServerException(
					"Error opening document from temporary input stream", e);
		}

		// get signing key and construct KeyInfo to be included in signature
		PrivateKey privateKey = getCryptoToken().getPrivateKey(
				ICryptoToken.PURPOSE_SIGN);

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

		// again add signature part to package.
		// NOTE: manifest.xml will not be changed since the required entries
		// were already added and the content of documentsignatures.xml is going
		// to be replaced with calculated signature content.
		Document outputDoc;
		try {
			outputDoc = ODFSignatureHelper.CreateDigitalSignatureDocument(fac,
					odfDoc, ki, privateKey);
		} catch (Exception e) {
			throw new SignServerException(
					"Error creating digital signature document for odf", e);
		}

		try {
			ODFSignatureHelper.AddDocumentSignaturePart(odfDoc, outputDoc);
		} catch (Exception e) {
			throw new SignServerException(
					"Error adding calculated signature part to document", e);
		}

		// save document to output stream
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		try {
			odfDoc.save(bout);
		} catch (Exception e) {
			throw new SignServerException(
					"Error saving document to output stream", e);
		}
		odfDoc.close();

		// return result
		byte[] signedbytes = bout.toByteArray();

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
}
