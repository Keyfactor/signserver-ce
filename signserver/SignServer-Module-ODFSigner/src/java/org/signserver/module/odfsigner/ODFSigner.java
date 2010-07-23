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
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.util.encoders.Hex;
import org.ejbca.util.CertTools;
import org.odftoolkit.odfdom.crypto.dsig.DocumentSignatureManager;
import org.odftoolkit.odfdom.crypto.dsig.SignatureCreationMode;
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
					"Data received is not in valid odf format", e);
		}

		// get signing key and construct KeyInfo to be included in signature
		PrivateKey signingPrivateKey = getCryptoToken().getPrivateKey(
				ICryptoToken.PURPOSE_SIGN);
		X509Certificate signingCertificate = (X509Certificate) getSigningCertificate();

		// create DocumentSignatureManager with OpenOffice31CompatibilityMode
		// mode.
		// we are using OpenOffice31CompatibilityMode , because user wants to
		// see signatures (and if we are in draftv1.2 mode then open office cant
		// show signatures
		// because openoffice expects signatures to be placed in
		// META-ING/documentsignatures.xml file)
		DocumentSignatureManager dsm = new DocumentSignatureManager(odfDoc,
				SignatureCreationMode.OpenOffice31CompatibilityMode);

		// sign document
		// pForceCreateNewSignatureGroup parameter is false , because we are in
		// OpenOffice31CompatibilityMode
		try {
			dsm.SignDocument(signingPrivateKey, signingCertificate, false);
		} catch (Exception e) {
			throw new SignServerException("Problem signing odf document", e);
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
