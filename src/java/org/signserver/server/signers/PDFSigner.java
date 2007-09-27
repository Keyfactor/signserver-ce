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

package org.signserver.server.signers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.util.CertTools;
import org.signserver.common.ArchiveData;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.ISignRequest;
import org.signserver.common.ISignResponse;
import org.signserver.common.ISignerCertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalSignRequestException;
import org.signserver.common.SignTokenOfflineException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.signtokens.ISignToken;

import com.lowagie.text.DocumentException;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
 

/**
 * A Signer signing PDF files using the IText PDF library.
 * 
 * Implements a ISigner and have the following properties:
 * REASON = The reason shown in the PDF signature
 * LOCATION = The location shown in the PDF signature
 * RECTANGLE = The location of the visible signature field (llx, lly, urx, ury)
 * 
 * @author Tomas Gustavsson
 * @version $Id: PDFSigner.java,v 1.2 2007-09-27 10:02:27 anatom Exp $
 */
public class PDFSigner extends BaseSigner{
	
    /** Log4j instance for actual implementation class */
    public transient Logger log = Logger.getLogger(this.getClass());
    
	//Private Property constants
	private static final String REASON = "REASON";
	private static final String REASONDEFAULT = "Signed by SignServer";
	private static final String LOCATION = "LOCATION";
	private static final String LOCATIONDEFAULT = "SignServer";
	private static final String RECTANGLE = "RECTANGLE";
	private static final String RECTANGLEDEFAULT = "400,700,500,800";
		
	public void init(int signerId, WorkerConfig config) {
		super.init(signerId, config);				                                 
	}

	/**
	 * The main method performing the actual signing operation.
	 * Expects the signRequest to be a GenericSignRequest containing a signed PDF file
	 * 
	 * @see org.signserver.server.signers.ISigner#signData(org.signserver.common.ISignRequest, java.security.cert.X509Certificate)
	 */
	public ISignResponse signData(ISignRequest signRequest, X509Certificate clientCert) 
		throws IllegalSignRequestException, SignTokenOfflineException {
		
		// Check that the request contains a valid GenericSignRequest object with a byte[].
		if(!(signRequest instanceof GenericSignRequest)){
			throw new IllegalSignRequestException("Recieved request wasn't a expected GenericSignRequest.");
		}
		if(!(signRequest.getSignRequestData() instanceof byte[]) ) {
			throw new IllegalSignRequestException("Recieved request data wasn't a expected byte[].");
		}
		
		// The reason shown in the PDF signature
		String reason = REASONDEFAULT;
		if(config.getProperties().getProperty(REASON) != null){
			reason = config.getProperties().getProperty(REASON);
		}
		log.debug("Using reason: "+reason);
		// The location shown in the PDF signature
		String location = LOCATIONDEFAULT;
		if(config.getProperties().getProperty(LOCATION) != null){
			location = config.getProperties().getProperty(LOCATION);
		}
		log.debug("Using location: "+location);
		// The location of the visible signature field (llx, lly, urx, ury)
		String rectangle = RECTANGLEDEFAULT;
		if(config.getProperties().getProperty(RECTANGLE) != null){
			rectangle = config.getProperties().getProperty(RECTANGLE);
		}
		log.debug("Using rectangle: "+rectangle);
		String[] rect = rectangle.split(",");
		if ( rect.length < 4) {
			throw new IllegalSignRequestException("RECTANGLE property must contain 4 comma separated values with no spaces.");			
		}
		int llx = Integer.valueOf(rect[0]);
		int lly = Integer.valueOf(rect[1]);
		int urx = Integer.valueOf(rect[2]);
		int ury = Integer.valueOf(rect[3]);
        
		// Start processing the actual signature
        GenericSignResponse signResponse = null;
			byte[] pdfbytes = (byte[])signRequest.getSignRequestData();
			byte[] fpbytes = CertTools.generateSHA1Fingerprint(pdfbytes);
			String fp = new String(Hex.encode(fpbytes));

			try {
				// Thanks to Ezizmuhamet Muhammetkuliyev for this PDF signing snippet 
				PdfReader reader = new PdfReader(pdfbytes);
				ByteArrayOutputStream fout = new  ByteArrayOutputStream();
				PdfStamper stp;
				stp = PdfStamper.createSignature(reader, fout, '\0');
				PdfSignatureAppearance sap = stp.getSignatureAppearance();
				Collection<Certificate> certs = this.getSigningCertificateChain();
				if (certs == null) {
					throw new IllegalArgumentException("Null certificate chain. This signer needs a certificate.");
				}
				Certificate[] certChain = (Certificate[])certs.toArray(new Certificate[0]);
				PrivateKey privKey = this.getSignToken().getPrivateKey(ISignToken.PURPOSE_SIGN);
				sap.setCrypto(privKey, certChain, null, PdfSignatureAppearance.WINCER_SIGNED);
				sap.setReason(reason);
				sap.setLocation(location);
				sap.setVisibleSignature(new com.lowagie.text.Rectangle(llx, lly, urx, ury), 1, null);
				stp.close();
				fout.close();
				byte[] signedbytes = fout.toByteArray();
				signResponse = new GenericSignResponse(signRequest.getRequestID(), signedbytes, getSigningCertificate(), fp, new ArchiveData(signedbytes));				
			} catch (DocumentException e) {
				log.error("Error signing PDF: ", e);
				throw new IllegalSignRequestException("DocumentException: " + e.getMessage());
			} catch (IOException e) {
				log.error("Error signing PDF: ", e);
				throw new IllegalSignRequestException("IOException: " + e.getMessage());
			}
		
		return signResponse;
	}

    /**
     * Not supported yet
     */
	public ISignerCertReqData genCertificateRequest(ISignerCertReqInfo info) throws SignTokenOfflineException{
		return this.getSignToken().genCertificateRequest(info);
	}
}


	

	 
	