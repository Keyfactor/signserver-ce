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
import java.util.Collection;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.util.CertTools;
import org.signserver.common.ArchiveData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.ISignRequest;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.RequestContext;
import org.signserver.server.cryptotokens.ICryptoToken;

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
 * @version $Id: PDFSigner.java,v 1.6 2007-12-12 14:00:06 herrvendil Exp $
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
		
	public void init(int signerId, WorkerConfig config, EntityManager em) {
		super.init(signerId, config, em);				                                 
	}

	/**
	 * The main method performing the actual signing operation.
	 * Expects the signRequest to be a GenericSignRequest containing a signed PDF file
	 * 
	 * @see org.signserver.server.signers.IProcessable#signData(org.signserver.common.ProcessRequest, java.security.cert.X509Certificate)
	 */
	public ProcessResponse processData(ProcessRequest signRequest, RequestContext requestContext) 
		throws IllegalRequestException, CryptoTokenOfflineException {
		
		ISignRequest sReq = (ISignRequest) signRequest;
		// Check that the request contains a valid GenericSignRequest object with a byte[].
		if(!(signRequest instanceof GenericSignRequest)){
			throw new IllegalRequestException("Recieved request wasn't a expected GenericSignRequest.");
		}
		if(!(sReq.getRequestData() instanceof byte[]) ) {
			throw new IllegalRequestException("Recieved request data wasn't a expected byte[].");
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
			throw new IllegalRequestException("RECTANGLE property must contain 4 comma separated values with no spaces.");			
		}
		int llx = Integer.valueOf(rect[0]);
		int lly = Integer.valueOf(rect[1]);
		int urx = Integer.valueOf(rect[2]);
		int ury = Integer.valueOf(rect[3]);
        
		// Start processing the actual signature
        GenericSignResponse signResponse = null;
			byte[] pdfbytes = (byte[])sReq.getRequestData();
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
				PrivateKey privKey = this.getCryptoToken().getPrivateKey(ICryptoToken.PURPOSE_SIGN);
				sap.setCrypto(privKey, certChain, null, PdfSignatureAppearance.WINCER_SIGNED);
				sap.setReason(reason);
				sap.setLocation(location);
				sap.setVisibleSignature(new com.lowagie.text.Rectangle(llx, lly, urx, ury), 1, null);
				stp.close();
				fout.close();
				byte[] signedbytes = fout.toByteArray();
				signResponse = new GenericSignResponse(sReq.getRequestID(), signedbytes, getSigningCertificate(), fp, new ArchiveData(signedbytes));				
			} catch (DocumentException e) {
				log.error("Error signing PDF: ", e);
				throw new IllegalRequestException("DocumentException: " + e.getMessage());
			} catch (IOException e) {
				log.error("Error signing PDF: ", e);
				throw new IllegalRequestException("IOException: " + e.getMessage());
			}
		
		return signResponse;
	}

    /**
     * Not supported yet
     */
	public ICertReqData genCertificateRequest(ISignerCertReqInfo info) throws CryptoTokenOfflineException{
		return this.getCryptoToken().genCertificateRequest(info);
	}
}


	

	 
	