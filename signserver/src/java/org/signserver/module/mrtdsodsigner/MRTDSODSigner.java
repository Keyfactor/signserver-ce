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
package org.signserver.module.mrtdsodsigner;



import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.jmrtd.SODFile;
import org.signserver.common.ArchiveData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ISignRequest;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SODSignRequest;
import org.signserver.common.SODSignResponse;
import org.signserver.common.SignServerException;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.signers.BaseSigner;

/**
 * A Signer signing creating a signed SOD file to be stored in ePassports.
 *
 * Properties:
 * <ul>
 *  <li>DIGESTALGORITHM = Message digest algorithm applied to the datagroups. (Optional)</li>
 *  <li>SIGNATUREALGORITHM = Signature algorithm for signing the SO(d), should match
 *  the digest algorithm. (Optional)</li>
 * </ul>
 * 
 * @author Markus Kilas
 * @version $Id$
 */
public class MRTDSODSigner extends BaseSigner {

    private static final Logger log = Logger.getLogger(MRTDSODSigner.class);

    /** The digest algorithm, for example SHA1, SHA256. Defaults to SHA256. */
    private static final String PROPERTY_DIGESTALGORITHM = "DIGESTALGORITHM";

    /** Default value for the digestAlgorithm property */
    private static final String DEFAULT_DIGESTALGORITHM = "SHA256";

    /** The signature algorithm, for example SHA1withRSA, SHA256withRSA, SHA256withECDSA. Defaults to SHA256withRSA. */
    private static final String PROPERTY_SIGNATUREALGORITHM = "SIGNATUREALGORITHM";

    /** Default value for the signature algorithm property */
    private static final String DEFAULT_SIGNATUREALGORITHM = "SHA256withRSA";

    public ProcessResponse processData(ProcessRequest signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        if (log.isTraceEnabled()) {
            log.trace(">processData");
        }
        ProcessResponse ret = null;
        ISignRequest sReq = (ISignRequest) signRequest;

        // Check that the request contains a valid SODSignRequest object.
        if (!(signRequest instanceof SODSignRequest)) {
            throw new IllegalRequestException("Recieved request wasn't an expected SODSignRequest.");
        }
        SODSignRequest sodRequest = (SODSignRequest) signRequest;

        // Construct SOD
        SODFile sod;
        X509Certificate cert = (X509Certificate) getSigningCertificate();
        if (log.isDebugEnabled()) {
        	log.debug("Using signer certificate with subjectDN '"+CertTools.getSubjectDN(cert)+"', issuerDN '"+CertTools.getIssuerDN(cert)+", serNo "+CertTools.getSerialNumberAsString(cert));
        }
        try {
        	// Create the SODFile using the data group hashes that was sent to us in the request.
        	String digestAlgorithm = config.getProperty(PROPERTY_DIGESTALGORITHM, DEFAULT_DIGESTALGORITHM);
        	String digestEncryptionAlgorithm = config.getProperty(PROPERTY_SIGNATUREALGORITHM, DEFAULT_SIGNATUREALGORITHM);
        	if (log.isDebugEnabled()) {
        		log.debug("Using algorithms "+digestAlgorithm+", "+digestEncryptionAlgorithm);
        	}
            sod = new SODFile(digestAlgorithm, digestEncryptionAlgorithm, sodRequest.getDataGroupHashes(), getCryptoToken().getPrivateKey(ICryptoToken.PURPOSE_SIGN), cert, getCryptoToken().getProvider(ICryptoToken.PURPOSE_SIGN));
        } catch (NoSuchAlgorithmException ex) {
            throw new SignServerException("Problem constructing SOD", ex);
        } catch (CertificateException ex) {
            throw new SignServerException("Problem constructing SOD", ex);
        }

        // Verify the Signature before returning
        try {
			boolean verify = sod.checkDocSignature(cert);
			if (!verify) {
				log.error("Failed to verify the SOD we signed ourselves.");
				log.error("Cert: "+cert);
				log.error("SOD: "+sod);
				throw new SignServerException("Failed to verify the SOD we signed ourselves.");
			} else {
				log.debug("SOD verified correctly, returning SOD.");
		        // Return response
		        byte[] signedbytes = sod.getEncoded();
		        String fp = CertTools.getFingerprintAsString(signedbytes);
		        ret = new SODSignResponse(sReq.getRequestID(), signedbytes, getSigningCertificate(), fp, new ArchiveData(signedbytes));
			}
		} catch (GeneralSecurityException e) {
			log.error("Error verifying the SOD we signed ourselves. ", e);
		}

        if (log.isTraceEnabled()) {
            log.trace("<processData");
        }
        return ret;
    }
}
