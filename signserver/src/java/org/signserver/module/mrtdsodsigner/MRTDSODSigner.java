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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.jmrtd.SODFile;
import org.signserver.common.ArchiveData;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ISignRequest;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SODSignRequest;
import org.signserver.common.SODSignResponse;
import org.signserver.common.SignServerException;
import org.signserver.common.SignerStatus;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.signers.BaseSigner;

/**
 * A Signer signing creating a signed SOD file to be stored in ePassports.
 *
 * Properties:
 * <ul>
 *  <li>DIGESTALGORITHM = Message digest algorithm that is applied or should be applied to the values. (Optional)</li>
 *  <li>SIGNATUREALGORITHM = Signature algorithm for signing the SO(d), should match
 *  the digest algorithm. (Optional)</li>
 *  <li>DODATAGROUPHASHING = True if this signer first should hash to values. Otherwise
 * the values are assumed to be hashes</li>
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

    /** Determines if the the data group values should be hashed by the signer. If false we assume they are already hashed. */
    private static final String PROPERTY_DODATAGROUPHASHING = "DODATAGROUPHASHING";

    /** Default value if the data group values should be hashed by the signer. */
    private static final String DEFAULT_DODATAGROUPHASHING = "false";

    private static Object syncObj = new Object();
    
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

        ICryptoToken token = getCryptoToken();
        // Trying to do a workaround for issue when the PKCS#11 session becomes invalid
        // If autoactivate is on, we can deactivate and re-activate the token.
        synchronized (syncObj) {
        	int status = token.getCryptoTokenStatus();
        	if (log.isDebugEnabled()) {
             	log.debug("Crypto token status: "+status);        		
        	}
        	if (status != SignerStatus.STATUS_ACTIVE) {
            	log.info("Crypto token status is not active, will see if we can autoactivate.");
        		String pin = config.getProperty("PIN");
        		if (pin == null) {
        			pin = config.getProperty("pin");
        		}
        		if (pin != null) {
                	log.info("Deactivating and re-activating crypto token.");
        			token.deactivate();
        			try {
        				token.activate(pin);
        			} catch (CryptoTokenAuthenticationFailureException e) {
        				throw new CryptoTokenOfflineException(e);
        			}					
        		} else {
                	log.info("Autoactivation not enabled, can not re-activate crypto token.");
        		}
        	}
        }
        X509Certificate cert = (X509Certificate) getSigningCertificate();
        PrivateKey privKey = token.getPrivateKey(ICryptoToken.PURPOSE_SIGN);
        String provider = token.getProvider(ICryptoToken.PURPOSE_SIGN);

        if (cert == null) {
            throw new CryptoTokenOfflineException("No signing certificate");
        }

        if (log.isDebugEnabled()) {
        	log.debug("Using signer certificate with subjectDN '"+CertTools.getSubjectDN(cert)+"', issuerDN '"+CertTools.getIssuerDN(cert)+", serNo "+CertTools.getSerialNumberAsString(cert));
        }
        // Construct SOD
        SODFile sod;
        try {
        	// Create the SODFile using the data group hashes that was sent to us in the request.
        	String digestAlgorithm = config.getProperty(PROPERTY_DIGESTALGORITHM, DEFAULT_DIGESTALGORITHM);
        	String digestEncryptionAlgorithm = config.getProperty(PROPERTY_SIGNATUREALGORITHM, DEFAULT_SIGNATUREALGORITHM);
        	if (log.isDebugEnabled()) {
        		log.debug("Using algorithms "+digestAlgorithm+", "+digestEncryptionAlgorithm);
        	}
        	String doHashing = config.getProperty(PROPERTY_DODATAGROUPHASHING, DEFAULT_DODATAGROUPHASHING);
        	Map<Integer, byte[]> dgvalues = sodRequest.getDataGroupHashes();
        	Map<Integer, byte[]> dghashes = dgvalues;
        	if (StringUtils.equalsIgnoreCase(doHashing, "true")) {
        		if (log.isDebugEnabled()) {
                	log.debug("Converting data group values to hashes using algorithm "+digestAlgorithm);        			
        		}
        		// If true here the "data group hashes" are not really hashes but values that we must hash.
            	// The input is already decoded (if needed) and nice, so we just need to hash it
        		dghashes = new HashMap<Integer, byte[]>(16);
        		for (Integer dgId : dgvalues.keySet()) {
        			byte[] value = dgvalues.get(dgId);
            		if (log.isDebugEnabled()) {
            			log.debug("Hashing data group "+dgId+", value is of length: "+value.length);
            		}
        			if ( (value != null) && (value.length > 0) ) {
                		MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
        				byte[] result = digest.digest(value);
                		if (log.isDebugEnabled()) {
                			log.debug("Resulting hash is of length: "+result.length);
                		}
                    	dghashes.put(dgId, result);        				
        			}
				}
        	}
            sod = new SODFile(digestAlgorithm, digestEncryptionAlgorithm, dghashes, privKey, cert, provider);
        } catch (NoSuchAlgorithmException ex) {
            throw new SignServerException("Problem constructing SOD", ex);
        } catch (CertificateException ex) {
            throw new SignServerException("Problem constructing SOD", ex);
        }

        // Verify the Signature before returning
        try {
        	if (log.isDebugEnabled()) {
        		log.debug("Verifying SOD signed by DS with issuer: "+sod.toString());
        	}
			boolean verify = sod.checkDocSignature(cert);
			if (!verify) {
				log.error("Failed to verify the SOD we signed ourselves.");
				log.error("Cert: "+cert);
				log.error("SOD: "+sod);
				throw new SignServerException("Failed to verify the SOD we signed ourselves.");
			} else {
	        	if (log.isDebugEnabled()) {
	        		log.debug("SOD verified correctly, returning SOD.");
	        	}
		        // Return response
		        byte[] signedbytes = sod.getEncoded();
		        String fp = CertTools.getFingerprintAsString(signedbytes);
		        ret = new SODSignResponse(sReq.getRequestID(), signedbytes, cert, fp, new ArchiveData(signedbytes));
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
