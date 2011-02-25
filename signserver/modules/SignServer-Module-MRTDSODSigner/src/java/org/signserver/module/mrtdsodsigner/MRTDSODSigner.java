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



import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import javax.security.auth.x500.X500Principal;
import net.sourceforge.scuba.util.Hex;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509Name;
import org.ejbca.util.CertTools;
import org.signserver.module.mrtdsodsigner.jmrtd.SODFile;
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

    private static final String PROPERTY_LDSVERSION = "LDSVERSION";

    private static final String REQUEST_LDSVERSION = "LDSVERSION";

    private static final String DEFAULT_LDSVERSION = "0107";
    
    private static final String PROPERTY_UNICODEVERSION = "UNICODEVERSION";

    private static final String REQUEST_UNICODEVERSION = "UNICODEVERSION";

    private static final String DEFAULT_UNICODEVERSION = "040000";

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

                // Version values from configuration
                String ldsVersion = config.getProperty(PROPERTY_LDSVERSION,
                        DEFAULT_LDSVERSION);
                String unicodeVersion
                        = config.getProperty(PROPERTY_UNICODEVERSION);

                // Version values in request overrides configuration
                final String ldsVersionRequest
                        = sodRequest.getLdsVersion();
                if (ldsVersionRequest != null) {
                    ldsVersion = ldsVersionRequest;
                }
                final String unicodeVersionRequest
                        = sodRequest.getUnicodeVersion();
                if (unicodeVersionRequest != null) {
                    unicodeVersion = unicodeVersionRequest;
                }

                // Check version
                if ("0107".equals(ldsVersion)) {
                    // LDS V1.7 does not supported the version fields
                    ldsVersion = null;
                    unicodeVersion = null;
                } else if ("0108".equals(ldsVersion)) {
                    // LDS V1.8 requires a unicode version
                    if (unicodeVersion == null) {
                        throw new IllegalRequestException(
                        "Unicode version must be specified in LDS version 1.8");
                    }
                } else {
                    throw new IllegalRequestException(
                            "Unsupported LDS version: " + ldsVersion);
                }
                if (log.isDebugEnabled()) {
                    log.debug("LDS version: " + ldsVersion
                            + ", unicodeVerison: " + unicodeVersion);
                }

            final SODFile constructedSod
                    = new SODFile(digestAlgorithm, digestEncryptionAlgorithm,
                    dghashes, privKey, cert, provider,
                    ldsVersion, unicodeVersion);

            // Reconstruct the sod
            sod = new SODFile(new ByteArrayInputStream(constructedSod.getEncoded()));

        } catch (NoSuchAlgorithmException ex) {
            throw new SignServerException("Problem constructing SOD", ex);
        } catch (CertificateException ex) {
            throw new SignServerException("Problem constructing SOD", ex);
        } catch (IOException ex) {
            throw new SignServerException("Problem reconstructing SOD", ex);
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
                            // Get chain and signer certificate
                            final Collection<Certificate> chain = getSigningCertificateChain();
                            final X509Certificate sodCert
                                    = sod.getDocSigningCertificate();
                            try {
                                // Find the issuer certificate and use it for verification
                                final X509Certificate issuerCert = (chain == null ? null : findIssuerCert(chain, sodCert));
                                if (issuerCert == null) {
                                    log.error("Failed to verify certificate chain");
                                    log.error("Cert: " + cert);
                                    log.error("SOD Cert: " + sodCert);
                                    log.error("Chain: " + chain);
                                    throw new GeneralSecurityException("Issuer of cert not in chain");
                                }
                                sodCert.verify(issuerCert.getPublicKey());

                                if (log.isDebugEnabled()) {
                                        log.debug("SOD verified correctly, returning SOD.");
                                }
                                // Return response
                                byte[] signedbytes = sod.getEncoded();
                                String fp = CertTools.getFingerprintAsString(signedbytes);
                                ret = new SODSignResponse(sReq.getRequestID(), signedbytes, cert, fp, new ArchiveData(signedbytes));
                            } catch (GeneralSecurityException ex) {
                                log.error("Error verifying certificate in the SOD we signed ourselves. ", ex);
                                throw new SignServerException("SOD verification failure", ex);
                            }
			}
		} catch (GeneralSecurityException e) {
			log.error("Error verifying the SOD we signed ourselves. ", e);
                        throw new SignServerException("SOD verification failure", e);
		} catch (IOException e) {
                    log.error("Error verifying the SOD we signed ourselves. ", e);
                    throw new SignServerException("SOD verification failure", e);
                }

        if (log.isTraceEnabled()) {
            log.trace("<processData");
        }
        return ret;
    }

    private X509Certificate findIssuerCert(Collection<Certificate> chain, X509Certificate sodCert) {
        X509Certificate result = null;
        final X509Name issuer = new X509Name(sodCert.getIssuerX500Principal().getName());
        log.debug("Looking for " + issuer);
        for (Certificate cert : chain) {
            if (cert instanceof X509Certificate) {
                final X509Certificate x509 = (X509Certificate) cert;
                final X509Name subject = new X509Name(x509.getSubjectX500Principal().getName());
                if (issuer.equals(subject)) {
                    result = (X509Certificate) cert;
                    log.debug("Found issuer");
                    break;
                } else {
                    log.debug(issuer + "!=" + subject);
                }
            }
        }
        return result;
    }
}
