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
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.persistence.EntityManager;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.util.CertTools;
import org.signserver.common.*;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SODRequest;
import org.signserver.common.data.SODResponse;
import org.signserver.common.data.WritableData;
import org.signserver.module.mrtdsodsigner.jmrtd.SODFile;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.signers.BaseSigner;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;
import org.signserver.server.HashDigestUtils;

/**
 * A Signer creating a signed Security Object Data (SOD) file to be stored in ePassports.
 *
 * Properties:
 * <ul>
 *  <li>DIGESTALGORITHM = Message digest algorithm that is applied or should be applied to the values. (Optional)</li>
 *  <li>SIGNATUREALGORITHM = Signature algorithm for signing the SO(d), should match
 *  the digest algorithm. (Optional)</li>
 *  <li>DODATAGROUPHASHING = True if this signer first should hash to values. Otherwise
 * the values are assumed to be hashes</li>
 *  <li>LDSVERSION = Version of Logical Data Structure (LDS). For LDS version 1.7 enter "0107" and for version 1.8 "0108". (Optional, default is 0107)</li>
 *  <li>UNICODEVERSION = Version of Unicode used in the datagroups. Required if LDS 1.8 is used. Example: "040000" for Unicode version 4.0.0.</li>
 * </ul>
 *
 * @author Tomas Gustavsson
 * @author Markus Kilås
 * @version $Id$
 */
public class MRTDSODSigner extends BaseSigner {

    private static final Logger log = Logger.getLogger(MRTDSODSigner.class);
    
    /** The digest algorithm, for example SHA1, SHA256. Defaults to SHA256. */
    private static final String PROPERTY_DIGESTALGORITHM = "DIGESTALGORITHM";
    
    /** Default value for the digestAlgorithm property */
    private static final String DEFAULT_DIGESTALGORITHM = "SHA256";
    
    /** The signature algorithm, for example SHA1withRSA, SHA256withRSA, SHA256withECDSA.*/
    private static final String PROPERTY_SIGNATUREALGORITHM = "SIGNATUREALGORITHM";
    
    /** Determines if the the data group values should be hashed by the signer. If false we assume they are already hashed. */
    private static final String PROPERTY_DODATAGROUPHASHING = "DODATAGROUPHASHING";
    
    /** Default value if the data group values should be hashed by the signer. */
    private static final String DEFAULT_DODATAGROUPHASHING = "false";
    
    /** Determines which version of the LDS to use. */
    private static final String PROPERTY_LDSVERSION = "LDSVERSION";
    
    /** Default value if the LDS version is not specified. */
    private static final String DEFAULT_LDSVERSION = "0107";
    
    /** Determines which version of Unicode to set. */
    private static final String PROPERTY_UNICODEVERSION = "UNICODEVERSION";
    
    private static final Object syncObj = new Object();
    
    private List<String> configErrors;
    private String signatureAlgorithm;

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        configErrors = new LinkedList<>();
        
        // Get the signature algorithm
        signatureAlgorithm = config.getProperty(PROPERTY_SIGNATUREALGORITHM, DEFAULT_NULL);

        if (hasSetIncludeCertificateLevels) {
            configErrors.add(WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS + " is not supported.");
        }
        }

    @Override
    public Response processData(Request signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        if (log.isTraceEnabled()) {
            log.trace(">processData");
        }

        // Check that the request contains a valid SODSignRequest object.
        if (!(signRequest instanceof SODRequest)) {
            throw new IllegalRequestException("Received request wasn't an expected SODSignRequest.");
        }
        
         if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }
        
        final SODRequest sodRequest = (SODRequest) signRequest;

        final IServices services = requestContext.getServices();
        final ICryptoTokenV4 token = getCryptoToken(services);
        // Trying to do a workaround for issue when the PKCS#11 session becomes invalid
        // If autoactivate is on, we can deactivate and re-activate the token.
        synchronized (syncObj) {
            int status = token.getCryptoTokenStatus(services);
            if (log.isDebugEnabled()) {
                log.debug("Crypto token status: " + status);
            }
            if (status != WorkerStatus.STATUS_ACTIVE) {
                log.info("Crypto token status is not active, will see if we can autoactivate.");
                String pin = config.getPropertyThatCouldBeEmpty("PIN");
                if (pin == null) {
                    pin = config.getPropertyThatCouldBeEmpty("pin");
                }
                if (pin != null) {
                    log.info("Deactivating and re-activating crypto token.");
                    token.deactivate(services);
                    try {
                        token.activate(pin, services);
                    } catch (CryptoTokenAuthenticationFailureException e) {
                        throw new CryptoTokenOfflineException(e);
                    }
                } else {
                    log.info("Autoactivation not enabled, can not re-activate crypto token.");
                }
            }
        }

        // Construct SOD
        final WritableData responseData = sodRequest.getResponseData();
        final SODFile sod;
        final X509Certificate cert;
        final List<Certificate> certChain;
        ICryptoInstance crypto = null;
        try {
            crypto = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, signRequest, requestContext);

            cert = (X509Certificate) getSigningCertificate(crypto);
            if (cert == null) {
                throw new CryptoTokenOfflineException("No signing certificate");
            }
            if (log.isDebugEnabled()) {
                log.debug("Using signer certificate with subjectDN '" 
                        + CertTools.getSubjectDN(cert) 
                        + "', issuerDN '" 
                        + CertTools.getIssuerDN(cert) 
                        + ", serNo " 
                        + CertTools.getSerialNumberAsString(cert));
            }
            certChain = getSigningCertificateChain(crypto);

            // Create the SODFile using the data group hashes that was sent to us in the request.
            final String digestAlgorithm = config.getProperty(PROPERTY_DIGESTALGORITHM, DEFAULT_DIGESTALGORITHM);
            final String sigAlg = signatureAlgorithm == null ? getDefaultSignatureAlgorithm(crypto.getPublicKey()) : signatureAlgorithm;
            final String digestEncryptionAlgorithm = config.getProperty(PROPERTY_SIGNATUREALGORITHM, sigAlg);
            if (log.isDebugEnabled()) {
                log.debug("Using algorithms " + digestAlgorithm + ", " + digestEncryptionAlgorithm);
            }
            final String doHashing = config.getProperty(PROPERTY_DODATAGROUPHASHING, DEFAULT_DODATAGROUPHASHING);
            final Map<Integer, byte[]> dgvalues = sodRequest.getDataGroupHashes();
            Map<Integer, byte[]> dghashes = dgvalues;
            if (StringUtils.equalsIgnoreCase(doHashing, "true")) {
                if (log.isDebugEnabled()) {
                    log.debug("Converting data group values to hashes using algorithm " + digestAlgorithm);
                }
                // If true here the "data group hashes" are not really hashes but values that we must hash.
                // The input is already decoded (if needed) and nice, so we just need to hash it
                dghashes = new HashMap<>(16);
                for (Map.Entry<Integer, byte[]> dgId : dgvalues.entrySet()) {
                    final byte[] value = dgId.getValue();
                    if (log.isDebugEnabled()) {
                        log.debug("Hashing data group " + dgId + ", value is of length: " + value.length);
                    }
                    if ((value != null) && (value.length > 0)) {
                        MessageDigest digest = MessageDigest.getInstance(digestAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
                        byte[] result = digest.digest(value);
                        if (log.isDebugEnabled()) {
                            log.debug("Resulting hash is of length: " + result.length);
                        }
                        dghashes.put(dgId.getKey(), result);
                    }
                }
            } else {
                for (Map.Entry<Integer, byte[]> dgId : dgvalues.entrySet()) {
                    final byte[] value = dgId.getValue();
                    if (log.isDebugEnabled()) {
                        log.debug("Hashing data group " + dgId + ", value is of length: " + value.length);
                    }
                    if ((value != null) && (value.length > 0)) {
                        boolean isSuppliedHashDigestLengthOk = HashDigestUtils.isSuppliedHashDigestLengthValid(digestAlgorithm, value.length);
                        if (!isSuppliedHashDigestLengthOk) {
                            throw new IllegalRequestException("Client-side hashing data length must match with the length of client specified digest algorithm");
                        }
                    }
                }
            }

            // Version values from configuration
            String ldsVersion = config.getProperty(PROPERTY_LDSVERSION,
                    DEFAULT_LDSVERSION);
            String unicodeVersion = config.getProperty(PROPERTY_UNICODEVERSION, DEFAULT_NULL);

            // Version values in request overrides configuration
            final String ldsVersionRequest = sodRequest.getLdsVersion();
            if (ldsVersionRequest != null) {
                ldsVersion = ldsVersionRequest;
            }
            final String unicodeVersionRequest = sodRequest.getUnicodeVersion();
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
                    dghashes, crypto.getPrivateKey(), cert, crypto.getProvider().getName(),
                    ldsVersion, unicodeVersion);

            // Reconstruct the sod
            sod = new SODFile(new ByteArrayInputStream(constructedSod.getEncoded()));

        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new SignServerException("Problem constructing SOD as configured algorithm not supported", ex);
        } catch(InvalidKeyException ex) {
            throw new SignServerException("Problem constructing SOD as key could not be used", ex);
        } catch(SignatureException ex) {
            throw new SignServerException("Problem constructing SOD as signature could not be made", ex);
        } catch (CertificateException ex) {
            throw new SignServerException("Problem constructing SOD", ex);
        } catch (IOException ex) {
            throw new SignServerException("Problem reconstructing SOD", ex);
        } finally {
            releaseCryptoInstance(crypto, requestContext);
        }

        // Verify the Signature before returning
        try (OutputStream out = responseData.getAsOutputStream()) {
            verifySignatureAndChain(sod, certChain);

            if (log.isDebugEnabled()) {
                log.debug("SOD verified correctly, returning SOD.");
            }
            // Return response
            final byte[] signedbytes = sod.getEncoded();
            out.write(signedbytes);
            final String archiveId = createArchiveId(signedbytes, (String) requestContext.get(RequestContext.TRANSACTION_ID));
            final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE, responseData.toReadableData(), archiveId));

            // The client can be charged for the request
            requestContext.setRequestFulfilledByWorker(true);
            
            return new SODResponse(sodRequest.getRequestID(), responseData, cert,
                    archiveId, archivables, "application/octet-stream");
        } catch (GeneralSecurityException e) {
            log.error("Error verifying the SOD we signed ourselves. ", e);
            throw new SignServerException("SOD verification failure", e);
        } catch (IOException e) {
        	log.error("Error encoding SOD", e);
        	throw new SignServerException("SOD encoding failure", e);
        }
    }

    private X509Certificate findIssuerCert(Collection<Certificate> chain, X509Certificate sodCert) {
        X509Certificate result = null;
        final X500Name issuer = JcaX500NameUtil.getIssuer(sodCert);
        if (log.isDebugEnabled()) {
            final StringBuilder buff = new StringBuilder();
            buff.append("Looking for ");
            buff.append(issuer);
            log.debug(buff.toString());
        }
        for (Certificate cert : chain) {
            if (cert instanceof X509Certificate) {
                final X509Certificate x509 = (X509Certificate) cert;
                final X500Name subject = JcaX500NameUtil.getSubject(x509);
                if (issuer.equals(subject)) {
                    result = (X509Certificate) cert;
                    if (log.isDebugEnabled()) {
                        log.debug("Found issuer");
                    }
                    break;
                } else {
                    if (log.isDebugEnabled()) {
                        final StringBuilder buff = new StringBuilder();
                        buff.append(issuer);
                        buff.append("!=");
                        buff.append(subject);
                        log.debug(buff.toString());
                    }
                }
            }
        }
        return result;
    }

    private void verifySignatureAndChain(final SODFile sod,
            final Collection<Certificate> chain) throws GeneralSecurityException {
        try {
            if (log.isDebugEnabled()) {
                final StringBuilder buff = new StringBuilder();
                buff.append("Verifying SOD signed by DS with issuer: ");
                buff.append(sod.toString());
                log.debug(buff.toString());
            }

            // Get Signer certificate from SOD
            final X509Certificate sodCert = sod.getDocSigningCertificate();

            // We need a Bouncy Castle certificate so reconstruct it
            final CertificateFactory factory
                    = CertificateFactory.getInstance("X.509", "BC");
            final X509Certificate signerCert
                    = (X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(sodCert.getEncoded()));

            // Verify the SOD signature using certificate from SOD
            final boolean consistent = sod.checkDocSignature(signerCert);
            if (!consistent) {
                log.error("Failed to verify the SOD we signed ourselves.");
                log.error("Cert: " + signerCert);
                log.error("SOD: " + sod);
                throw new GeneralSecurityException("Signature not consistent");
            }

            // Find the issuer certificate from the configured chain
            final X509Certificate issuerCert = (chain == null ? null : findIssuerCert(chain, signerCert));
            if (issuerCert == null) {
                log.error("Failed to verify certificate chain");
                log.error("Cert: " + signerCert);
                log.error("SOD Cert: " + signerCert);
                log.error("Chain: " + chain);
                throw new GeneralSecurityException("Issuer of cert not in chain");
            }

            // Verify the signer certificate using the issuer from the chain
            signerCert.verify(issuerCert.getPublicKey());
        } catch (IOException e) {
            log.error("Getting signer certificate from SOD failed", e);
            throw new GeneralSecurityException(
                    "Getting signer certificate from SOD failed", e);
        }
    }
    
    @Override
    protected List<String> getFatalErrors(IServices services) {
        final List<String> errors = super.getFatalErrors(services);
        
        errors.addAll(configErrors);
        return errors;
    }
    
    /**
     * Return the default signature algorithm name given the public key.
     *
     * @param publicKey
     * @return
     */
    private String getDefaultSignatureAlgorithm(final PublicKey publicKey) {
        String result;

        switch (publicKey.getAlgorithm()) {
            case "EC":
            case "ECDSA":
                result = "SHA256withECDSA";
                break;
            case "DSA":
                result = "SHA256withDSA";
                break;
            case "Ed25519":
                result = "Ed25519";
                break;
            case "Ed448":
                result = "Ed448";
                break;
            case "RSA":
            default:
                result = "SHA256withRSA";    
        }

        return result;
    }
}
