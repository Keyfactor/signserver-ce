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
package org.signserver.module.cmssigner;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.common.*;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.data.impl.UploadUtil;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;
import org.signserver.server.signers.BaseSigner;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;

/**
 * A Signer signing arbitrary content and produces a plain signature.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class PlainSigner extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(PlainSigner.class);

    /** Content-type for the produced data. */
    private static final String CONTENT_TYPE = "application/octet-stream";

    // Property constants
    public static final String SIGNATUREALGORITHM_PROPERTY = "SIGNATUREALGORITHM";
    /**
     * Algorithm for the request digest put in the log (and used as base for
     * archive ID).
     */
    public static final String LOGREQUEST_DIGESTALGORITHM_PROPERTY = "LOGREQUEST_DIGESTALGORITHM";

    private static final String DEFAULT_LOGREQUEST_DIGESTALGORITHM = "SHA256";
    
    /** If the request digest should be created and logged. */
    public static final String DO_LOGREQUEST_DIGEST = "DO_LOGREQUEST_DIGEST";

    private static final boolean DEFAULT_DO_LOGREQUEST_DIGEST = true;
    
    private LinkedList<String> configErrors;
    private String signatureAlgorithm;
    private String logRequestDigestAlgorithm;
    private boolean doLogRequestDigest;

    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Configuration errors
        configErrors = new LinkedList<>();

        // Get the signature algorithm
        signatureAlgorithm = config.getProperty(SIGNATUREALGORITHM_PROPERTY, DEFAULT_NULL);
                
        // Get the log digest algorithm
        logRequestDigestAlgorithm = config.getProperty(LOGREQUEST_DIGESTALGORITHM_PROPERTY, DEFAULT_LOGREQUEST_DIGESTALGORITHM);
        
        // If the request digest should computed and be logged
        final String s = config.getProperty(DO_LOGREQUEST_DIGEST, Boolean.toString(DEFAULT_DO_LOGREQUEST_DIGEST));
        if ("true".equalsIgnoreCase(s)) {
            doLogRequestDigest = true;
        } else if ("false".equalsIgnoreCase(s)) {
            doLogRequestDigest = false;
        } else {
            configErrors.add("Incorrect value for " + DO_LOGREQUEST_DIGEST);
        }
    }

    @Override
    public Response processData(final Request signRequest,
            final RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        
        // Log values
        final LogMap logMap = LogMap.getInstance(requestContext);

        // Check that the request contains a valid GenericSignRequest object
        // with a byte[].
        if (!(signRequest instanceof SignatureRequest)) {
            throw new IllegalRequestException(
                    "Received request wasn't an expected GenericSignRequest.");
        }
        final SignatureRequest sReq = (SignatureRequest) signRequest;

        if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }

        // Get the file name from the request
        final Object fileNameObject = requestContext.get(RequestContext.FILENAME);
        final String fileNameOriginal;
        if (fileNameObject instanceof String) {
            fileNameOriginal = (String) fileNameObject;
        } else {
            fileNameOriginal = null;
        }
        
        final ReadableData requestData = sReq.getRequestData();
        final WritableData responseData = sReq.getResponseData();
        final byte[] digest;
        logMap.put(IWorkerLogger.LOG_REQUEST_DIGEST_ALGORITHM, new Loggable() {
            @Override
            public String toString() {
                return logRequestDigestAlgorithm;
            }
        });
        if (doLogRequestDigest) {
            try (InputStream input = requestData.getAsInputStream()) {
                final MessageDigest md = MessageDigest.getInstance(logRequestDigestAlgorithm);

                // Digest all data
                // TODO: Future optimization: could be done while the file is read instead
                final byte[] requestDigest = UploadUtil.digest(input, md);

                logMap.put(IWorkerLogger.LOG_REQUEST_DIGEST, new Loggable() {
                    @Override
                    public String toString() {
                        return Hex.toHexString(requestDigest);
                    }
                });
            } catch (NoSuchAlgorithmException ex) {
                LOG.error("Log digest algorithm not supported", ex);
                throw new SignServerException("Log digest algorithm not supported", ex);
            } catch (IOException ex) {
                LOG.error("Log request digest failed", ex);
                throw new SignServerException("Log request digest failed", ex);
            }
        }
        final String archiveId = createArchiveId(new byte[0], (String) requestContext.get(RequestContext.TRANSACTION_ID));

        ICryptoInstance crypto = null;
        try (
                InputStream in = requestData.getAsInputStream();
                OutputStream out = responseData.getAsInMemoryOutputStream()
            ) {
            crypto = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, signRequest, requestContext);
            // Get certificate chain and signer certificate
            final List<Certificate> certs = this.getSigningCertificateChain(crypto);
            if (certs == null) {
                throw new IllegalArgumentException(
                        "Null certificate chain. This signer needs a certificate.");
            }

            final Certificate cert = this.getSigningCertificate(crypto);
            if (LOG.isDebugEnabled()) {
                LOG.debug("SigningCert: " + ((X509Certificate) cert).getSubjectDN());
            }

            // Private key
            final PrivateKey privKey = crypto.getPrivateKey();

            final String sigAlg = signatureAlgorithm == null ? getDefaultSignatureAlgorithm(cert.getPublicKey()) : signatureAlgorithm;
            final byte[] signedbytes;

            if (sigAlg.toUpperCase(Locale.ENGLISH).startsWith("NONEWITH")) { 
                // Special case as BC (ContentSignerBuilder) does not handle NONEwithRSA
                final Signature signature = Signature.getInstance(sigAlg, crypto.getProvider());
                signature.initSign(privKey);

                final byte[] buffer = new byte[4096]; 
                int n = 0;
                while (-1 != (n = in.read(buffer))) {
                    signature.update(buffer, 0, n);
                }

                signedbytes = signature.sign();
            } else {
                // Special handling to support the new Java names not handled by BC
                Map<String, String> algorithmNames = new HashMap<>();
                algorithmNames.put("SHA1withRSASSA-PSS".toUpperCase(Locale.ENGLISH), "SHA1withRSAandMGF1");
                algorithmNames.put("SHA224withRSASSA-PSS".toUpperCase(Locale.ENGLISH), "SHA224withRSAandMGF1");
                algorithmNames.put("SHA256withRSASSA-PSS".toUpperCase(Locale.ENGLISH), "SHA256withRSAandMGF1");
                algorithmNames.put("SHA384withRSASSA-PSS".toUpperCase(Locale.ENGLISH), "SHA384withRSAandMGF1");
                algorithmNames.put("SHA512withRSASSA-PSS".toUpperCase(Locale.ENGLISH), "SHA512withRSAandMGF1");

                String effectiveSigAlgName = algorithmNames.get(sigAlg.toUpperCase(Locale.ENGLISH));
                if (effectiveSigAlgName == null) {
                    effectiveSigAlgName = sigAlg;
                }

                // Use BC for this as it supports the old algorithm names etc
                JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(effectiveSigAlgName);
                signerBuilder.setProvider(crypto.getProvider());
                ContentSigner signer = signerBuilder.build(privKey);
                
                OutputStream signerOut = signer.getOutputStream();
                final byte[] buffer = new byte[4096]; 
                int n = 0;
                while (-1 != (n = in.read(buffer))) {
                    signerOut.write(buffer, 0, n);
                }
                
                signedbytes = signer.getSignature();
            }
            
            out.write(signedbytes);
            
            logMap.put(IWorkerLogger.LOG_RESPONSE_ENCODED, new Loggable() {
                @Override
                public String toString() {
                    return Base64.toBase64String(signedbytes);
                }
            });
            
            final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST, CONTENT_TYPE, requestData, archiveId), 
                    new DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, responseData.toReadableData(), archiveId));

            // Suggest new file name
            if (fileNameOriginal != null) {
                requestContext.put(RequestContext.RESPONSE_FILENAME, fileNameOriginal + ".sig");
            }

            // The client can be charged for the request
            requestContext.setRequestFulfilledByWorker(true);

            return new SignatureResponse(sReq.getRequestID(),
                        responseData, cert, archiveId,
                        archivables,
                        CONTENT_TYPE);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | OperatorCreationException ex) {
            LOG.error("Error initializing signer", ex);
            throw new SignServerException("Error initializing signer", ex);
        } catch (IOException ex) {
            throw new SignServerException("IO error", ex);
        } finally {
            releaseCryptoInstance(crypto, requestContext);
        }
    }
    
    private String getDefaultSignatureAlgorithm(final PublicKey publicKey) {
        final String result;

        if (publicKey instanceof ECPublicKey) {
            result = "SHA256withECDSA";
        }  else if (publicKey instanceof DSAPublicKey) {
            result = "SHA256withDSA";
        } else {
            result = "SHA256withRSA";
        }

        return result;
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        final LinkedList<String> errors = new LinkedList<>(super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }

}
