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
import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.common.*;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.server.signers.BaseSigner;

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
    
    private LinkedList<String> configErrors;
    private String signatureAlgorithm;
    private String logRequestDigestAlgorithm;


    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Configuration errors
        configErrors = new LinkedList<String>();

        // Get the signature algorithm
        signatureAlgorithm = config.getProperty(SIGNATUREALGORITHM_PROPERTY);
        if (signatureAlgorithm != null && signatureAlgorithm.trim().isEmpty()) {
            signatureAlgorithm = null;
        }
        
        // Get the log digest algorithm
        logRequestDigestAlgorithm = config.getProperty(LOGREQUEST_DIGESTALGORITHM_PROPERTY);
        if (logRequestDigestAlgorithm == null || logRequestDigestAlgorithm.trim().isEmpty()) {
            logRequestDigestAlgorithm = DEFAULT_LOGREQUEST_DIGESTALGORITHM;
        }
    }

    @Override
    public ProcessResponse processData(final ProcessRequest signRequest,
            final RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {

        ProcessResponse signResponse;
        
        // Log values
        final LogMap logMap = LogMap.getInstance(requestContext);

        // Check that the request contains a valid GenericSignRequest object
        // with a byte[].
        if (!(signRequest instanceof GenericSignRequest)) {
            throw new IllegalRequestException(
                    "Recieved request wasn't a expected GenericSignRequest.");
        }

        final ISignRequest sReq = (ISignRequest) signRequest;

        if (!(sReq.getRequestData() instanceof byte[])) {
            throw new IllegalRequestException(
                    "Recieved request data wasn't a expected byte[].");
        }

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
        
        final byte[] data = (byte[]) sReq.getRequestData();
        byte[] digest;
        logMap.put(IWorkerLogger.LOG_REQUEST_DIGEST_ALGORITHM, logRequestDigestAlgorithm);
        try {
            final MessageDigest md = MessageDigest.getInstance(logRequestDigestAlgorithm);
            digest = md.digest(data);
            logMap.put(IWorkerLogger.LOG_REQUEST_DIGEST, Hex.toHexString(digest));
        } catch (NoSuchAlgorithmException ex) {
            LOG.error("Digest algorithm not supported", ex);
            throw new SignServerException("Digest algorithm not supported", ex);
        }
        final String archiveId = createArchiveId(digest, (String) requestContext.get(RequestContext.TRANSACTION_ID));

        ICryptoInstance crypto = null;
        try {
            crypto = acquireCryptoInstance(ICryptoToken.PURPOSE_SIGN, signRequest, requestContext);
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
            final Signature signature = Signature.getInstance(sigAlg, crypto.getProvider());
            signature.initSign(privKey);
            signature.update(data);

            final byte[] signedbytes = signature.sign();
            
            logMap.put(IWorkerLogger.LOG_RESPONSE_ENCODED, Base64.toBase64String(signedbytes));
            
            final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST, CONTENT_TYPE, data, archiveId), 
                    new DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, signedbytes, archiveId));

            if (signRequest instanceof GenericServletRequest) {
                signResponse = new GenericServletResponse(sReq.getRequestID(),
                        signedbytes, cert, archiveId,
                        archivables,
                        CONTENT_TYPE);
            } else {
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        signedbytes, cert, archiveId,
                        archivables);
            }

            // Suggest new file name
            if (fileNameOriginal != null) {
                requestContext.put(RequestContext.RESPONSE_FILENAME, fileNameOriginal + ".sig");
            }

            // The client can be charged for the request
            requestContext.setRequestFulfilledByWorker(true);

            return signResponse;
        } catch (NoSuchAlgorithmException ex) {
            LOG.error("Error initializing signer", ex);
            throw new SignServerException("Error initializing signer", ex);
        } catch (InvalidKeyException ex) {
            LOG.error("Error initializing signer", ex);
            throw new SignServerException("Error initializing signer", ex);
        } catch (SignatureException ex) {
            LOG.error("Error initializing signer", ex);
            throw new SignServerException("Error initializing signer", ex);
        } finally {
            releaseCryptoInstance(crypto, requestContext);
        }
    }
    
    private String getDefaultSignatureAlgorithm(final PublicKey publicKey) {
        final String result;

        if (publicKey instanceof ECPublicKey) {
            result = "SHA1withECDSA";
        }  else if (publicKey instanceof DSAPublicKey) {
            result = "SHA1withDSA";
        } else {
            result = "SHA1withRSA";
        }

        return result;
    }

    @Override
    protected List<String> getFatalErrors() {
        final LinkedList<String> errors = new LinkedList<String>(super.getFatalErrors());
        errors.addAll(configErrors);
        return errors;
    }

}
