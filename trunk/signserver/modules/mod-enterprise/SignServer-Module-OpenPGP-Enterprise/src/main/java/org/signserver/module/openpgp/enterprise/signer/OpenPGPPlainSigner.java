/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.openpgp.enterprise.signer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
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
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.SignServerException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.module.openpgp.signer.BaseOpenPGPSigner;
import org.signserver.module.openpgp.signer.OpenPGPUtils;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import static org.signserver.server.cryptotokens.ICryptoTokenV4.PARAM_INCLUDE_DUMMYCERTIFICATE;
import org.signserver.server.data.impl.UploadUtil;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;

/**
 * A Signer signing arbitrary content and produces a plain signature and also
 * has support for PGP key management.
 *
 * @author Vinay Singh
 * @Version $Id$
 */
public class OpenPGPPlainSigner extends BaseOpenPGPSigner {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(OpenPGPPlainSigner.class);
    
    /**
     * Content-type for the produced data.
     */
    private static final String CONTENT_TYPE = "application/octet-stream";

    // Worker properties      
    /**
     * Algorithm for the request digest put in the log (and used as base for
     * archive ID).
     */
    public static final String LOGREQUEST_DIGESTALGORITHM_PROPERTY = "LOGREQUEST_DIGESTALGORITHM";
    /**
     * If the request digest should be created and logged.
     */
    public static final String DO_LOGREQUEST_DIGEST = "DO_LOGREQUEST_DIGEST";
    
    public static String KEY_ID = "KEY_ID";
    public static String KEY_ALGORITHM = "KEY_ALGORITHM";
    public static String KEY_FINGERPRINT = "KEY_FINGERPRINT";
    
    // Default values
    private static final String DEFAULT_LOGREQUEST_DIGESTALGORITHM = "SHA256";    
    private static final boolean DEFAULT_DO_LOGREQUEST_DIGEST = true;
           
    // Configuration values           
    private String logRequestDigestAlgorithm;
    private boolean doLogRequestDigest;    

    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
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
    public Response processData(Request signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
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
                OutputStream out = responseData.getAsInMemoryOutputStream()) {
            
            final Map<String, Object> params = new HashMap<>();
                params.put(PARAM_INCLUDE_DUMMYCERTIFICATE, true);
                crypto = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, signRequest, params, requestContext);                
            
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
            
            // Check that keyid and keyalg provided by client match with signer key
            RequestMetadata requestMetadata = RequestMetadata.getInstance(requestContext);
            final String keyIdString = requestMetadata.get(KEY_ID);
            final String keyAlgString = requestMetadata.get(KEY_ALGORITHM);
            final String keyFingerPrintString = requestMetadata.get(KEY_FINGERPRINT);
            if (keyIdString != null && keyAlgString != null) {
                checkKeyParamaters(keyIdString, keyAlgString, keyFingerPrintString, ((X509Certificate) cert));
            }

            // Private key
            final PrivateKey privKey = crypto.getPrivateKey();

            final String sigAlg = getDefaultSignatureAlgorithm(cert.getPublicKey());
            final Signature signature = Signature.getInstance(sigAlg, crypto.getProvider());
            signature.initSign(privKey);

            final byte[] buffer = new byte[4096];
            int n = 0;
            while (-1 != (n = in.read(buffer))) {
                signature.update(buffer, 0, n);
            }

            final byte[] signedbytes = signature.sign();
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
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter ex) {
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
            result = "NONEwithECDSA";
        } else if (publicKey instanceof DSAPublicKey) {
            result = "NONEwithDSA";
        } else {
            result = "NONEwithRSA";
        }

        return result;
    }
    
    private void checkKeyParamaters(String keyIdInRequestString, String keyAlgInRequestrequestString, String keyFingerPrintString, final X509Certificate x509Cert) throws SignServerException, IllegalRequestException {
        final JcaPGPKeyConverter conv = new JcaPGPKeyConverter();
        boolean keyParamsMatched = true;
        try {
            PGPPublicKey pgpPublicKey = conv.getPGPPublicKey(OpenPGPUtils.getKeyAlgorithm(x509Cert), x509Cert.getPublicKey(), x509Cert.getNotBefore());
            long keyIdInRequest = new BigInteger(keyIdInRequestString, 16).longValue();
            int keyAlgInRequestrequest = Integer.valueOf(keyAlgInRequestrequestString);
            String fingerprint = Hex.toHexString(pgpPublicKey.getFingerprint()).toUpperCase(Locale.ENGLISH);

            if (keyIdInRequest != pgpPublicKey.getKeyID()) {
                keyParamsMatched = false;
            }

            if (keyAlgInRequestrequest != pgpPublicKey.getAlgorithm()) {
                keyParamsMatched = false;
            }

            // For debian dpkg-sig signing, also check key fingerprint if provided by client 
            if (keyFingerPrintString != null && !keyFingerPrintString.toUpperCase(Locale.ENGLISH).equals(fingerprint)) {
                keyParamsMatched = false;
            }

            if (!keyParamsMatched) {
                String keyFingerPrintError = keyFingerPrintString == null ? "" : " Expected key fingerprint: " + fingerprint;
                throw new IllegalRequestException("Mismatch between PGP key parameters sent in request and configured in signer. "
                        + "Expected key id: " + OpenPGPUtils.formatKeyID(pgpPublicKey.getKeyID()) + " Expected key algorithm: " + pgpPublicKey.getAlgorithm()
                        + keyFingerPrintError);
            }
        } catch (SignServerException | PGPException ex) {
            throw new SignServerException("Error initializing signer", ex);
        }
    }

}
