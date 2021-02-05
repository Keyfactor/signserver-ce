/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.apk.signer;

import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.internal.util.ByteArrayDataSink;
import com.android.apksig.util.DataSources;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import javax.persistence.EntityManager;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;
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
import static org.signserver.module.apk.signer.ApkSigner.LINEAGE_FILE_CONTENT;

/**
 * Hash signer intended for client-side hashing and construction for APK signing.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ApkHashSigner extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ApkHashSigner.class);

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

    private Optional<SigningCertificateLineage> lineage = Optional.empty();
    private ArrayList<String> otherSigners;

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

        final String lineageContentValue = config.getProperty(LINEAGE_FILE_CONTENT);
        if (StringUtils.isNotBlank(lineageContentValue)) {
            try {
                final byte[] data = Base64.decode(lineageContentValue);
                lineage = Optional.of(SigningCertificateLineage.readFromDataSource(DataSources.asDataSource(ByteBuffer.wrap(data))));
            } catch (DecoderException e) {
                configErrors.add("Illegal base64 value for " + LINEAGE_FILE_CONTENT);
            } catch (IOException | IllegalArgumentException e) {
                configErrors.add("Failed to parse lineage: " + e.getMessage());
            }
        }

        otherSigners = new ArrayList<>(5);
        final String otherSignersValue = config.getProperty(WorkerConfig.OTHER_SIGNERS);
        if (StringUtils.isNotBlank(otherSignersValue)) {
            final String[] values = otherSignersValue.trim().split(",");
            for (String value : values) {
                value = value.trim();
                if (!value.isEmpty()) {
                    otherSigners.add(value);
                }
            }
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
        List<ICryptoInstance> otherSignersCryptos = null;
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

            final byte[] signedbytes;
            final byte[] buffer = new byte[4096];
            // try reading the first "chunk" to know if it's an empty request or not
            final int firstBytesRead = in.read(buffer);
            
            if (firstBytesRead == -1) {
                // got EOF immediatly, empty request, this is a pre-request
                otherSignersCryptos = acquireCryptoInstancesFromOtherSigners(ICryptoTokenV4.PURPOSE_SIGN, signRequest, logMap, requestContext);

                final String preResponse =
                        createPreResponse(crypto, otherSignersCryptos);
                signedbytes = preResponse.getBytes(StandardCharsets.UTF_8);
            } else {
                // Private key
                final PrivateKey privKey = crypto.getPrivateKey();

                final String sigAlg = signatureAlgorithm == null ? getDefaultSignatureAlgorithm(cert.getPublicKey()) : signatureAlgorithm;
                final Signature signature = Signature.getInstance(sigAlg, crypto.getProvider());
                signature.initSign(privKey);

                // first update signature with data from the first read
                signature.update(buffer, 0, firstBytesRead);

                int n = 0;
                while (-1 != (n = in.read(buffer))) {
                    signature.update(buffer, 0, n);
                }

                signedbytes = signature.sign();
            }

            out.write(signedbytes);

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
        } catch (NoSuchAlgorithmException | InvalidKeyException |
                 SignatureException ex) {
            LOG.error("Error initializing signer", ex);
            throw new SignServerException("Error initializing signer", ex);
        } catch (CertificateEncodingException |
                 InvalidAlgorithmParameterException |
                 UnsupportedCryptoTokenParameter ex) {
            LOG.error("Error generating pre-response");
            throw new SignServerException("Error generating pre-response", ex);
        } catch (IOException ex) {
            throw new SignServerException("IO error", ex);
        } finally {
            releaseCryptoInstance(crypto, requestContext);
            if (otherSignersCryptos != null) {
                for (final ICryptoInstance otherCrypto : otherSignersCryptos) {
                    releaseCryptoInstance(otherCrypto, requestContext);
                }
            }
        }
    }

    private String createPreResponse(final ICryptoInstance cryptoInstance,
                                     final List<ICryptoInstance> otherCryptoInstances)
            throws IOException, CertificateEncodingException {
        final StringBuilder sb = new StringBuilder();

        sb.append("SIGNER_CERTIFICATE_CHAIN=");
        appendBase64CertChain(sb, cryptoInstance.getCertificateChain());
        sb.append("\n");

        sb.append("NUMBER_OF_OTHER_SIGNERS=");
        sb.append(otherSigners.size());
        sb.append("\n");

        for (int i = 0; i < otherCryptoInstances.size(); i++) {
            // signer name for other signer index i
            sb.append("OTHER_SIGNER_");
            sb.append(i);
            sb.append(".NAME=");
            sb.append(otherSigners.get(i));
            sb.append("\n");

            // cert chain for other signer index i
            sb.append("OTHER_SIGNER_");
            sb.append(i);
            sb.append(".CERTIFICATE_CHAIN=");
            appendBase64CertChain(sb, otherCryptoInstances.get(i).getCertificateChain());
            sb.append("\n");
        }
        
        if (lineage.isPresent()) {
            final ByteArrayDataSink sink = new ByteArrayDataSink();
        
            lineage.get().writeToDataSink(sink);
            final ByteBuffer buffer = sink.getByteBuffer(0L, (int) sink.size());

            sb.append("LINEAGE_FILE_CONTENT=");
            sb.append(Base64.toBase64String(buffer.array()));
            sb.append("\n");
        }

        return sb.toString();
    }

    private void appendBase64CertChain(final StringBuilder sb,
                                         final List<Certificate> certChain) throws CertificateEncodingException {
        for (int i = 0; i < certChain.size(); i++) {
            final Certificate cert = certChain.get(i);
            if (i != 0) {
                sb.append(";");
            }
            sb.append(Base64.toBase64String(cert.getEncoded()));
        }
    }
    
    private String getDefaultSignatureAlgorithm(final PublicKey publicKey) {
        final String result;

        if (publicKey instanceof ECPublicKey) {
            result = "NONEwithECDSA";
        } else if (publicKey instanceof RSAPublicKey) {
            result = "NONEwithRSA";
        } else if (publicKey instanceof DSAPublicKey) {
            result = "NONEwithDSA";
        } else {
            throw new IllegalArgumentException("Unknown key algorithm: " +
                                               publicKey.getAlgorithm());
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
