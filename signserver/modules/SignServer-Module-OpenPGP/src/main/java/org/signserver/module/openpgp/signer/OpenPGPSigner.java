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
package org.signserver.module.openpgp.signer;

import org.signserver.common.OpenPgpCertReqData;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.persistence.EntityManager;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.signers.BaseSigner;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPPrivateKey;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.NoSuchAliasException;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.server.ServicesImpl;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.PROPERTY_SELFSIGNED_VALIDITY;
import static org.signserver.server.cryptotokens.ICryptoTokenV4.PARAM_INCLUDE_DUMMYCERTIFICATE;

/**
 * Signer for OpenPGP.
 *
 * Input: Content to sign
 * Output: OpenPGP ASCII Armored signature
 *
 * @author Markus Kilås
 * @version $Id: SkeletonSigner.java 7050 2016-02-17 14:49:30Z netmackan $
 */
public class OpenPGPSigner extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(OpenPGPSigner.class);

    // Worker properties
    public static final String PROPERTY_SIGNATUREALGORITHM = "SIGNATUREALGORITHM";
    public static final String PROPERTY_RESPONSE_FORMAT = "RESPONSE_FORMAT";

    // Log fields
    //...

    // Default values
    private static final String DEFAULT_SIGNATUREALGORITHM = "SHA256withRSA";

    // Content types
    private static final String REQUEST_CONTENT_TYPE = "application/octet-stream";
    private static final String RESPONSE_CONTENT_TYPE = "application/pgp-signature"; // [https://tools.ietf.org/html/rfc3156]

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    private String signatureAlgorithm;
    private PGPPublicKey pgpCertificate;
    private Long selfsignedValidity;
    private ResponseFormat responseFormat = ResponseFormat.ARMORED;
    //...

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Optional property SIGNATUREALGORITHM
        signatureAlgorithm = config.getProperty(PROPERTY_SIGNATUREALGORITHM);
        if (signatureAlgorithm == null || signatureAlgorithm.trim().isEmpty()) {
            signatureAlgorithm = DEFAULT_SIGNATUREALGORITHM;
        }

        // Optional property PGPPUBLICKEY
        final String publicKeyValue = config.getProperty("PGPPUBLICKEY");
        if (publicKeyValue != null) {
            try (InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(publicKeyValue.getBytes(StandardCharsets.US_ASCII)))) {
                final JcaPGPPublicKeyRingCollection pgpPub = new JcaPGPPublicKeyRingCollection(in);

                PGPPublicKey key = null;
                final Iterator<PGPPublicKeyRing> ringIterator = pgpPub.getKeyRings();
                while (key == null && ringIterator.hasNext()) {
                    final PGPPublicKeyRing ring = ringIterator.next();
                    final Iterator<PGPPublicKey> keyIterator = ring.getPublicKeys();
                    while (key == null && keyIterator.hasNext()) {
                        key = keyIterator.next();
                    }
                }
                if (key == null) {
                    configErrors.add("No public key found in worker property " + "PGPPUBLICKEY");
                } else {
                    pgpCertificate = key;
                }
            } catch (IOException | PGPException ex) {
                configErrors.add("Unable to parse public key in worker property " + "PGPPUBLICKEY" + ": " + ex.getLocalizedMessage());
            }
        }

        // Optional property SELFSIGNED_VALIDITY
        final String validityValue = config.getProperty(PROPERTY_SELFSIGNED_VALIDITY);
        if (validityValue != null && !validityValue.trim().isEmpty()) {
            selfsignedValidity = Long.parseLong(validityValue);
        }
        
        // Optional property RESPONSE_FORMAT
        final String responseFormatValue = config.getProperty(PROPERTY_RESPONSE_FORMAT);
        if (!StringUtils.isBlank(responseFormatValue)) {
            try {
                responseFormat = ResponseFormat.valueOf(responseFormatValue.trim());
            } catch (IllegalArgumentException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Illegal value for " + PROPERTY_RESPONSE_FORMAT, ex);
                }
                configErrors.add("Illegal value for " + PROPERTY_RESPONSE_FORMAT + ". Possible values are: " + Arrays.toString(ResponseFormat.values()));
            }
        }
    }

    @Override
    public Response processData(Request signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        try {
            if (!configErrors.isEmpty()) {
                throw new SignServerException("Worker is misconfigured");
            }
            if (!(signRequest instanceof SignatureRequest)) {
                throw new IllegalRequestException(
                        "Received request wasn't an expected GenericSignRequest.");
            }
            final SignatureRequest sReq = (SignatureRequest) signRequest;

            // Get the data from request
            final ReadableData requestData = sReq.getRequestData();
            final WritableData responseData = sReq.getResponseData();
            //...

            // Log anything interesting from the request to the worker logger
            //...

            // Produce the result, ie doing the work...
            Certificate signerCert = null;
            ICryptoInstance cryptoInstance = null;
            try (BCPGOutputStream bOut = createOutputStream(responseData.getAsOutputStream(), responseFormat)) {
                final Map<String, Object> params = new HashMap<>();
                params.put(PARAM_INCLUDE_DUMMYCERTIFICATE, true);
                cryptoInstance = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, signRequest, params, requestContext);

                // signature value
                final JcaPGPKeyConverter conv = new JcaPGPKeyConverter();
                final X509Certificate x509Cert = (X509Certificate) getSigningCertificate(cryptoInstance);
                final PGPPublicKey pgpPublicKey = conv.getPGPPublicKey(getKeyAlg(x509Cert), x509Cert.getPublicKey(), x509Cert.getNotBefore());

                final PGPSignatureGenerator generator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpPublicKey.getAlgorithm(), PGPUtil.SHA256).setProvider(cryptoInstance.getProvider()).setDigestProvider("BC"));

                generator.init(PGPSignature.BINARY_DOCUMENT, new org.bouncycastle.openpgp.operator.jcajce.JcaPGPPrivateKey(pgpPublicKey, cryptoInstance.getPrivateKey()));

                generator.update(requestData.getAsByteArray()); // TODO: getAsInputStream()
                generator.generate().encode(bOut);
            } catch (PGPException ex) {
                throw new SignServerException("PGP exception", ex);
            } catch (InvalidAlgorithmParameterException ex) {
                throw new SignServerException("Error initializing signer", ex);
            } catch (UnsupportedCryptoTokenParameter ex) {
                throw new SignServerException("Error initializing signer", ex);
            } finally {
                releaseCryptoInstance(cryptoInstance, requestContext);
            }

            // Create the archivables (request and response)
            final String archiveId = createArchiveId(new byte[0], (String) requestContext.get(RequestContext.TRANSACTION_ID));
            final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE, RESPONSE_CONTENT_TYPE, responseData.toReadableData(), archiveId));

            // Suggest new file name
            final Object fileNameOriginal = requestContext.get(RequestContext.FILENAME);
            if (fileNameOriginal instanceof String) {
                requestContext.put(RequestContext.RESPONSE_FILENAME, fileNameOriginal + ".asc");
            }

            // As everyting went well, the client can be charged for the request
            requestContext.setRequestFulfilledByWorker(true);

            // Return the response
            return new SignatureResponse(sReq.getRequestID(), responseData, signerCert, archiveId, archivables, RESPONSE_CONTENT_TYPE);
        } catch (UnsupportedEncodingException ex) {
            // This is a server-side error
            throw new SignServerException("Encoding not supported: " + ex.getLocalizedMessage(), ex);
        } catch (IOException ex) {
            throw new SignServerException("Encoding error", ex);
        }
    }
    
    @Override
    protected List<String> getFatalErrors(final IServices services) {
        // Add our errors to the list of errors
        final LinkedList<String> errors = new LinkedList<>(
                super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, boolean defaultKey) throws CryptoTokenOfflineException, NoSuchAliasException {
        return genCertificateRequest(info, explicitEccParameters, defaultKey, new ServicesImpl());
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, boolean defaultKey, IServices services) throws CryptoTokenOfflineException, NoSuchAliasException {
        return genCertificateRequest(certReqInfo, explicitEccParameters, defaultKey ? config.getProperty("DEFAULTKEY") : config.getProperty("NEXTCERTSIGNKEY"), services);
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, String keyAlias, IServices services) throws CryptoTokenOfflineException, NoSuchAliasException {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">genCertificateRequest");
        }

        final RequestContext context = new RequestContext(false);
        context.setServices(services);

        ICryptoInstance crypto = null;
        ICryptoTokenV4 token = null;
        try {
            token = getCryptoToken(services);

            if (token == null) {
                throw new CryptoTokenOfflineException("Crypto token offline");
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found a crypto token of type: " + token.getClass().getName());
            }

            // Acquire crypto instance
            final Map<String, Object> params = new HashMap<>();
            params.put(PARAM_INCLUDE_DUMMYCERTIFICATE, true);
            crypto = token.acquireCryptoInstance(keyAlias, params, context);

            PKCS10CertReqInfo reqInfo = (PKCS10CertReqInfo) info;

            final JcaPGPKeyConverter conv = new JcaPGPKeyConverter();
            final X509Certificate x509Cert = (X509Certificate) getSigningCertificate(crypto);
            final PGPPublicKey pgpPublicKey = pgpCertificate != null ? pgpCertificate : conv.getPGPPublicKey(getKeyAlg(x509Cert), x509Cert.getPublicKey(), x509Cert.getNotBefore());

            PGPSignatureGenerator generator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpPublicKey.getAlgorithm(), PGPUtil.SHA256).setProvider(crypto.getProvider()).setDigestProvider("BC"));

            // TODO: is this the right signatureType?
            generator.init(PGPSignature.DEFAULT_CERTIFICATION, new JcaPGPPrivateKey(pgpPublicKey, crypto.getPrivateKey()));

            // Validity time
            if (selfsignedValidity != null) {
                PGPSignatureSubpacketGenerator subGenerator = new PGPSignatureSubpacketGenerator();
                subGenerator.setKeyExpirationTime(true, selfsignedValidity);
                generator.setHashedSubpackets(subGenerator.generate());
            } else {
                LOG.error("No SELFSIGNED_VALIDITY so not setting any expiration");
            }

            // Generate and add certification
            final PGPSignature certification = generator.generateCertification(reqInfo.getSubjectDN(), pgpPublicKey);
            final PGPPublicKey certifiedKey = PGPPublicKey.addCertification(pgpPublicKey, reqInfo.getSubjectDN(), certification);

            final ICertReqData result = new OpenPgpCertReqData(certifiedKey);

            if (LOG.isTraceEnabled()) {
                LOG.trace("<genCertificateRequest");
            }

            return result;
        } catch (SignServerException e) {
            LOG.error("FAILED_TO_GET_CRYPTO_TOKEN_" + e.getMessage());
            throw new CryptoTokenOfflineException(e);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new CryptoTokenOfflineException(ex);
        } catch (UnsupportedCryptoTokenParameter ex) {
            throw new CryptoTokenOfflineException(ex);
        } catch (IllegalRequestException ex) {
            throw new CryptoTokenOfflineException(ex);
        } catch (PGPException ex) {
            throw new CryptoTokenOfflineException(ex);
        } catch (IOException ex) {
            throw new CryptoTokenOfflineException(ex);
        } finally {
            if (token != null) {
                token.releaseCryptoInstance(crypto, context);
            }
        }
    }

    @Override
    protected boolean isNoCertificates() {
        return true;
    }

    @Override
    public WorkerStatusInfo getStatus(final List<String> additionalFatalErrors, final IServices services) {
        final List<String> fatalErrors = new LinkedList<>(additionalFatalErrors);
        WorkerStatusInfo status = (WorkerStatusInfo) super.getStatus(additionalFatalErrors, services);

        final RequestContext context = new RequestContext(true);
        context.setServices(services);
        ICryptoInstance crypto = null;
        try {
            final Map<String, Object> params = new HashMap<>();
            params.put(PARAM_INCLUDE_DUMMYCERTIFICATE, true);
            crypto = acquireDefaultCryptoInstance(params, context);

            X509Certificate signerCertificate = (X509Certificate) crypto.getCertificate();
            if (signerCertificate != null) {

                final JcaPGPKeyConverter conv = new JcaPGPKeyConverter();
                X509Certificate x509Cert = (X509Certificate) getSigningCertificate(crypto);

                PGPPublicKey pgpPublicKey = conv.getPGPPublicKey(getKeyAlg(x509Cert), x509Cert.getPublicKey(), x509Cert.getNotBefore());

                status.getCompleteEntries().add(new WorkerStatusInfo.Entry("Key ID", String.format("%X", pgpPublicKey.getKeyID())));
                status.getCompleteEntries().add(new WorkerStatusInfo.Entry("Primary key fingerprint", Hex.toHexString(pgpPublicKey.getFingerprint()).toUpperCase(Locale.ENGLISH)));

                // Empty public key
                if (pgpCertificate != null) {
                    ByteArrayOutputStream bout = new ByteArrayOutputStream();
                    ArmoredOutputStream out2 = new ArmoredOutputStream(bout);
                    pgpCertificate.encode(out2);
                    out2.close();

                    status.getCompleteEntries().add(new WorkerStatusInfo.Entry("PGP Public key", new String(bout.toByteArray(), StandardCharsets.US_ASCII)));

                    status.getCompleteEntries().add(new WorkerStatusInfo.Entry("PGP Key ID", String.format("%X", pgpCertificate.getKeyID())));

                    final StringBuilder sb = new StringBuilder();

                    int algorithm = pgpCertificate.getAlgorithm();
                    int bitStrength = pgpCertificate.getBitStrength();
                    Date creationTime = pgpCertificate.getCreationTime();
                    long validSeconds = pgpCertificate.getValidSeconds();
                    boolean masterKey = pgpCertificate.isMasterKey();
                    int version = pgpCertificate.getVersion();

                    sb.append("Master key: ").append(masterKey).append("\n");
                    sb.append("Version: ").append(version).append("\n");
                    sb.append("Algorithm: ").append(algorithm).append("\n");
                    sb.append("Bit length: ").append(bitStrength).append("\n");
                    sb.append("Creation time: ").append(creationTime).append("\n");
                    sb.append("Expire time: ").append(validSeconds == 0 ? "n/a" : new Date(creationTime.getTime() + 1000L * validSeconds)).append("\n");

                    sb.append("User IDs:").append("\n");
                    Iterator userIDs = pgpCertificate.getUserIDs();
                    while (userIDs.hasNext()) {
                        Object o = userIDs.next();
                        if (o instanceof String) {
                            sb.append("   ").append((String) o).append("\n");
                        }
                    }

                    sb.append("Signatures:").append("\n");
                    Iterator signatures = pgpCertificate.getSignatures();
                    while (signatures.hasNext()) {
                        Object o = signatures.next();
                        if (o instanceof PGPSignature) {
                            PGPSignature sig = (PGPSignature) o;
                            sb.append("   ")
                                    .append(sig.getCreationTime())
                                    .append(" by key ID ")
                                    .append(String.format("%X", sig.getKeyID())).append("\n");
                        }
                    }

                    status.getCompleteEntries().add(new WorkerStatusInfo.Entry("PGP Public key", sb.toString()));
                }

            }
        } catch (CryptoTokenOfflineException e) {} // the error will have been picked up by getCryptoTokenFatalErrors already
        catch (InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter | IllegalRequestException | SignServerException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unable to obtain certificate from token", ex);
            }
        } catch (PGPException ex) {
            LOG.error("Unable to parse PGP public key", ex);
        } catch (IOException ex) {
            LOG.error("Unable to encode PGP public key", ex);
        } finally {
            if (crypto != null) {
                try {
                    releaseCryptoInstance(crypto, context);
                } catch (SignServerException ex) {
                    LOG.warn("Unable to release crypto instance", ex);
                }
            }
        }

        return status;
    }

    private int getKeyAlg(X509Certificate x509Cert) throws SignServerException {
        final int keyAlg;
        switch (x509Cert.getPublicKey().getAlgorithm()) {
            case "RSA":
                keyAlg = PublicKeyAlgorithmTags.RSA_SIGN;
                break;
            case "EC":
                keyAlg = PublicKeyAlgorithmTags.ECDSA;
                break;
            case "DSA":
                keyAlg = PublicKeyAlgorithmTags.DSA;
                break;
            default:
                throw new SignServerException("Unsupported key algorithm: " + x509Cert.getPublicKey().getAlgorithm());
        }
        return keyAlg;
    }

    private BCPGOutputStream createOutputStream(OutputStream out, ResponseFormat responseFormat) {
        switch (responseFormat) {
            case ARMORED:
                return new BCPGOutputStream(new ArmoredOutputStream(out));
            case BINARY:
                return new BCPGOutputStream(out);
            default:
                throw new UnsupportedOperationException("Unsupported response format: " + responseFormat);
        }
    }

    /**
     * Response format.
     */
    public enum ResponseFormat {
        /** Binary OpenPGP format. */
        BINARY,
        
        /** ASCII armored format. */
        ARMORED
    }
}
