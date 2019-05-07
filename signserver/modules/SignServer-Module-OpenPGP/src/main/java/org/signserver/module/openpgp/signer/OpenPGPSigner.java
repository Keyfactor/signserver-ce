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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
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
    public static final String PROPERTY_DIGEST_ALGORITHM = "DIGEST_ALGORITHM";
    public static final String PROPERTY_RESPONSE_FORMAT = "RESPONSE_FORMAT";
    public static final String PROPERTY_PGPPUBLICKEY = "PGPPUBLICKEY";
    public static final String PROPERTY_GENERATE_REVOCATION_CERTIFICATE =
            "GENERATE_REVOCATION_CERTIFICATE";

    // Log fields
    //...

    // Default values
    private static final ResponseFormat DEFAULT_RESPONSE_FORMAT = ResponseFormat.ARMORED;
    private static final int DEFAULT_DIGEST_ALGORITHM = PGPUtil.SHA256;

    // Content types
    private static final String REQUEST_CONTENT_TYPE = "application/octet-stream";
    private static final String RESPONSE_CONTENT_TYPE = "application/pgp-signature"; // [https://tools.ietf.org/html/rfc3156]

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    private int digestAlgorithm = DEFAULT_DIGEST_ALGORITHM;
    private PGPPublicKey pgpCertificate;
    private Long selfsignedValidity;
    private ResponseFormat responseFormat = DEFAULT_RESPONSE_FORMAT;
    private boolean generateRevocationCertificate;  
    private boolean detachedSignature; // property declared for future ticket
    public static final String DETACHEDSIGNATURE_PROPERTY = "DETACHEDSIGNATURE";
    //...

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Optional property DIGEST_ALGORITHM
        final String digestAlgorithmValue = config.getProperty(PROPERTY_DIGEST_ALGORITHM);
        if (!StringUtils.isBlank(digestAlgorithmValue)) {
            try {
                if (StringUtils.isNumeric(digestAlgorithmValue.trim())) {
                    digestAlgorithm = Integer.parseInt(digestAlgorithmValue.trim());
                } else {
                    digestAlgorithm = OpenPGPUtils.getDigestFromString(digestAlgorithmValue.trim());
                }
            } catch (NumberFormatException | PGPException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Illegal value for " + PROPERTY_DIGEST_ALGORITHM, ex);
                }
                configErrors.add("Illegal value for " + PROPERTY_DIGEST_ALGORITHM + ". Possible values are numeric or textual OpenPGP Hash Algorithms");
            }
        }

        // Optional property PGPPUBLICKEY
        final String publicKeyValue = config.getProperty(PROPERTY_PGPPUBLICKEY);
        if (publicKeyValue != null) {
            try {
                final List<PGPPublicKey> keys = OpenPGPUtils.parsePublicKeys(publicKeyValue);
                if (keys.isEmpty()) {
                    configErrors.add("No public key found in worker property " + PROPERTY_PGPPUBLICKEY);
                } else {
                    if (keys.size() > 1) {
                        LOG.warn("More than one public keys in PGPPUBLICKEY property.");
                    }
                    pgpCertificate = keys.get(0);
                }
            } catch (IOException | PGPException ex) {
                configErrors.add("Unable to parse public key in worker property " + PROPERTY_PGPPUBLICKEY + ": " + ex.getLocalizedMessage());
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

        // Optional property GENERATE_REVOCATION_CERTIFICATE
        final String generateRevocationCertificateValue =
                config.getProperty(PROPERTY_GENERATE_REVOCATION_CERTIFICATE);
        if (!StringUtils.isBlank(generateRevocationCertificateValue)) {
            if (Boolean.TRUE.toString().equalsIgnoreCase(generateRevocationCertificateValue)) {
                generateRevocationCertificate = true;
            } else if (Boolean.FALSE.toString().equalsIgnoreCase(generateRevocationCertificateValue)) {
                generateRevocationCertificate = false;
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Illegal value for " +
                              PROPERTY_GENERATE_REVOCATION_CERTIFICATE + ": " +
                              generateRevocationCertificateValue);
                }
                configErrors.add("Illegal value for " +
                                 PROPERTY_GENERATE_REVOCATION_CERTIFICATE +
                                 ". Specify boolean (true or false)");
            }
        }
        
        // Detached signature
        final String detachedSignatureValue = config.getProperty(DETACHEDSIGNATURE_PROPERTY);
        if (detachedSignatureValue == null) {
            configErrors.add("Please provide " + DETACHEDSIGNATURE_PROPERTY + " as TRUE or FALSE");
        } else {
            if (Boolean.FALSE.toString().equalsIgnoreCase(detachedSignatureValue)) {
                detachedSignature = false;
                configErrors.add("Currently only " + DETACHEDSIGNATURE_PROPERTY + " as TRUE supported"); // TODO: remove after clear text signature support
            } else if (Boolean.TRUE.toString().equalsIgnoreCase(detachedSignatureValue)) {
                detachedSignature = true;
            } else {
                configErrors.add("Incorrect value for property " + DETACHEDSIGNATURE_PROPERTY + ". Expecting TRUE or FALSE.");
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
            X509Certificate signerCert = null;
            ICryptoInstance cryptoInstance = null;
            try (BCPGOutputStream bOut = createOutputStream(responseData.getAsOutputStream(), responseFormat)) {
                final Map<String, Object> params = new HashMap<>();
                params.put(PARAM_INCLUDE_DUMMYCERTIFICATE, true);
                cryptoInstance = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, signRequest, params, requestContext);

                // signature value
                final JcaPGPKeyConverter conv = new JcaPGPKeyConverter();
                signerCert = (X509Certificate) getSigningCertificate(cryptoInstance);
                final PGPPublicKey pgpPublicKey = conv.getPGPPublicKey(OpenPGPUtils.getKeyAlgorithm(signerCert), signerCert.getPublicKey(), signerCert.getNotBefore());

                final PGPSignatureGenerator generator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpPublicKey.getAlgorithm(), digestAlgorithm).setProvider(cryptoInstance.getProvider()).setDigestProvider("BC"));

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
        final List<String> result = new LinkedList<>();
        result.addAll(super.getFatalErrors(services));
        result.addAll(configErrors);

        // Check that PGPPUBLICKEY matches key
        if (pgpCertificate != null) {
            try {
                final X509Certificate signerCert = (X509Certificate) getSigningCertificate(services);
                final JcaPGPKeyConverter conv = new JcaPGPKeyConverter();
                final PGPPublicKey pgpPublicKey = conv.getPGPPublicKey(OpenPGPUtils.getKeyAlgorithm(signerCert), signerCert.getPublicKey(), signerCert.getNotBefore());

                if (!Arrays.equals(pgpPublicKey.getPublicKeyPacket().getKey().getEncoded(), pgpCertificate.getPublicKeyPacket().getKey().getEncoded())) {
                    result.add("Configured " + PROPERTY_PGPPUBLICKEY + " not matching the key");
                }
            } catch (CryptoTokenOfflineException ex) {
                if (isCryptoTokenActive(services)) {
                    result.add("No signer certificate available");
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signer " + workerId + ": Could not get signer certificate: " + ex.getMessage());
                }
            } catch (SignServerException | PGPException ex) {
                result.add("Unable to parse OpenPGP public key: " + ex.getMessage());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unable to parse OpenPGP public key", ex);
                }
            }
        }

        return result;
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
            final PGPPublicKey pgpPublicKey = pgpCertificate != null ? pgpCertificate : conv.getPGPPublicKey(OpenPGPUtils.getKeyAlgorithm(x509Cert), x509Cert.getPublicKey(), x509Cert.getNotBefore());

            PGPSignatureGenerator generator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpPublicKey.getAlgorithm(), digestAlgorithm).setProvider(crypto.getProvider()).setDigestProvider("BC"));

            // TODO: is this the right signatureType?
            generator.init(generateRevocationCertificate ?
                           PGPSignature.KEY_REVOCATION :
                           PGPSignature.DEFAULT_CERTIFICATION,
                           new JcaPGPPrivateKey(pgpPublicKey, crypto.getPrivateKey()));

            PGPSignatureSubpacketGenerator subGenerator = new PGPSignatureSubpacketGenerator();
            PGPSignatureSubpacketGenerator nonHashedSubGenerator = new PGPSignatureSubpacketGenerator();
            
            // Validity time
            if (selfsignedValidity != null) {    
                subGenerator.setKeyExpirationTime(true, selfsignedValidity);
            } else {
                LOG.error("No SELFSIGNED_VALIDITY so not setting any expiration");
            }

            if (generateRevocationCertificate) {
                subGenerator.setRevocationReason(false, (byte) 0x00, "");
                nonHashedSubGenerator.setIssuerKeyID(false, pgpPublicKey.getKeyID());
            }

            generator.setHashedSubpackets(subGenerator.generate());
            generator.setUnhashedSubpackets(nonHashedSubGenerator.generate());

            // Generate and add certification
            final OpenPgpCertReqData result;
            if (generateRevocationCertificate) {
                final PGPSignature certification = generator.generateCertification(pgpPublicKey);
                final String revocationHeader = getRevocationHeader(pgpPublicKey);
                result = new OpenPgpCertReqData(certification, true, ".rev",
                                                revocationHeader,
                                                "This is a revocation certificate");
            } else {
                final PGPSignature certification = generator.generateCertification(reqInfo.getSubjectDN(), pgpPublicKey);
                final PGPPublicKey certifiedKey = PGPPublicKey.addCertification(pgpPublicKey, reqInfo.getSubjectDN(), certification);
                result = new OpenPgpCertReqData(certifiedKey);
            }

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

    private String getRevocationHeader(final PGPPublicKey publicKey) {
        final StringBuilder sb = new StringBuilder();

        sb.append("This is a revocation certificate for the OpenPGP key:")
          .append("\n")
          .append("Fingerprint: ").append(Hex.toHexString(publicKey.getFingerprint()).toUpperCase(Locale.ENGLISH))
          .append("\n")
          .append("User IDs:").append("\n");

        final Iterator userIDs = publicKey.getUserIDs();
        while (userIDs.hasNext()) {
            Object o = userIDs.next();
            if (o instanceof String) {
                sb.append("   ").append((String) o).append("\n");
            }
        }

        sb.append("\n")
          .append("To avoid an accidental use of this file,")
          .append("\n")
          .append("a colon has been inserted before the five dashes")
          .append("\n")
          .append("Remove this colon before using the revocation certificate")
          .append("\n")
          .append(":");

        return sb.toString();
    }
    
    @Override
    protected ICryptoInstance acquireDefaultCryptoInstance(Map<String, Object> params, String alias, RequestContext context) throws CryptoTokenOfflineException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter, IllegalRequestException, SignServerException {
        final Map<String, Object> newParams = new HashMap<>(params);
        newParams.put(PARAM_INCLUDE_DUMMYCERTIFICATE, true);
        return super.acquireDefaultCryptoInstance(newParams, alias, context);
    }
    
    @Override
    public WorkerStatusInfo getStatus(final List<String> additionalFatalErrors, final IServices services) {
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

                PGPPublicKey pgpPublicKey = conv.getPGPPublicKey(OpenPGPUtils.getKeyAlgorithm(x509Cert), x509Cert.getPublicKey(), x509Cert.getNotBefore());

                status.getCompleteEntries().add(new WorkerStatusInfo.Entry("Key ID", OpenPGPUtils.formatKeyID(pgpPublicKey.getKeyID())));
                status.getCompleteEntries().add(new WorkerStatusInfo.Entry("Primary key fingerprint", Hex.toHexString(pgpPublicKey.getFingerprint()).toUpperCase(Locale.ENGLISH)));

                // Empty public key
                if (pgpCertificate != null) {
                    ByteArrayOutputStream bout = new ByteArrayOutputStream();
                    ArmoredOutputStream out2 = new ArmoredOutputStream(bout);
                    pgpCertificate.encode(out2);
                    out2.close();

                    status.getCompleteEntries().add(new WorkerStatusInfo.Entry("PGP Public key", new String(bout.toByteArray(), StandardCharsets.US_ASCII)));

                    status.getCompleteEntries().add(new WorkerStatusInfo.Entry("PGP Key ID", OpenPGPUtils.formatKeyID(pgpCertificate.getKeyID())));

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
