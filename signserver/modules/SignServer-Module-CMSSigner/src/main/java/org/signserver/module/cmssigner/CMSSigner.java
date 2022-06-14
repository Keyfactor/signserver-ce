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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
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
import static org.signserver.module.cmssigner.ClientSideHashingHelper.ALLOW_CLIENTSIDEHASHING_OVERRIDE;
import static org.signserver.module.cmssigner.ClientSideHashingHelper.CLIENTSIDEHASHING;
import static org.signserver.module.cmssigner.ClientSideHashingHelper.CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY;
import org.signserver.server.HashDigestUtils;

/**
 * A Signer signing arbitrary content and produces the result in
 * Cryptographic Message Syntax (CMS) - RFC 3852.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CMSSigner extends BaseSigner {

    private static final Logger LOG = Logger.getLogger(CMSSigner.class);

    /** Content-type for the produced data. */
    private static final String CONTENT_TYPE = "application/pkcs7-signature";
    
    // Property constants
    public static final String SIGNATUREALGORITHM_PROPERTY = "SIGNATUREALGORITHM";
    public static final String DETACHEDSIGNATURE_PROPERTY = "DETACHEDSIGNATURE";
    public static final String ALLOW_SIGNATURETYPE_OVERRIDE_PROPERTY = "ALLOW_DETACHEDSIGNATURE_OVERRIDE";
    
    
    public static final String CONTENT_OID_PROPERTY = "CONTENTOID";
    public static final String ALLOW_CONTENTOID_OVERRIDE = "ALLOW_CONTENTOID_OVERRIDE";
    private static final ASN1ObjectIdentifier DEFAULT_CONTENT_OID =
            CMSObjectIdentifiers.data;
    
    public static final String DER_RE_ENCODE_PROPERTY = "DER_RE_ENCODE";
    
    public static final String DIRECTSIGNATURE_PROPERTY = "DIRECTSIGNATURE";

    /** If the request digest should be created and logged. */
    public static final String DO_LOGREQUEST_DIGEST = "DO_LOGREQUEST_DIGEST";

    /** If the response digest should be created and logged. */
    public static final String DO_LOGRESPONSE_DIGEST = "DO_LOGRESPONSE_DIGEST";

    /** Algorithm for the request digest put in the log. */
    public static final String LOGREQUEST_DIGESTALGORITHM_PROPERTY = "LOGREQUEST_DIGESTALGORITHM";

    /** Algorithm for the request digest put in the log. */
    public static final String LOGRESPONSE_DIGESTALGORITHM_PROPERTY = "LOGRESPONSE_DIGESTALGORITHM";

    private static final boolean DEFAULT_DO_LOGREQUEST_DIGEST = false;
    private static final String DEFAULT_LOGREQUEST_DIGESTALGORITHM = "SHA256";
    private static final boolean DEFAULT_DO_LOGRESPONSE_DIGEST = false;
    private static final String DEFAULT_LOGRESPONSE_DIGESTALGORITHM = "SHA256";

    private LinkedList<String> configErrors;
    private String signatureAlgorithm;

    private boolean detachedSignature;
    private boolean allowDetachedSignatureOverride;
    private boolean derReEncode;
    private boolean directSignature;

    private String logRequestDigestAlgorithm;
    private String logResponseDigestAlgorithm;
    private boolean doLogRequestDigest;
    private boolean doLogResponseDigest;

    private ASN1ObjectIdentifier contentOID;
    private boolean allowContentOIDOverride;
    
    protected final ClientSideHashingHelper clientSideHelper = new ClientSideHashingHelper();
    
    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager entityManager) {
        super.init(workerId, config, workerContext, entityManager);

        // Configuration errors
        configErrors = new LinkedList<>();

        // Get the signature algorithm
        signatureAlgorithm = config.getProperty(SIGNATUREALGORITHM_PROPERTY, DEFAULT_NULL);
        
        // Detached signature
        final String detachedSignatureValue = config.getProperty(DETACHEDSIGNATURE_PROPERTY, Boolean.FALSE.toString());
        if (Boolean.FALSE.toString().equalsIgnoreCase(detachedSignatureValue)) {
            detachedSignature = false;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(detachedSignatureValue)) {
            detachedSignature = true;
        } else {
            configErrors.add("Incorrect value for property " + DETACHEDSIGNATURE_PROPERTY + ". Expecting TRUE or FALSE.");
        }

        // Allow detached signature override
        final String allowDetachedSignatureOverrideValue = config.getProperty(ALLOW_SIGNATURETYPE_OVERRIDE_PROPERTY, Boolean.FALSE.toString());
        if (Boolean.FALSE.toString().equalsIgnoreCase(allowDetachedSignatureOverrideValue)) {
            allowDetachedSignatureOverride = false;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(allowDetachedSignatureOverrideValue)) {
            allowDetachedSignatureOverride = true;
        } else {
            configErrors.add("Incorrect value for property " + ALLOW_SIGNATURETYPE_OVERRIDE_PROPERTY + ". Expecting TRUE or FALSE.");
        }
        
        
        clientSideHelper.init(config, configErrors);
        
        
        
        final String contentOIDString = config.getProperty(CONTENT_OID_PROPERTY, DEFAULT_NULL);
        if (contentOIDString != null && !contentOIDString.isEmpty()) {
            try {
                contentOID = new ASN1ObjectIdentifier(contentOIDString);
            } catch (IllegalArgumentException e) {
                configErrors.add("Illegal content OID specified: " + contentOIDString);
            }
        } else {
            contentOID = getDefaultContentOID();
        }
        
        final String allowContentOIDOverrideValue = config.getProperty(ALLOW_CONTENTOID_OVERRIDE, Boolean.FALSE.toString());
        if (Boolean.FALSE.toString().equalsIgnoreCase(allowContentOIDOverrideValue)) {
            allowContentOIDOverride = false;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(allowContentOIDOverrideValue)) {
            allowContentOIDOverride = true;
        } else {
            configErrors.add("Incorrect value for property " + ALLOW_CONTENTOID_OVERRIDE + ". Expecting TRUE or FALSE.");
        }

        // DER re-encode
        final String derReEncodeValue = config.getProperty(DER_RE_ENCODE_PROPERTY, Boolean.FALSE.toString());
        if (Boolean.FALSE.toString().equalsIgnoreCase(derReEncodeValue)) {
            derReEncode = false;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(derReEncodeValue)) {
            derReEncode = true;
        } else {
            configErrors.add("Incorrect value for property " + DER_RE_ENCODE_PROPERTY + ". Expecting TRUE or FALSE.");
        }
        
        // Direct signature (no signed attributes)
        final String directSignatureValue = config.getProperty(DIRECTSIGNATURE_PROPERTY, Boolean.FALSE.toString());
        if (Boolean.FALSE.toString().equalsIgnoreCase(directSignatureValue.trim())) {
            directSignature = false;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(directSignatureValue.trim())) {
            directSignature = true;
        } else {
            configErrors.add("Incorrect value for property " + DIRECTSIGNATURE_PROPERTY + ". Expecting TRUE or FALSE.");
        }
        
        if (directSignature && clientSideHelper.isClientSideHashing()) {
            configErrors.add("Can not combine " + CLIENTSIDEHASHING + " and " + DIRECTSIGNATURE_PROPERTY);
        }
        
        if (directSignature && clientSideHelper.isAllowClientSideHashingOverride()) {
            configErrors.add("Can not combine " + ALLOW_CLIENTSIDEHASHING_OVERRIDE + " and " + DIRECTSIGNATURE_PROPERTY);
        }
        
        // If the request digest should computed and be logged
        String s = config.getProperty(DO_LOGREQUEST_DIGEST, Boolean.toString(DEFAULT_DO_LOGREQUEST_DIGEST));
        if ("true".equalsIgnoreCase(s)) {
            doLogRequestDigest = true;
        } else if ("false".equalsIgnoreCase(s)) {
            doLogRequestDigest = false;
        } else {
            configErrors.add("Incorrect value for " + DO_LOGREQUEST_DIGEST);
        }

        // If the response digest should computed and be logged
        s = config.getProperty(DO_LOGRESPONSE_DIGEST, Boolean.toString(DEFAULT_DO_LOGRESPONSE_DIGEST));
        if ("true".equalsIgnoreCase(s)) {
            doLogResponseDigest = true;
        } else if ("false".equalsIgnoreCase(s)) {
            doLogResponseDigest = false;
        } else {
            configErrors.add("Incorrect value for " + DO_LOGRESPONSE_DIGEST);
        }

        // Get the log digest algorithms
        logRequestDigestAlgorithm = config.getProperty(LOGREQUEST_DIGESTALGORITHM_PROPERTY, DEFAULT_LOGREQUEST_DIGESTALGORITHM);
        logResponseDigestAlgorithm = config.getProperty(LOGRESPONSE_DIGESTALGORITHM_PROPERTY, DEFAULT_LOGRESPONSE_DIGESTALGORITHM);
    }
    
    /**
     * Get the default content OID to use when not explicitly set, or overridden
     * in the request.
     * 
     * @return Content OID
     */
    protected ASN1ObjectIdentifier getDefaultContentOID() {
        return DEFAULT_CONTENT_OID;
    }
    
    /**
     * Returns true if the signer wants to augment the CMSSignedData instance.
     * This can be overridden by extending implementations.
     * 
     * @return True if the implementation expects extendCMSData to be called
     */
    protected boolean extendsCMSData() {
        return false;
    }
    
    /**
     * Augment CMSSignedData object with extended attributes.
     * Must be overridden by extending implementations when extendCMSData
     * returns true.
     * 
     * @param cms Basic CMS signature data
     * @param context Request context
     * @return CMS signature data with additional attributes
     * @throws java.io.IOException
     * @throws org.bouncycastle.cms.CMSException
     */
    protected CMSSignedData extendCMSData(CMSSignedData cms, RequestContext context)
        throws IOException, CMSException {
        throw new UnsupportedOperationException("Base CMS signer doesn't support extending CMS data");
    }

    private void signData(final ICryptoInstance crypto,
                          final X509Certificate cert,
                          final Collection<Certificate> certs,
                          final String sigAlg,
                          final RequestContext requestContext,
                          final ReadableData requestData,
                          final WritableData responseData,
                          final ASN1ObjectIdentifier contentOID)
            throws OperatorCreationException, CertificateEncodingException, CMSException, IllegalRequestException, IOException {
        final CMSSignedDataStreamGenerator generator
                    = new CMSSignedDataStreamGenerator();
        final ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg).setProvider(crypto.getProvider()).build(crypto.getPrivateKey());
        
        JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());
        signerInfoGeneratorBuilder.setDirectSignature(directSignature);
        if ("SPHINCS+".equalsIgnoreCase(sigAlg)) {
            // XXX: Note: the .setContentDigest call above is needed as of BC 1.71 there is no entry for SPHINCS+ in the DefaultDigestAlgorithmIdentifierFinder
            signerInfoGeneratorBuilder.setContentDigest(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
        }
        generator.addSignerInfoGenerator(signerInfoGeneratorBuilder.build(contentSigner, cert));
        generator.addCertificates(new JcaCertStore(certs));
        
        // Should the content be detached or not
        final boolean detached;
        final Boolean detachedRequested = getDetachedSignatureRequest(requestContext);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Detached signature configured: " + detachedSignature + "\n"
                    + "Detached signature requested: " + detachedRequested);
        }
        if (detachedRequested == null) {
            detached = detachedSignature;
        } else {
            if (detachedRequested) {
                if (!detachedSignature && !allowDetachedSignatureOverride) {
                    throw new IllegalRequestException("Detached signature requested but not allowed");
                }
            } else {
                if (detachedSignature && !allowDetachedSignatureOverride) {
                    throw new IllegalRequestException("Non detached signature requested but not allowed");
                }
            }
            detached = detachedRequested;
        }

        // Generate the signature
        if (!derReEncode && !extendsCMSData()) {
            try (
                    final OutputStream responseOutputStream = requestData.isFile() && !detached ? responseData.getAsFileOutputStream() : responseData.getAsInMemoryOutputStream();
                    final OutputStream out = generator.open(contentOID, responseOutputStream, !detached);
                    final InputStream requestIn = requestData.getAsInputStream();
                ) {
                IOUtils.copyLarge(requestIn, out);
            }
        } else {
            // Sign and then parse and re-encode as DER
            // Note, this will not support large files as the above case and will not be as performant.
            if (LOG.isDebugEnabled()) {
                LOG.debug("Signing and then re-encoding as DER");
            }
            final ByteArrayOutputStream bout = new ByteArrayOutputStream();
            try (
                    final OutputStream out = generator.open(contentOID, bout, !detached);
                    final InputStream requestIn = requestData.getAsInputStream();
                ) {
                IOUtils.copyLarge(requestIn, out);
            }
            
            CMSSignedData signedData = new CMSSignedData(bout.toByteArray());
            
            if (extendsCMSData()) {
                signedData = extendCMSData(signedData, requestContext);
            } 
            
            try (final OutputStream responseOutputStream = requestData.isFile() && !detached ? responseData.getAsFileOutputStream() : responseData.getAsInMemoryOutputStream();) {
                if (derReEncode) {
                    final ASN1OutputStream derOut =
                            ASN1OutputStream.create(responseOutputStream,
                                                    ASN1Encoding.DER);
                    derOut.writeObject(signedData.toASN1Structure());
                } else {
                    responseOutputStream.write(signedData.getEncoded());
                }
            }
        }

    }
    
    private void signHash(final ICryptoInstance crypto,
                          final X509Certificate cert,
                          final Collection<Certificate> certs,
                          final String sigAlg,
                          final RequestContext requestContext,
                          final ReadableData requestData,
                          final WritableData responseData,
                          final ASN1ObjectIdentifier contentOID)
            throws OperatorCreationException, CertificateEncodingException, CMSException, IOException, IllegalRequestException {
        final CMSSignedDataGenerator generator
                    = new CMSSignedDataGenerator();
        final ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg).setProvider(crypto.getProvider()).build(crypto.getPrivateKey());
        final byte[] digestData = requestData.getAsByteArray();
        final AlgorithmIdentifier alg = clientSideHelper.getClientSideHashAlgorithm(requestContext);
                
        // Check supplied Hash Digest length
        final String clientSpecifiedHashDigestAlgo = RequestMetadata.getInstance(requestContext).get(CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY);
        boolean isSuppliedHashDigestLengthOk = HashDigestUtils.isSuppliedHashDigestLengthValid(clientSpecifiedHashDigestAlgo, digestData.length);
        if (!isSuppliedHashDigestLengthOk) {
            throw new IllegalRequestException("Client-side hashing data length must match with the length of client specified digest algorithm");
        }
        
        final DigestCalculator digestCalculator = new DigestCalculator() {
            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return alg;
            }

            @Override
            public OutputStream getOutputStream() {
                return new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // do nothing
                    }
                };
            }

            @Override
            public byte[] getDigest() {
                return digestData;
            }
            
        };
        
        final DigestCalculatorProvider calcProv = new DigestCalculatorProvider() {
            @Override
            public DigestCalculator get(AlgorithmIdentifier digestAlgorithmIdentifier) throws OperatorCreationException {
                return digestCalculator;
            }  
        };
        
        final JcaSignerInfoGeneratorBuilder siBuilder = new JcaSignerInfoGeneratorBuilder(calcProv);
        final SignerInfoGenerator sig = siBuilder.build(contentSigner, cert);

        generator.addSignerInfoGenerator(sig);
        generator.addCertificates(new JcaCertStore(certs));
        
        // Generate the signature
        CMSSignedData signedData = generator.generate(new CMSProcessableByteArray(contentOID, "dummy".getBytes()), false);
        
        if (extendsCMSData()) {
            signedData = extendCMSData(signedData, requestContext);
        }

        try (final OutputStream responseOutputStream = responseData.getAsInMemoryOutputStream();) {
            if (derReEncode) {
                final ASN1OutputStream derOut =
                        ASN1OutputStream.create(responseOutputStream,
                                                ASN1Encoding.DER);
                derOut.writeObject(signedData.toASN1Structure());
            } else {
                responseOutputStream.write(signedData.getEncoded());
            }
        }
    }

    @Override
    public Response processData(final Request signRequest,
            final RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
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

        final ReadableData requestData = sReq.getRequestData();
        final WritableData responseData = sReq.getResponseData();
        final X509Certificate cert;
        final List<Certificate> certs;
        ICryptoInstance crypto = null;
        try {
            crypto = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, signRequest, requestContext);
            cert = (X509Certificate) getSigningCertificate(crypto);
            if (LOG.isDebugEnabled()) {
                LOG.debug("SigningCert: " + cert);
            }
            
            // Get certificate chain and signer certificate
            certs = includedCertificates(this.getSigningCertificateChain(crypto));
            if (certs == null) {
                throw new IllegalArgumentException("Null certificate chain. This signer needs a certificate.");
            }
            
            ASN1ObjectIdentifier contentOIDToUse;
            try {
                final ASN1ObjectIdentifier requestedContentOID =
                        getRequestedContentOID(requestContext);
                if (requestedContentOID == null) {
                    contentOIDToUse = contentOID;
                } else {
                    if (!requestedContentOID.equals(contentOID) && !allowContentOIDOverride) {
                        throw new IllegalRequestException("Overriding content OID requested but not allowed");
                    }
                    contentOIDToUse = requestedContentOID;
                }
            } catch (IllegalArgumentException e) {
                throw new IllegalRequestException("Illegal OID specified in request");
            }
            
            final String sigAlg = signatureAlgorithm == null ? getDefaultSignatureAlgorithm(crypto.getPublicKey()) : signatureAlgorithm;

            // Log anything interesting from the request to the worker logger
            final LogMap logMap = LogMap.getInstance(requestContext);

            final byte[] requestDigest;
            if (doLogRequestDigest) {
                logMap.put(IWorkerLogger.LOG_REQUEST_DIGEST_ALGORITHM, logRequestDigestAlgorithm);

                try (InputStream input = requestData.getAsInputStream()) {
                    final MessageDigest md = MessageDigest.getInstance(logRequestDigestAlgorithm, BouncyCastleProvider.PROVIDER_NAME);

                    // Digest all data
                    // TODO: Future optimization: could be done while the file is read instead
                    requestDigest = UploadUtil.digest(input, md);

                    logMap.put(IWorkerLogger.LOG_REQUEST_DIGEST, new Loggable() {
                        @Override
                        public String toString() {
                            return Hex.toHexString(requestDigest);
                        }
                    });
                } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                    LOG.error("Log digest algorithm not supported", ex);
                    throw new SignServerException("Log digest algorithm not supported", ex);
                } catch (IOException ex) {
                    LOG.error("Log request digest failed", ex);
                    throw new SignServerException("Log request digest failed", ex);
                }
            }

            sign(crypto, cert, certs, sigAlg, requestContext, requestData,
                         responseData, contentOIDToUse);

            final String archiveId = createArchiveId(new byte[0], (String) requestContext.get(RequestContext.TRANSACTION_ID));
            final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST, CONTENT_TYPE, requestData, archiveId), 
                    new DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, responseData.toReadableData(), archiveId));

            final byte[] responseDigest;
            if (doLogResponseDigest) {
                logMap.put(IWorkerLogger.LOG_RESPONSE_DIGEST_ALGORITHM, logResponseDigestAlgorithm);

                try (InputStream in = responseData.toReadableData().getAsInputStream()) {
                    final MessageDigest md = MessageDigest.getInstance(logResponseDigestAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
                    responseDigest = UploadUtil.digest(in, md);

                    logMap.put(IWorkerLogger.LOG_RESPONSE_DIGEST,
                               new Loggable() {
                                   @Override
                                   public String toString() {
                                        return Hex.toHexString(responseDigest);
                                   }
                               });
                } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                    LOG.error("Log digest algorithm not supported", ex);
                    throw new SignServerException("Log digest algorithm not supported", ex);
                }
            }

            // Suggest new file name
            final Object fileNameOriginal = requestContext.get(RequestContext.FILENAME);
            if (fileNameOriginal instanceof String) {
                requestContext.put(RequestContext.RESPONSE_FILENAME, fileNameOriginal + ".p7s");
            }
            
            // The client can be charged for the request
            requestContext.setRequestFulfilledByWorker(true);
            
            return new SignatureResponse(sReq.getRequestID(), responseData, cert, archiveId, archivables, CONTENT_TYPE);
        } catch (OperatorCreationException ex) {
            LOG.error("Error initializing signer", ex);
            throw new SignServerException("Error initializing signer", ex);
        } catch (CertificateEncodingException ex) {
            LOG.error("Error constructing cert store", ex);
            throw new SignServerException("Error constructing cert store", ex);
        } catch (CMSException | IOException ex) {
            LOG.error("Error constructing CMS", ex);
            throw new SignServerException("Error constructing CMS", ex);
        } finally {
            releaseCryptoInstance(crypto, requestContext);
        }
    }
    
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

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        final LinkedList<String> errors = new LinkedList<>(super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }

    /**
     * Read the request metadata property for DETACHEDSIGNATURE if any.
     * Note that empty String is treated as an unset property.
     * @param context to read from
     * @return null if no DETACHEDSIGNATURE request property specified otherwise
     * true or false.
     */
    private static Boolean getDetachedSignatureRequest(final RequestContext context) {
        Boolean result = null;
        final String value = RequestMetadata.getInstance(context).get(DETACHEDSIGNATURE_PROPERTY);
        if (value != null && !value.isEmpty()) {
            result = Boolean.parseBoolean(value);
        }
        return result;
    }
    
    private static ASN1ObjectIdentifier getRequestedContentOID(final RequestContext context) {
        ASN1ObjectIdentifier result = null;
        final String value = RequestMetadata.getInstance(context).get(CONTENT_OID_PROPERTY);
        if (value != null && !value.isEmpty()) {
            result = new ASN1ObjectIdentifier(value);
        }
        return result;
    }

    protected void sign(ICryptoInstance crypto, X509Certificate cert, List<Certificate> certs, String sigAlg, RequestContext requestContext, ReadableData requestData, WritableData responseData, ASN1ObjectIdentifier contentOIDToUse) throws IllegalRequestException, OperatorCreationException, CertificateEncodingException, CMSException, IOException {
        final boolean useClientSideHashing =
                clientSideHelper.shouldUseClientSideHashing(requestContext);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Using client-side supplied hash: " + useClientSideHashing);
        }
        if (useClientSideHashing) {
            final Boolean requestDetached =
                getDetachedSignatureRequest(requestContext);
            if (requestDetached != null && !requestDetached && !detachedSignature) {
                throw new IllegalRequestException("Client-side hashing can only be used with detached signatures");
            }
            
            signHash(crypto, cert, certs, sigAlg, requestContext, requestData,
                     responseData, contentOIDToUse);
        } else {
            signData(crypto, cert, certs, sigAlg, requestContext, requestData,
                     responseData, contentOIDToUse);
        }
    } 
}
