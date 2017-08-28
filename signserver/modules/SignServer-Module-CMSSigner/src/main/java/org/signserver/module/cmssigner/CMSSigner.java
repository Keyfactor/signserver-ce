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
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import javax.persistence.EntityManager;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
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
import org.signserver.server.signers.BaseSigner;

/**
 * A Signer signing arbitrary content and produces the result in
 * Cryptographic Message Syntax (CMS) - RFC 3852.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CMSSigner extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CMSSigner.class);

    /** Content-type for the produced data. */
    private static final String CONTENT_TYPE = "application/pkcs7-signature";
    
    // Property constants
    public static final String SIGNATUREALGORITHM_PROPERTY = "SIGNATUREALGORITHM";
    public static final String DETACHEDSIGNATURE_PROPERTY = "DETACHEDSIGNATURE";
    public static final String ALLOW_SIGNATURETYPE_OVERRIDE_PROPERTY = "ALLOW_DETACHEDSIGNATURE_OVERRIDE";
    public static final String CLIENTSIDEHASHING = "CLIENTSIDEHASHING";
    public static final String ALLOW_CLIENTSIDEHASHING_OVERRIDE = "ALLOW_CLIENTSIDEHASHING_OVERRIDE";
    public static final String ACCEPTED_HASHDIGEST_ALGORITHMS = "ACCEPTED_HASH_DIGEST_ALGORITHMS";
    
    public static final String CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY = "CLIENTSIDE_HASHDIGESTALGORITHM";
    public static final String USING_CLIENTSUPPLIED_HASH_PROPERTY = "USING_CLIENTSUPPLIED_HASH";
    
    public static final String CONTENT_OID_PROPERTY = "CONTENTOID";
    public static final String ALLOW_CONTENTOID_OVERRIDE = "ALLOW_CONTENTOID_OVERRIDE";
    private static final ASN1ObjectIdentifier DEFAULT_CONTENT_OID =
            CMSObjectIdentifiers.data;
    
    public static final String DER_RE_ENCODE_PROPERTY = "DER_RE_ENCODE";
    
    private LinkedList<String> configErrors;
    private String signatureAlgorithm;

    private boolean detachedSignature;
    private boolean allowDetachedSignatureOverride;
    private boolean clientSideHashing;
    private boolean allowClientSideHashingOverride;
    private boolean derReEncode;
    
    private Set<AlgorithmIdentifier> acceptedHashDigestAlgorithms;

    private ASN1ObjectIdentifier contentOID;
    private boolean allowContentOIDOverride;
    
    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Configuration errors
        configErrors = new LinkedList<>();

        // Get the signature algorithm
        signatureAlgorithm = config.getProperty(SIGNATUREALGORITHM_PROPERTY);

        // Detached signature
        final String detachedSignatureValue = config.getProperty(DETACHEDSIGNATURE_PROPERTY);
        if (detachedSignatureValue == null || Boolean.FALSE.toString().equalsIgnoreCase(detachedSignatureValue)) {
            detachedSignature = false;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(detachedSignatureValue)) {
            detachedSignature = true;
        } else {
            configErrors.add("Incorrect value for property " + DETACHEDSIGNATURE_PROPERTY + ". Expecting TRUE or FALSE.");
        }

        // Allow detached signature override
        final String allowDetachedSignatureOverrideValue = config.getProperty(ALLOW_SIGNATURETYPE_OVERRIDE_PROPERTY);
        if (allowDetachedSignatureOverrideValue == null || Boolean.FALSE.toString().equalsIgnoreCase(allowDetachedSignatureOverrideValue)) {
            allowDetachedSignatureOverride = false;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(allowDetachedSignatureOverrideValue)) {
            allowDetachedSignatureOverride = true;
        } else {
            configErrors.add("Incorrect value for property " + ALLOW_SIGNATURETYPE_OVERRIDE_PROPERTY + ". Expecting TRUE or FALSE.");
        }
        
        final String clientSideHashingValue = config.getProperty(CLIENTSIDEHASHING);
        if (clientSideHashingValue == null || clientSideHashingValue.isEmpty() ||
            Boolean.FALSE.toString().equalsIgnoreCase(clientSideHashingValue)) {
            clientSideHashing = false;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(clientSideHashingValue)) {
            clientSideHashing = true;
        } else {
            configErrors.add("Incorrect value for property " + CLIENTSIDEHASHING + ". Expecting TRUE or FALSE.");
        }
        
        final String allowClientSideHashingOverrideValue = config.getProperty(ALLOW_CLIENTSIDEHASHING_OVERRIDE);
        if (allowClientSideHashingOverrideValue == null ||
            allowClientSideHashingOverrideValue.isEmpty() ||
            Boolean.FALSE.toString().equalsIgnoreCase(allowClientSideHashingOverrideValue)) {
            allowClientSideHashingOverride = false;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(allowClientSideHashingOverrideValue)) {
            allowClientSideHashingOverride = true;
        } else {
            configErrors.add("Incorrect value for property " + ALLOW_CLIENTSIDEHASHING_OVERRIDE + ". Expecting TRUE or FALSE.");
        }
        
        initAcceptedHashDigestAlgorithms();
        
        /* require ACCEPTED_HASHDIGEST_ALGORITHMS to be set when either
         * CLIENTSIDEHASHING is set to true or ALLOW_CLIENTSIDEHASHING_OVERRIDE
         * is set to true
         */
        if (acceptedHashDigestAlgorithms == null &&
            (allowClientSideHashingOverride || clientSideHashing)) {
            configErrors.add("Must specify " + ACCEPTED_HASHDIGEST_ALGORITHMS +
                             " when " + CLIENTSIDEHASHING + " or " +
                             ALLOW_CLIENTSIDEHASHING_OVERRIDE + " is true");
        }
        
        final String contentOIDString = config.getProperty(CONTENT_OID_PROPERTY);
        if (contentOIDString != null && !contentOIDString.isEmpty()) {
            try {
                contentOID = new ASN1ObjectIdentifier(contentOIDString);
            } catch (IllegalArgumentException e) {
                configErrors.add("Illegal content OID specified: " + contentOIDString);
            }
        } else {
            contentOID = getDefaultContentOID();
        }
        
        final String allowContentOIDOverrideValue = config.getProperty(ALLOW_CONTENTOID_OVERRIDE);
        if (allowContentOIDOverrideValue == null ||
            allowContentOIDOverrideValue.isEmpty() ||
            Boolean.FALSE.toString().equalsIgnoreCase(allowContentOIDOverrideValue)) {
            allowContentOIDOverride = false;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(allowContentOIDOverrideValue)) {
            allowContentOIDOverride = true;
        } else {
            configErrors.add("Incorrect value for property " + ALLOW_CONTENTOID_OVERRIDE + ". Expecting TRUE or FALSE.");
        }

        // DER re-encode
        final String derReEncodeValue = config.getProperty(DER_RE_ENCODE_PROPERTY);
        if (derReEncodeValue == null || Boolean.FALSE.toString().equalsIgnoreCase(derReEncodeValue)) {
            derReEncode = false;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(derReEncodeValue)) {
            derReEncode = true;
        } else {
            configErrors.add("Incorrect value for property " + DER_RE_ENCODE_PROPERTY + ". Expecting TRUE or FALSE.");
        }
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

    private void initAcceptedHashDigestAlgorithms() {
        final String acceptedHashDigestAlgorithmsValue =
                config.getProperty(ACCEPTED_HASHDIGEST_ALGORITHMS);
        final DigestAlgorithmIdentifierFinder algFinder = new DefaultDigestAlgorithmIdentifierFinder();
        
        if (acceptedHashDigestAlgorithmsValue != null &&
            !acceptedHashDigestAlgorithmsValue.isEmpty()) {
            acceptedHashDigestAlgorithms = new HashSet<>();
            for (final String digestAlgorithmString :
                 acceptedHashDigestAlgorithmsValue.split(",")) {
                final String digestAlgorithmStringTrim = digestAlgorithmString.trim();
                final AlgorithmIdentifier alg = algFinder.find(digestAlgorithmStringTrim);
                
                if (alg == null || alg.getAlgorithm() == null) {
                    configErrors.add("Illegal algorithm specified for " + ACCEPTED_HASHDIGEST_ALGORITHMS + ": " +
                                     digestAlgorithmStringTrim);
                } else {
                    acceptedHashDigestAlgorithms.add(alg);
                }
            }
        }
        
    }

    
    private boolean shouldUseClientSideHashing(final RequestContext requestContext)
            throws IllegalRequestException {
        final boolean useClientSideHashing;
        final Boolean clientSideHashingRequested =
            getClientSuppliedHashRequest(requestContext);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Client-side hashing configured: " + clientSideHashing + "\n"
                    + "Client-side hashing requested: " + clientSideHashingRequested);
        }
        if (clientSideHashingRequested == null) {
            useClientSideHashing = clientSideHashing;
        } else {
            if (clientSideHashingRequested) {
                if (!clientSideHashing && !allowClientSideHashingOverride) {
                    throw new IllegalRequestException("Client-side hashing requested but not allowed");
                }
            } else {
                if (clientSideHashing && !allowClientSideHashingOverride) {
                    throw new IllegalRequestException("Server-side hashing requested but not allowed");
                }
            }
            
            final Boolean requestDetached =
                    getDetachedSignatureRequest(requestContext);
            if (requestDetached != null && !requestDetached && !detachedSignature) {
                throw new IllegalRequestException("Client-side hashing can only be used with detached signatures");
            }
   
            useClientSideHashing = clientSideHashingRequested;
        }

        return useClientSideHashing;
    }
    
    protected final AlgorithmIdentifier getClientSideHashAlgorithm(final RequestContext requestContext)
            throws IllegalRequestException {
        AlgorithmIdentifier alg = null;
        final String value = RequestMetadata.getInstance(requestContext).get(CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY);
        if (value != null && !value.isEmpty()) {
            final DigestAlgorithmIdentifierFinder algFinder =
                    new DefaultDigestAlgorithmIdentifierFinder();
            alg = algFinder.find(value);
        }

        if (alg == null) {
            throw new IllegalRequestException("Client-side hashing request must specify hash algorithm used");
        }
        
        /* DefaultDigestAlgorithmIdentifierFinder returns an AlgorithmIdentifer
         * with a null algorithm for an unknown algorithm
         */
        if (alg.getAlgorithm() == null) {
            throw new IllegalRequestException("Client specified an unknown digest algorithm");
        }
        
        if (acceptedHashDigestAlgorithms != null &&
            !acceptedHashDigestAlgorithms.isEmpty() &&
            !acceptedHashDigestAlgorithms.contains(alg)) {
            throw new IllegalRequestException("Client specified a non-accepted digest hash algorithm");
        }
        
        return alg;
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
        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                 new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                 .build(contentSigner, cert));
        
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
                    final DEROutputStream derOut = new DEROutputStream(responseOutputStream);
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
        final AlgorithmIdentifier alg = getClientSideHashAlgorithm(requestContext);
        
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
        
        responseData.getAsInMemoryOutputStream().write(signedData.getEncoded());
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

            sign(crypto, cert, certs, sigAlg, requestContext, requestData,
                         responseData, contentOIDToUse);

            final String archiveId = createArchiveId(new byte[0], (String) requestContext.get(RequestContext.TRANSACTION_ID));
            final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, responseData.toReadableData(), archiveId));

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
    
    /**
     * Read the request metadata property for USING_CLIENTSUPPLIED_HASH if any.
     * Note that empty String is treated as an unset property.
     * @param context to read from
     * @return null if no USING_CLIENTSUPPLIED_HASH request property specified otherwise
     * true or false.
     */
    private static Boolean getClientSuppliedHashRequest(final RequestContext context) {
        Boolean result = null;
        final String value = RequestMetadata.getInstance(context).get(USING_CLIENTSUPPLIED_HASH_PROPERTY);
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
                shouldUseClientSideHashing(requestContext);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Using client-side supplied hash");
        }
        if (useClientSideHashing) {
            signHash(crypto, cert, certs, sigAlg, requestContext, requestData,
                     responseData, contentOIDToUse);
        } else {
            signData(crypto, cert, certs, sigAlg, requestContext, requestData,
                     responseData, contentOIDToUse);
        }
    }
}
