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
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
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

    public static final String CONTENT_OID_PROPERTY = "CONTENTOID";
    public static final String ALLOW_CONTENTOID_OVERRIDE = "ALLOW_CONTENTOID_OVERRIDE";
    private static final ASN1ObjectIdentifier DEFAULT_CONTENT_OID =
            CMSObjectIdentifiers.data;
    
    private LinkedList<String> configErrors;
    private String signatureAlgorithm;

    private boolean detachedSignature;
    private boolean allowDetachedSignatureOverride;

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
        
        final String contentOIDString = config.getProperty(CONTENT_OID_PROPERTY);
        if (contentOIDString != null && !contentOIDString.isEmpty()) {
            try {
                contentOID = new ASN1ObjectIdentifier(contentOIDString);
            } catch (IllegalArgumentException e) {
                configErrors.add("Illegal content OID specified: " + contentOIDString);
            }
        } else {
            contentOID = DEFAULT_CONTENT_OID;
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
        X509Certificate cert = null;
        List<Certificate> certs = null;
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
            
            final CMSSignedDataStreamGenerator generator
                    = new CMSSignedDataStreamGenerator();
            final String sigAlg = signatureAlgorithm == null ? getDefaultSignatureAlgorithm(crypto.getPublicKey()) : signatureAlgorithm;
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
            try (
                    final OutputStream responseOutputStream = requestData.isFile() && !detached ? responseData.getAsFileOutputStream() : responseData.getAsInMemoryOutputStream();
                    final OutputStream out = generator.open(responseOutputStream, !detached);
                    final InputStream requestIn = requestData.getAsInputStream();
                ) {
                IOUtils.copyLarge(requestIn, out);
            }

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
    
    private static ASN1ObjectIdentifier getRequestedContentOID(final RequestContext context) {
        ASN1ObjectIdentifier result = null;
        final String value = RequestMetadata.getInstance(context).get(CONTENT_OID_PROPERTY);
        if (value != null && !value.isEmpty()) {
            result = new ASN1ObjectIdentifier(value);
        }
        return result;
    }
}
