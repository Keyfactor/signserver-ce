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

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.signserver.common.CompileTimeSettings;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import static org.signserver.server.cryptotokens.ICryptoTokenV4.PARAM_INCLUDE_DUMMYCERTIFICATE;

/**
 * Signer for OpenPGP.
 *
 * Input: Content to sign
 * Output: OpenPGP ASCII Armored or binary signature
 *
 * @author Markus Kilås
 * @version $Id: SkeletonSigner.java 7050 2016-02-17 14:49:30Z netmackan $
 */
public class OpenPGPSigner extends BaseOpenPGPSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(OpenPGPSigner.class);

    // Worker properties    
    public static final String PROPERTY_RESPONSE_FORMAT = "RESPONSE_FORMAT";
    public static final String DETACHEDSIGNATURE_PROPERTY = "DETACHEDSIGNATURE";
    
    // Log fields
    //...

    // Default values
    private static final ResponseFormat DEFAULT_RESPONSE_FORMAT = ResponseFormat.ARMORED;
    
    // Content types
    private static final String REQUEST_CONTENT_TYPE = "application/octet-stream";
    private static final String RESPONSE_CONTENT_TYPE = "application/pgp-signature"; // [https://tools.ietf.org/html/rfc3156]
    
    // Configuration values     
    private ResponseFormat responseFormat = DEFAULT_RESPONSE_FORMAT;    
    private boolean detachedSignature;     
    //...

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
                        
        // Optional property RESPONSE_FORMAT
        final String responseFormatValue = config.getProperty(PROPERTY_RESPONSE_FORMAT);
        if (responseFormatValue != null) {
            try {
                responseFormat = ResponseFormat.valueOf(responseFormatValue.trim());
            } catch (IllegalArgumentException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Illegal value for " + PROPERTY_RESPONSE_FORMAT, ex);
                }
                configErrors.add("Illegal value for " + PROPERTY_RESPONSE_FORMAT + ". Possible values are: " + Arrays.toString(ResponseFormat.values()));
            }
        }       

        // Detached signature
        final String detachedSignatureValue = config.getProperty(DETACHEDSIGNATURE_PROPERTY);
        if (detachedSignatureValue == null) {
            configErrors.add("Please provide " + DETACHEDSIGNATURE_PROPERTY + " as TRUE or FALSE");
        } else {
            if (Boolean.FALSE.toString().equalsIgnoreCase(detachedSignatureValue)) {
                detachedSignature = false;
                if (responseFormat == ResponseFormat.BINARY) {
                    configErrors.add(PROPERTY_RESPONSE_FORMAT + " can be only set as " + ResponseFormat.ARMORED.toString() + " when " + DETACHEDSIGNATURE_PROPERTY + " is FALSE");
                }
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
            try {
                final Map<String, Object> params = new HashMap<>();
                params.put(PARAM_INCLUDE_DUMMYCERTIFICATE, true);
                cryptoInstance = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, signRequest, params, requestContext);

                // signature value
                final JcaPGPKeyConverter conv = new JcaPGPKeyConverter();
                signerCert = (X509Certificate) getSigningCertificate(cryptoInstance);
                final PGPPublicKey pgpPublicKey = conv.getPGPPublicKey(OpenPGPUtils.getKeyAlgorithm(signerCert), signerCert.getPublicKey(), signerCert.getNotBefore());
                PGPPrivateKey pgpPrivateKey = new org.bouncycastle.openpgp.operator.jcajce.JcaPGPPrivateKey(pgpPublicKey, cryptoInstance.getPrivateKey());

                final PGPSignatureGenerator generator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpPublicKey.getAlgorithm(), digestAlgorithm).setProvider(cryptoInstance.getProvider()).setDigestProvider("BC"));

                if (detachedSignature) {
                    try (final BCPGOutputStream bOut = createOutputStreamForDetachedSignature(responseData.getAsOutputStream(), responseFormat);
                            final InputStream fIn = new BufferedInputStream(requestData.getAsInputStream())) {
                        generator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivateKey);

                        final byte[] buffer = new byte[4096];
                        int n = 0;
                        while (-1 != (n = fIn.read(buffer))) {
                            generator.update(buffer, 0, n);
                        }
                        generator.generate().encode(bOut);
                    }
                } else {
                    try (InputStream in = requestData.getAsInputStream();
                            OutputStream out = responseData.getAsOutputStream()) {
                        signClearText(pgpPrivateKey, pgpPublicKey, generator, in, out, digestAlgorithm);
                    }
                }

            } catch (PGPException ex) {
                throw new SignServerException("PGP exception", ex);
            } catch (InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter ex) {
                throw new SignServerException("Error initializing signer", ex);
            } finally {
                releaseCryptoInstance(cryptoInstance, requestContext);
            }

            // Create the archivables (request and response)
            final String archiveId = createArchiveId(new byte[0], (String) requestContext.get(RequestContext.TRANSACTION_ID));
            final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST, REQUEST_CONTENT_TYPE, requestData, archiveId), 
                    new DefaultArchivable(Archivable.TYPE_RESPONSE, RESPONSE_CONTENT_TYPE, responseData.toReadableData(), archiveId));

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
                  
    private BCPGOutputStream createOutputStreamForDetachedSignature(OutputStream out, ResponseFormat responseFormat) {
        switch (responseFormat) {
            case ARMORED:
                final ArmoredOutputStream aOut = new ArmoredOutputStream(out);
                
                aOut.setHeader(ArmoredOutputStream.VERSION_HDR,
                               CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_VERSION));
                return new BCPGOutputStream(aOut);
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
