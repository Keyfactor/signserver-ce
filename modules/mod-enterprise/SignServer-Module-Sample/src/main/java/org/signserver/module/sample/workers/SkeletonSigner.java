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
package org.signserver.module.sample.workers;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
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
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.server.signers.BaseSigner;

/**
 * Skeleton signer...
 *
  * <p>
 * The signer has the following worker properties:
 * </p>
 * <ul>
 *    <li>
 *       <b>SIGNATUREALGORITHM</b> = Algorithm for signing
 *       (Optional, default: "SHA256withRSA")
 *    </li>
 *    <li>
 *       <b>PROPERTY_NAME...</b> = Description...
 *       (Optional/required, default: ...)
 *    </li>
 * </ul>
 * @author ...
 * @version $Id$
 */
public class SkeletonSigner extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SkeletonSigner.class);

    // Worker properties
    public static final String PROPERTY_SIGNATUREALGORITHM
            = "SIGNATUREALGORITHM";
    //...

    // Log fields
    //...

    // Default values
    private static final String DEFAULT_SIGNATUREALGORITHM = "SHA256withRSA";
    //...

    // Content types
    private static final String REQUEST_CONTENT_TYPE = ""; //...
    private static final String RESPONSE_CONTENT_TYPE = ""; //...

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    private String signatureAlgorithm;
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

        // Read properties
        //...
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
                throw new IllegalRequestException("Unexpected request type");
            }
            final SignatureRequest request = (SignatureRequest) signRequest;

            // Get the data from request
            final ReadableData requestData = request.getRequestData();
            final WritableData responseData = request.getResponseData();
            //...
            
            // Log anything interesting from the request to the worker logger
            //...

            // Produce the result, ie doing the work...
            Certificate signerCert = null;
            ICryptoInstance cryptoInstance = null;
            try (
                    InputStream in = requestData.getAsInputStream();
                    OutputStream out = responseData.getAsOutputStream();
                ) {
                cryptoInstance = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN,
                        signRequest, requestContext);

                // Signature instance
                final Signature signature = Signature.getInstance(
                        signatureAlgorithm, cryptoInstance.getProvider());
                signature.initSign(cryptoInstance.getPrivateKey());
                
                // Feed the data to be signed
                final byte[] buffer = new byte[4096]; 
                int n = 0;
                while (-1 != (n = in.read(buffer))) {
                    signature.update(buffer, 0, n);
                }
                
                // Get the final signature
                byte[] signatureBytes = signature.sign();
                
                // Format the results...
                String result = "Signature: "
                        + Base64.toBase64String(signatureBytes); // ...
                
                // Write the result
                out.write(result.getBytes(StandardCharsets.UTF_8));
            } finally {
                releaseCryptoInstance(cryptoInstance, requestContext);
            }

            // Create the archivables (request and response)
            final String archiveId = createArchiveId(new byte[0],
                    (String) requestContext.get(RequestContext.TRANSACTION_ID));
            final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST,
                            REQUEST_CONTENT_TYPE, requestData, archiveId), 
                    new DefaultArchivable(Archivable.TYPE_RESPONSE,
                            RESPONSE_CONTENT_TYPE,
                            responseData.toReadableData(), archiveId));

            // Suggest new file name
            final Object fileNameOriginal = requestContext.get(
                    RequestContext.FILENAME);
            if (fileNameOriginal instanceof String) {
                requestContext.put(RequestContext.RESPONSE_FILENAME,
                        fileNameOriginal + "");
            }

            // As everyting went well, the client can be charged for the request
            requestContext.setRequestFulfilledByWorker(true);

            // Return the response
            return new SignatureResponse(
                    request.getRequestID(), responseData, signerCert, archiveId,
                    archivables, RESPONSE_CONTENT_TYPE);
        } catch (IOException ex) {
            throw new SignServerException("Encoding error", ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new SignServerException("Configured algorithm not supported",
                    ex);
        } catch (InvalidKeyException | SignatureException ex) {
            throw new SignServerException("Error signing", ex);
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

}
