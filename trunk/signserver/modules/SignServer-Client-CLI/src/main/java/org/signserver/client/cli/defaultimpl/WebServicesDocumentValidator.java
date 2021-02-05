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
package org.signserver.client.cli.defaultimpl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLSocketFactory;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.signserver.client.api.ISignServerWorker;
import org.signserver.client.api.SigningAndValidationWS;
import org.signserver.common.*;

/**
 * DocumentValidator using web services.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class WebServicesDocumentValidator extends AbstractDocumentValidator {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(WebServicesDocumentValidator.class);

    private String workerName;

    private ISignServerWorker signServer;

    private Random random = new Random();
    
    private Map<String, String> metadata;

    public WebServicesDocumentValidator(final String host, final int port,
            final String servlet, final boolean useHTTPS, final String workerName,
            final String username, final String password,
            final SSLSocketFactory socketFactory,
            final Map<String, String> metadata) {
        this.signServer = new SigningAndValidationWS(host, port, servlet, useHTTPS,
                username, password, socketFactory);
        this.workerName = workerName;
        this.metadata = metadata;
    }

    @Override
    protected void doValidate(final InputStream data, final long size, final String encoding,
            final OutputStream out, final Map<String,Object> requestContext) throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException,
                IOException {

        final int requestId = random.nextInt();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending validation request with ID " + requestId
                    + " containing data of length " + size + " bytes"
                    + " to worker " + workerName);
        }

        // Take start time
        final long startTime = System.nanoTime();
        
        final RemoteRequestContext context = new RemoteRequestContext();
        RequestMetadata requestMetadata = new RequestMetadata();
        context.setMetadata(requestMetadata);
        
        if (metadata != null) {
            requestMetadata.putAll(metadata);
        }

        final ProcessResponse response = signServer.process(workerName,
                new GenericValidationRequest(requestId, IOUtils.toByteArray(data)), context);

        // Take stop time
        final long estimatedTime = System.nanoTime() - startTime;

        if(response instanceof GenericValidationResponse) {
            final GenericValidationResponse signResponse =
                    (GenericValidationResponse) response;

            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Got validation response with ID %d, "
                        + "signed data of length %d bytes "
                        + "signed by signer with certificate:\n%s.",
                        signResponse.getRequestID(),
                        signResponse.getProcessedData().length,
                        signResponse.getSignerCertificate()));
            }

            out.write(("Valid: " + signResponse.isValid()).getBytes());
            out.write("\n".getBytes());

            LOG.info("Processing took "
                    + TimeUnit.NANOSECONDS.toMillis(estimatedTime) + " ms");
        } else {
            throw new SignServerException("Unexpected response type: "
                    + response.getClass().getName());
        }
    }
}
