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
import java.io.OutputStream;
import java.util.Random;
import java.util.concurrent.TimeUnit;
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

    public WebServicesDocumentValidator(final String host, final int port,
            final String servlet, final boolean useHTTPS, final String workerName,
            final String username, final String password) {
        this.signServer = new SigningAndValidationWS(host, port, servlet, useHTTPS,
                username, password);
        this.workerName = workerName;
    }

    protected void doValidate(final byte[] data, final String encoding,
            final OutputStream out) throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException,
                IOException {

        final int requestId = random.nextInt();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending validation request with id " + requestId
                    + " containing data of length " + data.length + " bytes"
                    + " to worker " + workerName);
        }

        // Take start time
        final long startTime = System.nanoTime();

        final ProcessResponse response = signServer.process(workerName,
                new GenericValidationRequest(requestId, data), new RequestContext());

        // Take stop time
        final long estimatedTime = System.nanoTime() - startTime;

        if(response instanceof GenericValidationResponse) {
            final GenericValidationResponse signResponse =
                    (GenericValidationResponse) response;

            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Got validation response with id %d, "
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
