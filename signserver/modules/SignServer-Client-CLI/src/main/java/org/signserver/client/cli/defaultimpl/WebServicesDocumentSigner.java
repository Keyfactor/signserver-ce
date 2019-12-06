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
import org.apache.log4j.Logger;
import org.apache.commons.io.IOUtils;
import org.signserver.client.api.ISignServerWorker;
import org.signserver.client.api.SigningAndValidationWS;
import org.signserver.common.*;


/**
 * DocumentSigner using the Web Services interface.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class WebServicesDocumentSigner extends AbstractDocumentSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(WebServicesDocumentSigner.class);

    private String workerName;
    private String pdfPassword;
    private Map<String, String> metadata;

    private ISignServerWorker signServer;

    private Random random = new Random();

    public WebServicesDocumentSigner(final String host, final int port,
            final String servlet, final String workerName, final boolean useHTTPS, 
            final String username, final String password, final String pdfPassword,
            final SSLSocketFactory socketFactory,
            final Map<String, String> metadata) {
        this.signServer = null;
        
        if (servlet != null) {
        	this.signServer =
                        new SigningAndValidationWS(host, port, servlet, useHTTPS, 
                                                   username, password, socketFactory);
        } else {
        	this.signServer =
                        new SigningAndValidationWS(host, port, useHTTPS,
                                                   username, password,
                                                   socketFactory);
        }

        this.workerName = workerName;
        this.pdfPassword = pdfPassword;
        this.metadata = metadata;
    }

    @Override
    protected void doSign(final InputStream data, final long size, final String encoding,
            final OutputStream out, final Map<String, Object> requestContext)
            throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException,
                IOException {

        final int requestId = random.nextInt();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending sign request with ID " + requestId
                    + " containing data of length " + size + " bytes"
                    + " to worker " + workerName);
        }

        // Take start time
        final long startTime = System.nanoTime();

        // RequestContext is used by this API to transfer the metadata
        RemoteRequestContext context = new RemoteRequestContext();
        RequestMetadata requestMetadata = new RequestMetadata();
        context.setMetadata(requestMetadata);
        
        if (metadata != null) {
            requestMetadata.putAll(metadata);
        }
       
        if (pdfPassword != null) {
            requestMetadata.put(RequestContext.METADATA_PDFPASSWORD, pdfPassword);
        }
            
        String fileName = (String) requestContext.get(RequestContext.FILENAME);
        // if a file name was specified, pass it in as meta data
        if (fileName != null) {
            requestMetadata.put(RequestContext.FILENAME, fileName);
        }
        
        final ProcessResponse response = signServer.process(workerName,
                new GenericSignRequest(requestId, IOUtils.toByteArray(data)), context);

        // Take stop time
        final long estimatedTime = System.nanoTime() - startTime;

        if(response instanceof GenericSignResponse) {
            final GenericSignResponse signResponse =
                    (GenericSignResponse) response;

            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Got sign response with ID %d, "
                        + "archive ID %d, signed data of length %d bytes "
                        + "signed by signer with certificate:\n%s.",
                        signResponse.getRequestID(),
                        signResponse.getArchiveId(),
                        signResponse.getProcessedData().length,
                        signResponse.getSignerCertificate()));
            }

            // Write the signed data
            out.write(signResponse.getProcessedData());

            LOG.info("Processing took "
                    + TimeUnit.NANOSECONDS.toMillis(estimatedTime) + " ms");
        } else {
            throw new SignServerException("Unexpected response type: "
                    + response.getClass().getName());
        }
    }
}
