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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.LinkedList;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import javax.xml.namespace.QName;
import org.apache.log4j.Logger;
import org.signserver.client.clientws.ClientWS;
import org.signserver.client.clientws.ClientWSService;
import org.signserver.client.clientws.DataResponse;
import org.signserver.client.clientws.InternalServerException_Exception;
import org.signserver.client.clientws.Metadata;
import org.signserver.client.clientws.RequestFailedException_Exception;
import org.signserver.common.*;


/**
 * DocumentSigner using the Web Services interface.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ClientWSDocumentSigner extends AbstractDocumentSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ClientWSDocumentSigner.class);

    private String workerName;
    private String pdfPassword;

    private final ClientWS signServer;

    private Random random = new Random();

    public ClientWSDocumentSigner(final String host, final int port,
            final String servlet, final String workerName, final boolean useHTTPS, 
            final String username, final String password, final String pdfPassword) {
        final String url = (useHTTPS ? "https://" : "http://")
                + host + ":" + port
                + servlet;
        final ClientWSService service;
        
        try {
            service = new ClientWSService(new URL(url), new QName("http://clientws.signserver.org/", "ClientWSService"));
        } catch (MalformedURLException ex) {
            throw new IllegalArgumentException("Malformed URL: "
                    + url, ex);
        }
        
        this.signServer = service.getClientWSPort();
        this.workerName = workerName;
        this.pdfPassword = pdfPassword;
    }

    protected void doSign(final byte[] data, final String encoding,
            final OutputStream out, final Map<String, Object> requestContext)
            throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException,
                IOException {
        try {
            final int requestId = random.nextInt();

            if (LOG.isDebugEnabled()) {
                LOG.debug("Sending sign request with id " + requestId
                        + " containing data of length " + data.length + " bytes"
                        + " to worker " + workerName);
            }

            // Take start time
            final long startTime = System.nanoTime();

            // Metadata        
            final LinkedList<Metadata> metadata = new LinkedList<Metadata>();
            final Metadata pdfPasswordMetadata = new Metadata();
            pdfPasswordMetadata.setName(RequestContext.METADATA_PDFPASSWORD);
            pdfPasswordMetadata.setValue(pdfPassword);
            
            String fileName = (String) requestContext.get(RequestContext.FILENAME);
            // if a file name was specified, pass it in as meta data
            if (fileName != null) {
                final Metadata fileNameMetadata = new Metadata();
                fileNameMetadata.setName(RequestContext.FILENAME);
                fileNameMetadata.setValue(fileName);
                metadata.add(fileNameMetadata);
            }
            
            final DataResponse response = signServer.processData(workerName,
                    metadata, data);

            // Take stop time
            final long estimatedTime = System.nanoTime() - startTime;

            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Got sign response with id %d, "
                        + "archive id %d, signed data of length %d bytes "
                        + "signed by signer with certificate:\n%s.",
                        response.getRequestId(),
                        response.getArchiveId(),
                        response.getData().length,
                        response.getSignerCertificate()));
            }

            // Write the signed data
            out.write(response.getData());

            LOG.info("Processing took "
                    + TimeUnit.NANOSECONDS.toMillis(estimatedTime) + " ms");
        } catch (InternalServerException_Exception ex) {
            throw new SignServerException("Exception at server side: " + ex.getLocalizedMessage(), ex);
        } catch (RequestFailedException_Exception ex) {
            LOG.error("failed: " + ex.getLocalizedMessage());
            throw new IllegalRequestException("Client request failed: " + ex.getLocalizedMessage(), ex);
        }

    }
}
