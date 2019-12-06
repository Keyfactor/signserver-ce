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
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.util.LinkedList;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.soap.MTOMFeature;
import org.apache.log4j.Logger;
import org.apache.commons.io.IOUtils;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.bouncycastle.util.encoders.Base64;
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
    private Map<String, String> metadata;

    private final ClientWS signServer;

    private Random random = new Random();

    public ClientWSDocumentSigner(final String host, final int port,
            final String servlet, final String workerName, final boolean useHTTPS, 
            final String username, final String password, final String pdfPassword,
            final SSLSocketFactory socketFactory,
            final Map<String, String> metadata) {
        final String url = (useHTTPS ? "https://" : "http://")
                + host + ":" + port
                + servlet;
        final ClientWSService service;

        // Set the username and password. This is needed here in case the WSDL
        // is password protected
        if (username !=null && password != null) {
            Authenticator.setDefault(new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(username, password.toCharArray());
                }

            });
        }

        final URL resource =
                getClass().getResource("/org/signserver/client/cli/ClientWS.wsdl");

        service = new ClientWSService(resource, new QName("http://clientws.signserver.org/", "ClientWSService"));

        this.signServer = service.getPort(new QName("http://clientws.signserver.org/", "ClientWSPort"), ClientWS.class, new MTOMFeature(true));
        this.workerName = workerName;
        this.pdfPassword = pdfPassword;
        this.metadata = metadata;
        
        final BindingProvider bp = (BindingProvider) signServer;
        final Map<String, Object> requestContext = bp.getRequestContext();
            
        requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, url);
        
        // Authentication
        if (username != null && password != null) { 
            requestContext.put(BindingProvider.USERNAME_PROPERTY, username);
            requestContext.put(BindingProvider.PASSWORD_PROPERTY, password);
        }
        
        if (socketFactory != null) {
            final Client client = ClientProxy.getClient(bp);
            final HTTPConduit http = (HTTPConduit) client.getConduit();
            final TLSClientParameters params = new TLSClientParameters();
            
            params.setSSLSocketFactory(socketFactory);
            http.setTlsClientParameters(params);
        }
    }

    @Override
    protected void doSign(final InputStream data, final long size, final String encoding,
            final OutputStream out, final Map<String, Object> requestContext)
            throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException,
                IOException {
        try {
            final int requestId = random.nextInt();

            if (LOG.isDebugEnabled()) {
                LOG.debug("Sending sign request with ID " + requestId
                        + " containing data of length " + size + " bytes"
                        + " to worker " + workerName);
            }

            // Take start time
            final long startTime = System.nanoTime();

            // Metadata        
            final LinkedList<Metadata> requestMetadata = new LinkedList<>();
            
            if (metadata != null) {
                for (final String key : metadata.keySet()) {
                    final Metadata metadataItem = new Metadata();
                
                    metadataItem.setName(key);
                    metadataItem.setValue(metadata.get(key));
                    requestMetadata.add(metadataItem);
                }
            }

            if (pdfPassword != null) {
                final Metadata pdfPasswordMetadata = new Metadata();
                
                pdfPasswordMetadata.setName(RequestContext.METADATA_PDFPASSWORD);
                pdfPasswordMetadata.setValue(pdfPassword);
                requestMetadata.add(pdfPasswordMetadata);
            }
                
            String fileName = (String) requestContext.get(RequestContext.FILENAME);
            // if a file name was specified, pass it in as meta data
            if (fileName != null) {
                final Metadata fileNameMetadata = new Metadata();
                fileNameMetadata.setName(RequestContext.FILENAME);
                fileNameMetadata.setValue(fileName);
                requestMetadata.add(fileNameMetadata);
            }
            
            final DataResponse response = getWSPort().processData(workerName,
                    requestMetadata, IOUtils.toByteArray(data));

            // Take stop time
            final long estimatedTime = System.nanoTime() - startTime;

            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Got sign response with ID %d, "
                        + "archive ID %s, signed data of length %d bytes "
                        + "signed by signer with certificate:\n%s.",
                        response.getRequestId(),
                        response.getArchiveId(),
                        response.getData().length,
                        response.getSignerCertificate() == null ? "(null)" : Base64.toBase64String(response.getSignerCertificate())));
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
    
    protected ClientWS getWSPort() {
        return signServer;
    }
}
