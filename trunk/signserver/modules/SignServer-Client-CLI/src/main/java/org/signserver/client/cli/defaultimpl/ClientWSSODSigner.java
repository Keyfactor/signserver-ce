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
import java.net.URL;
import java.util.List;
import java.util.LinkedList;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.log4j.Logger;
import org.signserver.client.clientws.ClientWS;
import org.signserver.client.clientws.ClientWSService;
import org.signserver.client.clientws.DataGroup;
import org.signserver.client.clientws.DataResponse;
import org.signserver.client.clientws.InternalServerException_Exception;
import org.signserver.client.clientws.Metadata;
import org.signserver.client.clientws.RequestFailedException_Exception;
import org.signserver.client.clientws.SodRequest;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;


/**
 * Signs data groups using the HTTP(s) interface.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ClientWSSODSigner extends AbstractSODSigner {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ClientWSSODSigner.class);

    private String workerName;
    private Map<String, String> metadata;
    
    private final ClientWS signServer;
    
    public ClientWSSODSigner(final String host, final int port,
            final String servlet, final String workerName, final boolean useHTTPS, 
            final String username, final String password,
            final Map<String, String> metadata, final SSLSocketFactory socketFactory) {
        final String url = (useHTTPS ? "https://" : "http://")
                + host + ":" + port
                + servlet;
        final ClientWSService service;
        
        final URL resource =
                getClass().getResource("/org/signserver/client/cli/ClientWS.wsdl");

        service = new ClientWSService(resource, new QName("http://clientws.signserver.org/", "ClientWSService"));
        
        this.signServer = service.getClientWSPort();
        this.workerName = workerName;
        
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
        
        this.metadata = metadata;
    }

    @Override
    protected void doSign(final Map<Integer,byte[]> dataGroups, final String encoding,
            final OutputStream out) throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException,
                IOException {
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Sending sign request "
                        + " containing " + dataGroups.size() + " datagroups"
                        + " to worker " + workerName);
            }

            // Take start time
            final long startTime = System.nanoTime();
            
            final SodRequest sodRequest = new SodRequest();
            for (Map.Entry<Integer, byte[]> entry : dataGroups.entrySet()) {
                DataGroup dg = new DataGroup();
                dg.setId(entry.getKey());
                dg.setValue(entry.getValue());
                sodRequest.getDataGroup().add(dg);
            }
            
            List<Metadata> requestMetadata = new LinkedList<>();
            
            if (metadata != null) {
                for (final String key : metadata.keySet()) {
                    final Metadata md = new Metadata();
                    
                    md.setName(key);
                    md.setValue(metadata.get(key));
                    requestMetadata.add(md);
                }
            }

            final DataResponse response = signServer.processSOD(workerName,
                        requestMetadata, sodRequest);

            // Take stop time
            final long estimatedTime = System.nanoTime() - startTime;

            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Got sign response "
                        + "with signed data of length %d bytes.",
                        response.getData().length));
            }

            // Write the signed data
            out.write(response.getData());

            if (LOG.isInfoEnabled()) {
                LOG.info("Processing took "
                    + TimeUnit.NANOSECONDS.toMillis(estimatedTime) + " ms");
            }
        } catch (InternalServerException_Exception ex) {
            throw new SignServerException("Exception at server side: " + ex.getLocalizedMessage(), ex);
        } catch (RequestFailedException_Exception ex) {
            throw new IllegalRequestException("Client request failed: " + ex.getLocalizedMessage(), ex);
        }
    }

}
