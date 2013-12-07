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
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
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
    
    private final ClientWS signServer;

    public ClientWSSODSigner(final String host, final int port,
            final String servlet, final String workerName, final boolean useHTTPS, 
            final String username, final String password) {
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
        
        // Authentication
        if (username != null && password != null) {
            ((BindingProvider) signServer).getRequestContext().put(BindingProvider.USERNAME_PROPERTY, username);
            ((BindingProvider) signServer).getRequestContext().put(BindingProvider.PASSWORD_PROPERTY, password);
        }
    }

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
            
            List<Metadata> metadata = Collections.emptyList();
            
            final DataResponse response = signServer.processSOD(workerName,
                        metadata, sodRequest);

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
