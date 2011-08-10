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
package org.signserver.protocol.ws.client;

import java.util.List;

import javax.net.ssl.SSLSocketFactory;

import org.signserver.protocol.ws.ProcessResponseWS;
import org.signserver.protocol.ws.ProcessRequestWS;

/**
 * Interface that should be implemented by all SignService WebService
 * clients. It contains two main methods, the first one used to process
 * the other one to initialize the client.
 * 
 * It's up to the implementing class to take care of high-availability
 * related functionality according to a policy that should be added to
 * the SignServerWSClientFactory
 *
 * @author Philip Vendil
 * @version $Id$
 */
public interface ISignServerWSClient {

    /**
     * Method used to initialize a SignServer client with a given
     * high availability policy.
     * 
     * @param host to connect to
     * @param port to connect to
     * @param timeOut in milliseconds
     * @param wSDLURI the URL to the WSDL of the service appended to the host and port.
     * @param useHTTPS if HTTPS should be used to connect to the server. 
     * @param faultCallback an interface to which all the problems are reported
     * @param sSLSocketFactory the SSLSocketFactory to use, null means that the Default 
     * SSLSocketFactory will be used if necessary. 
     * this is mainly used to report problems when connecting to nodes. 
     */
    void init(String[] hosts, int port, int timeOut,
            String wSDLURI, boolean useHTTPS, IFaultCallback faultCallback,
            SSLSocketFactory sSLSocketFactory);

    /**
     * The main method used to send process requests to a sign server.
     * 
     * It's up the implementing class to take care of the High-Availability according to
     * the policy.
     * 
     * @param requests a list of requests to process
     * @param workerIdOrName name or id of worker.
     * 
     */
    List<ProcessResponseWS> process(String workerIdOrName, List<ProcessRequestWS> requests);
}