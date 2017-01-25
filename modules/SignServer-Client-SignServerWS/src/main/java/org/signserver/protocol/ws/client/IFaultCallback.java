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

/**
 * Interface that should be implemented by all users
 * using the message client. The main method addCommunicationError is
 * called by the message client when error or timeout occurred
 * with some or all the servers in the cluster.
 * 
 * 
 * @author Philip Vendil 
 *
 * @version $Id$
 */
public interface IFaultCallback {

    /**
     * Method called by the message client error occurred to some of the nodes in the cluster
     * 
     * @param fault the error
     */
    void addCommunicationError(ICommunicationFault fault);
}
