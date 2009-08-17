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
 * Interface used to containing one fault of 
 * one of the calls made to a sign server node.
 * 
 * 
 * 
 * @author Philip Vendil 
 *
 * @version $Id$
 */

public interface ICommunicationFault {
    /**
     * @return the error that happened during the communication, can be null
     * if the error didn't come from an exception.
     */
    Throwable getThrowed();
    /**
     * @return a description of what happened
     */
    String getDescription();
    /**
     * @return the host name that the client were trying to connect to.
     */
    String getHostName();
}
