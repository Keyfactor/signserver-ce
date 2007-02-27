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


package org.signserver.rmi;

import java.rmi.Remote;
import java.rmi.RemoteException;

import org.signserver.common.ISignRequest;
import org.signserver.common.ISignResponse;
 

/**
 * Interface to an object that allways should be running on the server.
 * @author Lars Silvén
 *
 * @version $Id: Server.java,v 1.1 2007-02-27 16:18:29 herrvendil Exp $
 *
 */
public interface Server extends Remote {

    /*
     * Starts a session to the object. To be used if not session id is available.
     */
    void wakeUp() throws RemoteException;

    String ping(byte[] sessionID) throws RemoteException;

    ISignResponse signData(int signerID, ISignRequest request,
                           byte[] sessionID) throws RemoteException;
}
