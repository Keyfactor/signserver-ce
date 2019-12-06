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
package org.signserver.ejb.interfaces;

import javax.ejb.Remote;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerIdentifier;

/**
 * Remote interface for the process session to be used from CLI/GUI using
 * the EJB interface.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@Remote
public interface ProcessSessionRemote {

    /**
     * The Worker Beans main method. Takes  requests processes them
     * and returns a response.
     *
     * @param wi ID of worker who should process the request
     * @param request the request
     * @param remoteContext context of the request
     * @return The process response
     * @throws CryptoTokenOfflineException if the signers token isn't activated.
     * @throws IllegalRequestException if illegal request is sent to the method
     * @throws SignServerException if some other error occurred server side
     * during process.
     */
    ProcessResponse process(WorkerIdentifier wi, ProcessRequest request,
            RemoteRequestContext remoteContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException;
}
