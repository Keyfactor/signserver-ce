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
package org.signserver.cli.groupkeyservice;

import java.rmi.RemoteException;

import org.signserver.cli.BaseCommand;
import org.signserver.cli.IllegalAdminCommandException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.WorkerStatus;
import org.signserver.groupkeyservice.common.GroupKeyServiceStatus;

/**
 * Command containing common help methods for group key service commands. 
 *
 * @version $Id$
 * @author Philip Vendil
 */
public abstract class BaseGroupKeyServiceCommand extends BaseCommand {

    /**
     * 
     *
     * @param args command line arguments
     */
    public BaseGroupKeyServiceCommand(String[] args) {
        super(args);
    }

    /**
     * Method checking if the given workerId exists and if its a
     * group key service.
     */
    protected void isWorkerGroupKeyService(String hostname, int workerId) throws RemoteException, InvalidWorkerIdException, Exception {
        checkThatWorkerIsProcessable(workerId, hostname);
        WorkerStatus status = getCommonAdminInterface(hostname).getStatus(workerId);
        if (!(status instanceof GroupKeyServiceStatus)) {
            throw new IllegalAdminCommandException("Error: given workerId doesn't seem to point to any existing group key service.");
        }
    }
    // execute
}
