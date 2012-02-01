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
package org.signserver.admin.cli.defaultimpl.groupkeyservice;

import java.rmi.RemoteException;
import org.signserver.admin.cli.defaultimpl.AbstractAdminCommand;
import org.signserver.admin.cli.defaultimpl.AdminCommandHelper;
import org.signserver.admin.cli.defaultimpl.IllegalAdminCommandException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.WorkerStatus;
import org.signserver.groupkeyservice.common.GroupKeyServiceStatus;

/**
 * Command containing common help methods for group key service commands. 
 *
 * @version $Id$
 * @author Philip Vendil
 */
public abstract class BaseGroupKeyServiceCommand extends AbstractAdminCommand {

    protected AdminCommandHelper helper = new AdminCommandHelper();

    /**
     * Method checking if the given workerId exists and if its a
     * group key service.
     */
    protected void isWorkerGroupKeyService(int workerId) throws RemoteException, InvalidWorkerIdException, Exception {
        helper.checkThatWorkerIsProcessable(workerId);
        WorkerStatus status = helper.getWorkerSession().getStatus(workerId);
        if (!(status instanceof GroupKeyServiceStatus)) {
            throw new IllegalAdminCommandException("Error: given workerId doesn't seem to point to any existing group key service.");
        }
    }
}
