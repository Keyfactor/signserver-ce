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
package org.signserver.admin.cli.defaultimpl;

import java.rmi.RemoteException;
import java.util.Iterator;
import org.apache.log4j.Logger;
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IStatusRepositorySession;
import org.signserver.ejb.interfaces.IWorkerSession.IRemote;

/**
 *
 * @author Markus Kilås
 */
public abstract class AbstractAdminCommand extends AbstractCommand {
    
    /** Log4j instance for actual implementing class. */
    private Logger logger = Logger.getLogger(this.getClass());
    
    private AdminCommandHelper delegate = new AdminCommandHelper();

    protected IRemote getWorkerSession() throws RemoteException {
        return delegate.getWorkerSession();
    }

    protected int getWorkerId(String workerIdOrName) throws RemoteException, IllegalCommandArgumentsException {
        return delegate.getWorkerId(workerIdOrName);
    }

    protected IStatusRepositorySession.IRemote getStatusRepositorySession() throws RemoteException {
        return delegate.getStatusRepositorySession();
    }

    protected IGlobalConfigurationSession.IRemote getGlobalConfigurationSession() throws RemoteException {
        return delegate.getGlobalConfigurationSession();
    }

    protected void checkThatWorkerIsProcessable(int signerid) throws RemoteException, IllegalCommandArgumentsException {
        delegate.checkThatWorkerIsProcessable(signerid);
    }
    
    protected void printAuthorizedClients(WorkerConfig config) {
        Iterator<AuthorizedClient> iter = new ProcessableConfig(config).getAuthorizedClients().iterator();
        while (iter.hasNext()) {
            AuthorizedClient client = (AuthorizedClient) iter.next();
            this.getOutputStream().println("  " + client.getCertSN() + ", " + client.getIssuerDN() + "\n");
        }
    }

    protected Logger getLogger() {
        return logger;
    }

}
