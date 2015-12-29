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
import java.util.Collection;

import org.apache.log4j.Logger;
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.common.AuthorizedClient;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionRemote;
import org.signserver.statusrepo.StatusRepositorySessionRemote;

/**
 * Implements methods useful for Commands.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class AbstractAdminCommand extends AbstractCommand {
    
    /** Log4j instance for actual implementing class. */
    private Logger logger = Logger.getLogger(this.getClass());
    
    private AdminCommandHelper delegate = new AdminCommandHelper();

    /**
     * @see AdminCommandHelper#getProcessSession()
     */
    protected WorkerSessionRemote getWorkerSession() throws RemoteException {
        return delegate.getWorkerSession();
    }
    
    protected ProcessSessionRemote getProcessSession() throws RemoteException {
        return delegate.getProcessSession();
    }

    /**
     * @see AdminCommandHelper#getWorkerId(java.lang.String) 
     */
    protected int getWorkerId(String workerIdOrName) throws RemoteException, IllegalCommandArgumentsException {
        return delegate.getWorkerId(workerIdOrName);
    }

    /**
     * @see AdminCommandHelper#getStatusRepositorySession() 
     */
    protected StatusRepositorySessionRemote getStatusRepositorySession() throws RemoteException {
        return delegate.getStatusRepositorySession();
    }

    /**
     * @see AdminCommandHelper#getGlobalConfigurationSession() 
     */
    protected GlobalConfigurationSessionRemote getGlobalConfigurationSession() throws RemoteException {
        return delegate.getGlobalConfigurationSession();
    }

    /**
     * @see AdminCommandHelper#checkThatWorkerIsProcessable(int) 
     */
    protected void checkThatWorkerIsProcessable(int signerid) throws RemoteException, IllegalCommandArgumentsException {
        delegate.checkThatWorkerIsProcessable(signerid);
    }
    
    /**
     * Prints the list of authorized clients to the output stream.
     * @param authClients Clients to print
     */
    protected void printAuthorizedClients(final Collection<AuthorizedClient> authClients) {
        for (final AuthorizedClient client : authClients) {
            this.getOutputStream().println("  " + client.getCertSN() + ", " + client.getIssuerDN() + "\n");
        }
    }

    /**
     * @return The logger for the implementing class
     */
    protected Logger getLogger() {
        return logger;
    }
}
