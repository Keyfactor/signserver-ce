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
    private final Logger logger = Logger.getLogger(this.getClass());
    
    private final AdminCommandHelper delegate = new AdminCommandHelper();

    /**
     * Gets worker session.
     * 
     * @return Worker session
     * @throws java.rmi.RemoteException If failing to lookup remote session
     * @see AdminCommandHelper#getProcessSession()
     */
    protected WorkerSessionRemote getWorkerSession() throws RemoteException {
        return delegate.getWorkerSession();
    }
    
    protected ProcessSessionRemote getProcessSession() throws RemoteException {
        return delegate.getProcessSession();
    }

    /**
     * Gets worker ID
     * 
     * @param workerIdOrName
     * @return Worker ID given a worker name, or a worker ID
     * @throws java.rmi.RemoteException If failing to lookup remote session
     * @throws org.signserver.cli.spi.IllegalCommandArgumentsException
     * @see AdminCommandHelper#getWorkerId(java.lang.String) 
     */
    protected int getWorkerId(String workerIdOrName) throws RemoteException, IllegalCommandArgumentsException {
        return delegate.getWorkerId(workerIdOrName);
    }

    /**
     * Gets the StatusRepositorySession instance.
     * 
     * @return Status repository session
     * @throws java.rmi.RemoteException If failing to lookup remote session
     * @see AdminCommandHelper#getStatusRepositorySession() 
     */
    protected StatusRepositorySessionRemote getStatusRepositorySession() throws RemoteException {
        return delegate.getStatusRepositorySession();
    }

    /**
     * Returns the GlobalConfigurationSession instance.
     * 
     * @return Global configuration session
     * @throws java.rmi.RemoteException If failing to lookup remote session
     * @see AdminCommandHelper#getGlobalConfigurationSession() 
     */
    protected GlobalConfigurationSessionRemote getGlobalConfigurationSession() throws RemoteException {
        return delegate.getGlobalConfigurationSession();
    }

    /**
     * Checks if a worker is processable
     * 
     * @param signerid Worker ID to check
     * @throws java.rmi.RemoteException If failing to lookup remote session
     * @throws org.signserver.cli.spi.IllegalCommandArgumentsException
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
