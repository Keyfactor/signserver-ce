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

import java.io.FileInputStream;
import java.io.IOException;
import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import java.security.cert.CertificateException;

import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession.IRemote;
import org.signserver.statusrepo.IStatusRepositorySession;

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
     * @see AdminCommandHelper#getWorkerSession()
     */
    protected IRemote getWorkerSession() throws RemoteException {
        return delegate.getWorkerSession();
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
    protected IStatusRepositorySession.IRemote getStatusRepositorySession() throws RemoteException {
        return delegate.getStatusRepositorySession();
    }

    /**
     * @see AdminCommandHelper#getGlobalConfigurationSession() 
     */
    protected IGlobalConfigurationSession.IRemote getGlobalConfigurationSession() throws RemoteException {
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
     * @param config to read the authorization list from
     */
    protected void printAuthorizedClients(WorkerConfig config) {
        Iterator<AuthorizedClient> iter = new ProcessableConfig(config).getAuthorizedClients().iterator();
        while (iter.hasNext()) {
            AuthorizedClient client = (AuthorizedClient) iter.next();
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
