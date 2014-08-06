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
import java.util.LinkedList;
import java.util.List;
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

    /**
     * Internal class representing client authentications used for WS adminstration commands.
     */
    protected static class ClientEntry {

        private String certSerialNo;
        private String issuerDN;

        public ClientEntry(String certSerialNo, String issuerDN) {
            this.certSerialNo = certSerialNo;
            this.issuerDN = issuerDN;
        }

        public String getCertSerialNo() {
            return certSerialNo;
        }

        public String getIssuerDN() {
            return issuerDN;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final ClientEntry other = (ClientEntry) obj;
            if ((this.certSerialNo == null) ? (other.certSerialNo != null) : !this.certSerialNo.equals(other.certSerialNo)) {
                return false;
            }
            if ((this.issuerDN == null) ? (other.issuerDN != null) : !this.issuerDN.equals(other.issuerDN)) {
                return false;
            }
            return true;
        }

        @Override
        public int hashCode() {
            int hash = 7;
            hash = 89 * hash + (this.certSerialNo != null ? this.certSerialNo.hashCode() : 0);
            hash = 89 * hash + (this.issuerDN != null ? this.issuerDN.hashCode() : 0);
            return hash;
        }
    }
    
    protected static List<ClientEntry> parseClientEntries(final String clientEntries) {
        final List<ClientEntry> entries = new LinkedList<ClientEntry>();
        if (clientEntries != null && clientEntries.contains(";")) {
            for (String entry : clientEntries.split(";")) {
                final String[] parts = entry.split(",", 2);
                entries.add(new ClientEntry(parts[0], parts[1]));
            }
        }
        return entries;
    }

    protected static String serializeClientEntries(final List<ClientEntry> entries) {
        final StringBuilder buff = new StringBuilder();
        for (final ClientEntry entry : entries) {
            buff.append(entry.getCertSerialNo());
            buff.append(",");
            buff.append(entry.getIssuerDN());
            buff.append(";");
        }
        return buff.toString();
    }
    
}
