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
package org.signserver.testutils;

import java.rmi.RemoteException;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import org.apache.log4j.Logger;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;

/**
 *
 * @author markus
 * @version $Id$
 */
public final class ServiceLocator {

    /** Log4j instance. */
    private static final Logger LOG = Logger.getLogger(ServiceLocator.class);
    
    private InitialContext initialContext;
    private static ServiceLocator me;
    private IWorkerSession.IRemote workerSession;
    private IGlobalConfigurationSession.IRemote globalConfigurationSession;

    static {
        try {
            me = new ServiceLocator();
        } catch (NamingException se) {
            throw new RuntimeException(se);
        }
    }

    private ServiceLocator() throws NamingException {
        initialContext = new InitialContext();
    }

    public static ServiceLocator getInstance() {
        return me;
    }

    public IWorkerSession.IRemote getWorkerSession() throws RemoteException {

        if (workerSession == null) {
            try {
                workerSession = (IWorkerSession.IRemote)
                        initialContext.lookup(IWorkerSession.IRemote.JNDI_NAME);
            } catch (NamingException e) {
                try {
                    workerSession = (IWorkerSession.IRemote)
                        initialContext.lookup(
                            "org.signserver.ejb.interfaces.IWorkerSession$IRemote"
                        );
                } catch (NamingException ex) {
                    LOG.error("Error looking up signserver interface");
                    throw new RemoteException(ex.getMessage(), ex);
                }
            }
        }
        return workerSession;
    }

    public IGlobalConfigurationSession.IRemote getGlobalConfigurationSession()
            throws RemoteException {

        if (globalConfigurationSession == null) {
            try {
                globalConfigurationSession =
                    (IGlobalConfigurationSession.IRemote)
                        initialContext.lookup(
                            IGlobalConfigurationSession.IRemote.JNDI_NAME
                        );
            } catch (NamingException e) {
                try {
                    globalConfigurationSession = (IGlobalConfigurationSession.IRemote)
                        initialContext.lookup(
                            "org.signserver.ejb.interfaces.IGlobalConfigurationSession$IRemote"
                        );
                } catch (NamingException ex) {
                    LOG.error("Error looking up signserver interface");
                    throw new RemoteException(ex.getMessage(), ex);
                }
            }
        }
        return globalConfigurationSession;
    }
}
