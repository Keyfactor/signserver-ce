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
package org.signserver.test.random;

import java.rmi.RemoteException;
import javax.naming.NamingException;
import org.apache.log4j.Logger;
import org.signserver.common.ServiceLocator;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionRemote;
import org.signserver.statusrepo.StatusRepositorySessionRemote;

/**
 * Helper class with methods useful for many Command implementations.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AdminCommandHelper {
    
    /** Logger for this class. */
    private static Logger LOG = Logger.getLogger(AdminCommandHelper.class);
    
    /** The global configuration session. */
    private GlobalConfigurationSessionRemote globalConfig;

    /** The SignSession. */
    private WorkerSessionRemote signsession;
    private ProcessSessionRemote processSession;
    
    /** The StatusRepositorySession. */
    private StatusRepositorySessionRemote statusRepository;
    
    /**
     * Gets GlobalConfigurationSession Remote.
     * @return SignServerSession
     * @throws RemoteException in case the lookup failed
     */
    public GlobalConfigurationSessionRemote getGlobalConfigurationSession()
            throws RemoteException {
        if (globalConfig == null) {
            try {
                globalConfig = ServiceLocator.getInstance().lookupRemote(GlobalConfigurationSessionRemote.class);
            } catch (NamingException e) {
                LOG.error("Error instanciating the GlobalConfigurationSession.", e);
                throw new RemoteException("Error instanciating the GlobalConfigurationSession", e);
            }
        }
        return globalConfig;
    }

    /**
     * Gets StatusRepositorySession Remote.
     * @return SignServerSession
     * @throws RemoteException in case the lookup failed
     */
    public StatusRepositorySessionRemote getStatusRepositorySession()
            throws RemoteException {
        if (statusRepository == null) {
            try {
                statusRepository = ServiceLocator.getInstance().lookupRemote(StatusRepositorySessionRemote.class);
            } catch (NamingException e) {
                LOG.error("Error instanciating the StatusRepositorySession.", e);
                throw new RemoteException(
                        "Error instanciating the StatusRepositorySession", e);
            }
        }
        return statusRepository;
    }

    /**
     * Gets SignServerSession Remote.
     * @return SignServerSession
     * @throws RemoteException in case the lookup failed
     */
    public WorkerSessionRemote getWorkerSession() throws RemoteException {
        if (signsession == null) {
            try {
                signsession = ServiceLocator.getInstance().lookupRemote(WorkerSessionRemote.class);
            } catch (NamingException e) {
                LOG.error("Error looking up signserver interface");
                throw new RemoteException("Error looking up signserver interface", e);
            }
        }
        return signsession;
    }
    
    public ProcessSessionRemote getProcessSession() throws RemoteException {
        if (processSession == null) {
            try {
                processSession = ServiceLocator.getInstance().lookupRemote(
                        ProcessSessionRemote.class);
            } catch (NamingException e) {
                LOG.error("Error looking up signserver interface");
                throw new RemoteException("Error looking up signserver interface", e);
            }
        }
        return processSession;
    }
    
}
