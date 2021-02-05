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
import javax.naming.NamingException;
import org.apache.log4j.Logger;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionRemote;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.common.CESeCoreModules;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.ServiceLocator;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;
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
    private ProcessSessionRemote processSession;
    private WorkerSessionRemote workerSession;
    
    /** The StatusRepositorySession. */
    private StatusRepositorySessionRemote statusRepository;
    
    private SecurityEventsAuditorSessionRemote auditorSession;
    
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
    
    public WorkerSessionRemote getWorkerSession() throws RemoteException {
        if (workerSession == null) {
            try {
                workerSession = ServiceLocator.getInstance().lookupRemote(WorkerSessionRemote.class);
            } catch (NamingException e) {
                LOG.error("Error looking up signserver interface");
                throw new RemoteException("Error looking up signserver interface", e);
            }
        }
        return workerSession;
    }
    
    public SecurityEventsAuditorSessionRemote getAuditorSession() throws RemoteException {
        if (auditorSession == null) {
            try {
                auditorSession = ServiceLocator.getInstance().lookupRemote(
                        SecurityEventsAuditorSessionRemote.class, CESeCoreModules.CORE);
            } catch (NamingException e) {
                LOG.error("Error instantiating the SecurityEventsAuditorSession.", e);
                throw new RemoteException("Error instantiating the SecurityEventsAuditorSession", e);
            }
        }
        return auditorSession;
    }
    
    /**
     * Help Method that retrieves the id of a worker given either
     * it's id in string format or the name of a worker.
     *
     * @param workerIdOrName
     * @return Worker ID
     * @throws RemoteException If failing to lookup remote session
     * @throws org.signserver.cli.spi.IllegalCommandArgumentsException 
     */
    public int getWorkerId(String workerIdOrName) throws RemoteException, IllegalCommandArgumentsException {
        final int retval;

        if (workerIdOrName.substring(0, 1).matches("\\d")) {
            retval = Integer.parseInt(workerIdOrName);
        } else {
            try {
                retval = getWorkerSession().getWorkerId(workerIdOrName);
            } catch (InvalidWorkerIdException ex) {
                throw new IllegalCommandArgumentsException("Error: No worker with the given name could be found");
            }
        }

        return retval;
    }

    /**
     * Help method that checks that the current worker is a signer.
     * @param signerid
     * @throws IllegalCommandArgumentsException 
     * @throws RemoteException 
     */
    public void checkThatWorkerIsProcessable(int signerid) throws RemoteException, IllegalCommandArgumentsException {
        Collection<Integer> signerIds = getWorkerSession().getWorkers(WorkerType.PROCESSABLE);
        if (!signerIds.contains(signerid)) {
            throw new IllegalCommandArgumentsException("Error: given workerId doesn't seem to point to any processable worker in the system.");
        }
    }
}
