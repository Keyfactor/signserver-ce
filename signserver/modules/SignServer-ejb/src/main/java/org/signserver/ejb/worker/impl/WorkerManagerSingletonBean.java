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
package org.signserver.ejb.worker.impl;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.ejb.ConcurrencyManagement;
import javax.ejb.ConcurrencyManagementType;
import javax.ejb.EJB;
import javax.ejb.Singleton;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;

import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.*;
import org.signserver.server.IAuthorizer;
import org.signserver.server.IAccounter;
import org.signserver.server.archive.Archiver;
import org.signserver.server.config.entities.FileBasedWorkerConfigDataService;
import org.signserver.server.config.entities.IWorkerConfigDataService;
import org.signserver.server.config.entities.WorkerConfigDataService;
import org.signserver.server.entities.FileBasedKeyUsageCounterDataService;
import org.signserver.server.entities.IKeyUsageCounterDataService;
import org.signserver.server.entities.KeyUsageCounterDataService;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.nodb.FileBasedDatabaseManager;
import org.signserver.server.timedservices.ITimedService;

/**
 * Singleton bean managing the worker life-cycle.
 *
 * @see WorkerFactory
 * @author Markus Kilås
 * @version $Id$
 */
@ConcurrencyManagement(ConcurrencyManagementType.BEAN) // Currently the WorkerFactory handles concurrency, we might change this to be handled by the container instead after refactoring
@Singleton
public class WorkerManagerSingletonBean {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(WorkerManagerSingletonBean.class);
    
    private EntityManager em;
    
    private IWorkerConfigDataService workerConfigService;
    private IKeyUsageCounterDataService keyUsageCounterDataService;
    
    private WorkerFactory workerFactory;
    
    private SignServerContext workerContext;
    
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;
    
    @PostConstruct
    public void create() {
        if (em == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No EntityManager injected. Running without database.");
            }
            workerConfigService = new FileBasedWorkerConfigDataService(FileBasedDatabaseManager.getInstance());
            keyUsageCounterDataService = new FileBasedKeyUsageCounterDataService(FileBasedDatabaseManager.getInstance());
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("EntityManager injected. Running with database.");
            }
            workerConfigService = new WorkerConfigDataService(em);
            keyUsageCounterDataService = new KeyUsageCounterDataService(em);
        }
        workerContext = new SignServerContext(em, keyUsageCounterDataService);
        workerFactory = new WorkerFactory(workerConfigService, workerContext);
    }

    /**
     * Get a worker instance given the workerId.
     *
     * @param workerId Id of worker to get
     * @return The worker instance
     * @throws NoSuchWorkerException in case the worker does not exist
     */
    public IWorker getWorker(final int workerId) throws NoSuchWorkerException {
        return workerFactory.getWorker(workerId);
    }
    
    /**
     * @param workerName worker name to query the ID for
     * @return returning the ID of the named Worker
     * @throws NoSuchWorkerException in case no worker with that name exists
     */
    public int getIdFromName(final String workerName) throws NoSuchWorkerException {
        return workerFactory.getWorkerIdFromName(workerName.toUpperCase());
    }

    /**
     * Force a reload of the given worker.
     *
     * @param workerId Id of worker to reload
     */
    public void reloadWorker(int workerId) {
        workerFactory.reloadWorker(workerId);
    }

    /**
     * Get the worker's configured worker logger.
     *
     * @param workerId Id of worker
     * @param awc Worker configuration
     * @return An instance of the worker's worker logger
     * @throws IllegalRequestException in case the instance could not be loaded correctly
     */
    public IWorkerLogger getWorkerLogger(int workerId, WorkerConfig awc) throws IllegalRequestException {
        final IWorkerLogger logger = workerFactory.getWorkerLogger(workerId, awc, em);
        logger.setEjbs(getEjbs());
        
        return logger;
    }

    /**
     * Get the worker's authorizer.
     *
     * @param workerId Id of worker
     * @param authenticationType The authentication type/implementation class name
     * @param awc Worker configuration
     * @return An instance of the worker's authorizer
     * @throws IllegalRequestException in case the instance could not be loaded correctly
     */
    public IAuthorizer getAuthenticator(int workerId, String authenticationType, WorkerConfig awc) throws IllegalRequestException {
        return workerFactory.getAuthenticator(workerId,
                            authenticationType,
                            awc,
                            em);
    }

    /**
     * Get the worker's configured accounter.
     * 
     * @param workerId Id of worker
     * @param awc Worker configuration
     * @return An instance of the worker's accounter
     * @throws IllegalRequestException in case the instance could not be loaded correctly
     */
    public IAccounter getAccounter(int workerId, WorkerConfig awc) throws IllegalRequestException {
        final IAccounter result = workerFactory.getAccounter(workerId,
                                    awc,
                                    em);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Returning Accounter: " + result);
        }
        return result;
    }

    /**
     * Get the worker's archivers.
     *
     * @param workerId Id of worker
     * @param awc Worker configuration
     * @return A list of the worker's archiver instances
     * @throws IllegalRequestException in case the instances could not be loaded correctly
     */
    public List<Archiver> getArchivers(int workerId, WorkerConfig awc) throws IllegalRequestException {
        return workerFactory.getArchivers(workerId, awc, workerContext);
    }

    /**
     * Forget all created instances of workers and their resources.
     */
    public void flush() {
        workerFactory.flush();
    }
    
    /**
     * List all available worker IDs of the given type.
     *
     * @param workerType type of worker to list
     * @return a list of all available worker IDs of the given type
     * @see GlobalConfiguration#WORKERTYPE_ALL
     * @see GlobalConfiguration#WORKERTYPE_PROCESSABLE
     */
    public List<Integer> getWorkers(int workerType) {
        final List<Integer> retval;
        
        List<Integer> allIds = workerConfigService.findAllIds();
        if (workerType == WorkerConfig.WORKERTYPE_ALL) {
            retval = allIds;
        } else {
            retval = new LinkedList<>();
            for (Integer id : allIds) {
                try {
                    IWorker obj = getWorker(id);
                    if ((workerType == WorkerConfig.WORKERTYPE_PROCESSABLE && obj instanceof IProcessable)
                            || (workerType == WorkerConfig.WORKERTYPE_SERVICES && obj instanceof ITimedService)) {
                        retval.add(id);
                    }
                } catch (NoSuchWorkerException ex) {
                    LOG.error("Worker no longer exists: " + ex.getMessage());
                }
            }
        }

        return retval;
    }
    
    private Map<Class<?>, Object> getEjbs() {
        final Map<Class<?>, Object> ejbs = new HashMap<>();
        ejbs.put(SecurityEventsLoggerSessionLocal.class, logSession);
        
        return ejbs;
    }

    public void upgradeWorkerNames() {
        workerConfigService.populateNameColumn();
    }
    
}
