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

import java.util.List;
import jakarta.annotation.PostConstruct;
import jakarta.ejb.ConcurrencyManagement;
import jakarta.ejb.ConcurrencyManagementType;
import jakarta.ejb.Singleton;
import jakarta.persistence.EntityManager;
import org.signserver.ejb.interfaces2.WorkerManagerSingletonLocal;
import org.apache.log4j.Logger;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.server.IWorker;
import org.signserver.server.SignServerContext;
import org.signserver.server.ejb.WorkerWithComponents;
import org.signserver.server.config.entities.FileBasedWorkerConfigDataService;
import org.signserver.server.config.entities.IWorkerConfigDataService;
import org.signserver.server.config.entities.WorkerConfigDataService;
import org.signserver.server.entities.FileBasedKeyUsageCounterDataService;
import org.signserver.server.entities.IKeyUsageCounterDataService;
import org.signserver.server.entities.KeyUsageCounterDataService;
import org.signserver.server.nodb.FileBasedDatabaseManager;

/**
 * Singleton bean managing the worker life-cycle.
 *
 * @see WorkerFactory
 * @author Markus Kilås
 * @version $Id$
 */
@ConcurrencyManagement(ConcurrencyManagementType.BEAN) // Currently the WorkerFactory handles concurrency, we might change this to be handled by the container instead after refactoring
@Singleton
public class WorkerManagerSingletonBean implements WorkerManagerSingletonLocal {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(WorkerManagerSingletonBean.class);
    
    private EntityManager em;
    
    private IWorkerConfigDataService workerConfigService;
    private IKeyUsageCounterDataService keyUsageCounterDataService;
    
    private WorkerFactory workerFactory;
    
    private SignServerContext workerContext;

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
        if (LOG.isTraceEnabled()) {
            LOG.trace("Created WorkerFactory instance: " + workerFactory);
        }
    }

    @Override
    public IWorker getWorker(final WorkerIdentifier wi) throws NoSuchWorkerException {
        return workerFactory.getWorker(wi);
    }

    @Override
    public WorkerWithComponents getWorkerWithComponents(final WorkerIdentifier wi) throws NoSuchWorkerException {
        return workerFactory.getWorkerWithComponents(wi, workerContext);
    }

    @Override
    public void reloadWorker(WorkerIdentifier wi) {
        workerFactory.reloadWorker(wi);
    }

    @Override
    public void flush() {
        workerFactory.flush();
    }

    @Override
    public List<Integer> getAllWorkerIDs() {
        return workerConfigService.findAllIds();
    }

    @Override
    public List<String> getAllWorkerNames() {
        return workerConfigService.findAllNames();
    }

    @Override
    public List<Integer> getAllWorkerIDs(final WorkerType workerType) {
        return workerConfigService.findAllIds(workerType);
    }

    @Override
    public void upgradeWorkerNames() {
        workerConfigService.populateNameColumn();
    }
    
}
