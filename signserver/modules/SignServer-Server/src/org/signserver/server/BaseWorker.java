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
package org.signserver.server;

import java.util.Collections;
import java.util.List;
import javax.naming.NamingException;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.ServiceLocator;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;

/**
 * Base class with common methods for workers.
 *
 * @version $Id$
 */
public abstract class BaseWorker implements IWorker {

    /** Logger. */
    private static final Logger LOG = Logger.getLogger(BaseWorker.class);
    
    /** The global configuration session. */
    private transient IGlobalConfigurationSession globalConfig;

    /**
     * @return The global configuration session.
     */
    protected IGlobalConfigurationSession
            getGlobalConfigurationSession() { // FIXME: Better to somehow inject this
        if (globalConfig == null) {
            try {
                globalConfig = ServiceLocator.getInstance().lookupLocal(
                        IGlobalConfigurationSession.class);
            } catch (NamingException e) {
                LOG.error(e);
            }
        }
        return globalConfig;
    }

    //Private Property constants
    protected int workerId = 0;
    protected WorkerConfig config = null;
    protected WorkerContext workerContext;
    protected EntityManager em;
    protected EntityManager workerEM;

    protected BaseWorker() {
    }

    /**
     * Initialization method that should be called directly after creation
     */
    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        this.workerId = workerId;
        this.config = config;
        this.workerContext = workerContext;
        if (workerContext != null && workerContext instanceof SignServerContext) {
            this.em = ((SignServerContext) workerContext).getEntityManager();
        }

        this.workerEM = workerEM;
    }

    protected SignServerContext getSignServerContext() {
        if (workerContext != null && workerContext instanceof SignServerContext) {
            return (SignServerContext) workerContext;
        }
        return null;
    }

    public void destroy() {
        LOG.debug("Destroy called");
    }
    
    @Override
    public WorkerConfig getConfig() {
        return config;
    }
    
    /**
     * Method that can be overridden by IWorker implementations to give an 
     * up to date list of errors that would prevent a call to the process 
     * method to succeed.
     * If the returned list is non empty the worker will be reported as offline 
     * in status listings and by the health check (unless the worker is disabled).
     * @return A list of (short) messages describing each error or an empty list
     * in case there are no errors
     * @since SignServer 3.2.3
     */
    protected List<String> getFatalErrors() {
        return Collections.emptyList();
    }
    
}
