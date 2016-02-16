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
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import javax.naming.NamingException;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerConstants;
import org.signserver.common.StaticWorkerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;

/**
 * Base class with common methods for workers.
 *
 * @version $Id$
 */
public abstract class BaseWorker implements IWorker {

    /** Logger. */
    private static final Logger LOG = Logger.getLogger(BaseWorker.class);
    
    /** The global configuration session. */
    private transient GlobalConfigurationSessionLocal globalConfig;
    
    /**
     * @return The global configuration session.
     */
    protected GlobalConfigurationSessionLocal
            getGlobalConfigurationSession() { // FIXME: Better to somehow inject this
        if (globalConfig == null) {
            try {
                globalConfig = ServiceLocator.getInstance().lookupLocal(GlobalConfigurationSessionLocal.class);
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
    /** 
     * @deprecated This EntityManager was created when the worker was 
     * initialized and is not safe to use from an other transaction. Instead 
     * use the entity manager available in the RequestContext.
     */
    @Deprecated
    protected EntityManager em;
    /** 
     * @deprecated This EntityManager was created when the worker was 
     * initialized and is not safe to use from an other transaction. Instead 
     * use the entity manager available in the RequestContext.
     */
    @Deprecated
    protected EntityManager workerEM;

    protected BaseWorker() {
    }

    /**
     * Initialization method that should be called directly after creation
     * @param workerEM
     */
    @Override
    @SuppressWarnings("deprecation") // Need to still use it for backwards compatibility
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
        final SignServerContext result;
        if (workerContext != null && workerContext instanceof SignServerContext) {
            result = (SignServerContext) workerContext;
        } else {
            result = null;
        }
        return result;
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
    protected List<String> getFatalErrors(IServices services) {
        return Collections.emptyList();
    }

    /**
     * Default status information implementation for Workers.
     * This method can be overridden to provide a more customized status page.
     * @param additionalFatalErrors discovered at a different level
     * @param services available to query status
     * @return the status information
     */
    @Override
    public WorkerStatus getStatus(List<String> additionalFatalErrors, final IServices services) {
        final List<String> fatalErrors = new LinkedList<String>(additionalFatalErrors);
        fatalErrors.addAll(getFatalErrors(services));

        final List<WorkerStatusInfo.Entry> briefEntries = new LinkedList<WorkerStatusInfo.Entry>();
        final List<WorkerStatusInfo.Entry> completeEntries = new LinkedList<WorkerStatusInfo.Entry>();

        // Worker status
        final boolean active = fatalErrors.isEmpty();
        briefEntries.add(new WorkerStatusInfo.Entry("Worker status", active ? "Active" : "Offline"));

        // Disabled or not
        if (Boolean.TRUE.toString().equalsIgnoreCase(config.getProperty(SignServerConstants.DISABLED))) {
            briefEntries.add(new WorkerStatusInfo.Entry("", "Worker is disabled"));
        }

        // Worker Properties
        final StringBuilder configValue = new StringBuilder();
        Properties properties = config.getProperties();
        for (String key : properties.stringPropertyNames()) {
            configValue.append(key).append("=").append(properties.getProperty(key)).append("\n\n");
        }
        completeEntries.add(new WorkerStatusInfo.Entry("Worker properties", configValue.toString()));

        // Authorized Clients
        final StringBuilder clientsValue = new StringBuilder();
        for (AuthorizedClient client : new ProcessableConfig(config).getAuthorizedClients()) {
            clientsValue.append(client.getCertSN()).append(", ").append(properties.getProperty(client.getIssuerDN())).append("\n");
        }
        completeEntries.add(new WorkerStatusInfo.Entry("Authorized clients (serial number, issuer DN)", clientsValue.toString()));

        // Return everything
        return new StaticWorkerStatus(new WorkerStatusInfo(
                workerId, 
                config.getProperty("NAME"), 
                "Worker", 
                active ? WorkerStatus.STATUS_ACTIVE : WorkerStatus.STATUS_OFFLINE, 
                briefEntries, 
                fatalErrors, 
                completeEntries, 
                config));
    }

}
