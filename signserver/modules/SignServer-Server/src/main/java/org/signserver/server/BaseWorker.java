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

import java.util.EnumSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.SignServerConstants;
import org.signserver.common.StaticWorkerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.common.WorkerType;
import org.signserver.server.signers.CryptoWorker;
import org.signserver.server.timedservices.ITimedService;

/**
 * Base class with common methods for workers.
 *
 * @version $Id$
 */
public abstract class BaseWorker implements IWorker {

    /** Logger. */
    private static final Logger LOG = Logger.getLogger(BaseWorker.class);

            
    //Private Property constants
    protected int workerId = 0;
    protected WorkerConfig config = null;
    protected WorkerContext workerContext;
    private List<String> fatalErrors;
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
        this.fatalErrors = new LinkedList<>();
        try {
            final WorkerType wt = WorkerType.valueOf(config.getProperty(WorkerConfig.TYPE, WorkerType.UNKNOWN.name()));
            if (wt == WorkerType.UNKNOWN) {
                final EnumSet<WorkerType> values = EnumSet.allOf(WorkerType.class);
                values.remove(WorkerType.UNKNOWN);
                fatalErrors.add("Worker TYPE is unknown. Specify one of " + values.toString());
            }
        } catch (IllegalArgumentException ex) {
            final EnumSet<WorkerType> values = EnumSet.allOf(WorkerType.class);
            values.remove(WorkerType.UNKNOWN);
            fatalErrors.add("Incorrect Worker TYPE: " + ex.getMessage() + ". Specify one of " + values.toString());
        }
        
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
     * 
     * @param services Services for the implementations to use
     * @return A list of (short) messages describing each error or an empty list
     * in case there are no errors
     * @since SignServer 3.2.3
     */
    protected List<String> getFatalErrors(IServices services) {
        return fatalErrors;
    }

    /**
     * Default status information implementation for Workers.
     * This method can be overridden to provide a more customized status page.
     * @param additionalFatalErrors discovered at a different level
     * @param services available to query status
     * @return the status information
     */
    @Override
    public WorkerStatusInfo getStatus(List<String> additionalFatalErrors, final IServices services) {
        final List<String> errors = new LinkedList<>(additionalFatalErrors);
        errors.addAll(getFatalErrors(services));

        final List<WorkerStatusInfo.Entry> briefEntries = new LinkedList<>();
        final List<WorkerStatusInfo.Entry> completeEntries = new LinkedList<>();

        // Worker status
        final boolean active = errors.isEmpty();
        briefEntries.add(new WorkerStatusInfo.Entry("Worker status", active ? "Active" : "Offline"));

        // Disabled or not
        if (Boolean.TRUE.toString().equalsIgnoreCase(config.getProperty(SignServerConstants.DISABLED))) {
            briefEntries.add(new WorkerStatusInfo.Entry("", "Worker is disabled"));
        }

        // Worker Properties
        final StringBuilder configValue = new StringBuilder();
        Properties properties = config.getProperties();
        for (String key : properties.stringPropertyNames()) {
            final String value = config.shouldMaskProperty(key) ?
                                 WorkerConfig.WORKER_PROPERTY_MASK_PLACEHOLDER :
                                 properties.getProperty(key);
            configValue.append(key).append("=").append(value).append("\n\n");
        }
        completeEntries.add(new WorkerStatusInfo.Entry("Worker properties", configValue.toString()));

        // Authorized Clients
        final StringBuilder clientsValue = new StringBuilder();
        for (AuthorizedClient client : config.getAuthorizedClients()) {
            clientsValue.append(client.getCertSN()).append(", ").append(properties.getProperty(client.getIssuerDN())).append("\n");
        }
        completeEntries.add(new WorkerStatusInfo.Entry("Authorized clients (serial number, issuer DN)", clientsValue.toString()));

        // Return everything
        return new WorkerStatusInfo(workerId, 
                config.getProperty("NAME"), 
                "Worker", 
                active ? WorkerStatus.STATUS_ACTIVE : WorkerStatus.STATUS_OFFLINE, 
                briefEntries, 
                errors, 
                completeEntries, 
                config);
    }

    /**
     * Get the worker type for this worker.
     *
     * This is used to set the TYPE property for a worker when the database
     * is upgraded from an old version that did not have this property or when
     * the TYPE property is specified as an empty string to trigger this
     * automatic detection of the type.
     *
     * Implementations could potentially override this method to suggest a
     * different worker type.
     *
     * @return The suggested worker type describing this implementation
     */
    @Override
    public WorkerType getWorkerType() {
        final WorkerType type;
        // Note: The order is important here!
        // Start by checking for the most specific type
        if (this instanceof UnloadableWorker) {
            type = WorkerType.SPECIAL;
        } else if (this instanceof CryptoWorker) {
            type = WorkerType.CRYPTO_WORKER;
        } else if (this instanceof ITimedService) {
            type = WorkerType.TIMED_SERVICE;
        } else if (this instanceof IProcessable) {
            type = WorkerType.PROCESSABLE;
        } else if (this instanceof CryptoWorker) {
            type = WorkerType.CRYPTO_WORKER;
        } else {
            type = WorkerType.SPECIAL;
        }
        return type;
    }
}
