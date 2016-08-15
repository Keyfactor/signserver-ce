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

import java.util.List;
import javax.persistence.EntityManager;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.common.WorkerType;

/**
 * IWorker is an interface that all signers and services should implement.
 * 
 * There exists a BaseWorker that can be extended covering some of it's 
 * functions.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public interface IWorker {

    /**
     * Get the worker type for this worker.
     *
     * This is used to set the TYPE property for a worker when the database
     * is upgraded from an old version that did not have this property or when
     * the TYPE property is specified as an empty string to trigger this
     * automatic detection of the type.
     *
     * @return The suggested worker type describing this implementation
     */
    WorkerType getWorkerType();
    
    /**
     * Initialization method that should be called directly after creation.
     * @param workerId the unique id of the worker
     * @param config the configuration stored in database
     * @param workerContext this should be a SignServerContext for SignServer
     * @param workerEntityManager Worker specific JPA Entity Manager if worker is configured to use it.
     * implementation and MailSignerContext for mail processors.
     */
    void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEntityManager);
    
    /**
     * @return The worker configuration
     */
    WorkerConfig getConfig();
    
    /**
     * Should return the actual status of the worker, status could be if
     * the signer is activated or not, or equivalent for a service.
     * @param additionalFatalErrors Additional errors discovered for this worker
     * for instance by the WorkerSessionBean and that would not be discovered 
     * by the worker it self. Example are errors in the configuration of an 
     * IAuthorizer.
     * 
     * @param services services for the implementations to use
     * @return a WorkerStatus object.
     */
    WorkerStatusInfo getStatus(final List<String> additionalFatalErrors, final IServices services);
}
