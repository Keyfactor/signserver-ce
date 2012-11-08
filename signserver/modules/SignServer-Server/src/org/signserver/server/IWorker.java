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
import org.signserver.common.WorkerStatus;

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
     * Initialization method that should be called directly after creation.
     * @param workerId the unique id of the worker
     * @param config the configuration stored in database
     * @param workerContext this should be a SignServerContext for SignServer
     * @param workerEntityManager Worker specific JPA Entity Manager if worker is configured to use it.
     * implementation and MailSignerContext for mail processors.
     */
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEntityManager);
    
    WorkerConfig getConfig();
    
    /**
     * Should return the actual status of the worker, status could be if
     * the signer is activated or not, or equivalent for a service.
     * @param additionalFatalErrors Additional errors discovered for this worker
     * for instance by the WorkerSessionBean and that would not be discovered 
     * by the worker it self. Example are errors in the configuration of an 
     * IAuthorizer.
     * @return a WorkerStatus object.
     */
    public WorkerStatus getStatus(final List<String> additionalFatalErrors);
}
