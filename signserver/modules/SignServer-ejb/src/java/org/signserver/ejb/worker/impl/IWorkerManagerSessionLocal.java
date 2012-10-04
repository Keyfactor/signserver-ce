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
import javax.ejb.Local;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession.ILocal;
import org.signserver.server.IAccounter;
import org.signserver.server.IAuthorizer;
import org.signserver.server.IWorker;
import org.signserver.server.archive.Archiver;
import org.signserver.server.log.IWorkerLogger;

/**
 * Session bean managing the worker life-cycle.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@Local
public interface IWorkerManagerSessionLocal {

    /**
     * Get a worker instance given the workerId.
     *
     * @param workerId Id of worker to get
     * @param globalSession Global session that will be used for lookup
     * @return The worker instance
     */
    IWorker getWorker(final int workerId, final IGlobalConfigurationSession globalSession);

    /**
     * @param workerName worker name to query the ID for
     * @param globalSession Global session that will be used for lookup
     * @return returning the ID of the named Worker
     */
    int getIdFromName(final String workerName, final IGlobalConfigurationSession globalSession);

    /**
     * Force a reload of the given worker.
     *
     * @param workerId Id of worker to reload
     * @param globalConfigurationSession Global session that will be used for lookup
     */
    void reloadWorker(int workerId, ILocal globalConfigurationSession);

    /**
     * Get the worker's configured worker logger.
     *
     * @param workerId Id of worker
     * @param awc Worker configuration
     * @return An instance of the worker's worker logger
     * @throws IllegalRequestException in case the instance could not be loaded correctly
     */
    IWorkerLogger getWorkerLogger(int workerId, WorkerConfig awc) throws IllegalRequestException;

    /**
     * Get the worker's authorizer.
     *
     * @param workerId Id of worker
     * @param authenticationType The authentication type/implementation class name
     * @param awc Worker configuration
     * @return An instance of the worker's authorizer
     * @throws IllegalRequestException in case the instance could not be loaded correctly
     */
    IAuthorizer getAuthenticator(int workerId, String authenticationType, WorkerConfig awc) throws IllegalRequestException;

    /**
     * Get the worker's configured accounter.
     * 
     * @param workerId Id of worker
     * @param awc Worker configuration
     * @return An instance of the worker's accounter
     * @throws IllegalRequestException in case the instance could not be loaded correctly
     */
    IAccounter getAccounter(int workerId, WorkerConfig awc) throws IllegalRequestException;

    /**
     * Get the worker's archivers.
     *
     * @param workerId Id of worker
     * @param awc Worker configuration
     * @return A list of the worker's archiver instances
     * @throws IllegalRequestException in case the instances could not be loaded correctly
     */
    List<Archiver> getArchivers(int workerId, WorkerConfig awc) throws IllegalRequestException;

    /**
     * Forget all created instances of workers and their resources.
     */
    void flush();

    /**
     * List all available worker IDs of the given type.
     *
     * @param workerType type of worker to list
     * @param globalConfigurationSession
     * @return a list of all available worker IDs of the given type
     * @see GlobalConfiguration#WORKERTYPE_ALL
     * @see GlobalConfiguration#WORKERTYPE_PROCESSABLE
     */
    List<Integer> getWorkers(int workerType, IGlobalConfigurationSession globalConfigurationSession);
    
}
