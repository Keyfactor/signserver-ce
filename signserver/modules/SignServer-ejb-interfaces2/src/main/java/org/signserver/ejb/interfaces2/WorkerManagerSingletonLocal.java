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
package org.signserver.ejb.interfaces2;

import jakarta.ejb.Local;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.server.IWorker;
import org.signserver.server.ejb.WorkerWithComponents;

import java.util.List;

/**
 * Local interface for the worker manager session to be used internally when worker related
 * methods are invoked.
 *
 * @author Christofer Vikström
 * @version $Id$
 */
@Local
public interface WorkerManagerSingletonLocal {

    /**
     * Method for reloading a worker.
     *
     * @param wi
     */
    void reloadWorker(WorkerIdentifier wi);

    /**
     * Method for forgetting all created instances of workers and their resources.
     */
    void flush();

    /**
     * Method for listing all worker IDs in the database.
     *
     * @return a list of all available worker IDs
     */
    List<Integer> getAllWorkerIDs();

    /**
     * Method for listing all worker names in the database.
     *
     * @return a list of all available worker names
     */
    List<String> getAllWorkerNames();

    /**
     * Method for listing all worker IDs available in database of the given type.
     *
     * @param workerType
     * @return a list of all available worker IDs of the given type
     */
    List<Integer> getAllWorkerIDs(WorkerType workerType);

    /**
     * Method for retrieving a worker object and its components
     * given the workerId.
     *
     * @param wi
     * @return a WorkerWithComponents worker object
     * @throws NoSuchWorkerException in case the worker does not exist
     */
    WorkerWithComponents getWorkerWithComponents(WorkerIdentifier wi) throws NoSuchWorkerException;

    /**
     * Method to get a worker instance given the workerId.
     *
     * @param wi Id of worker to get
     * @return The worker instance
     * @throws NoSuchWorkerException in case the worker does not exist
     */
    IWorker getWorker(WorkerIdentifier wi) throws NoSuchWorkerException;

    void upgradeWorkerNames();
}

