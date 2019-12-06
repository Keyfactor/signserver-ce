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
package org.signserver.server.config.entities;

import java.util.List;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;

/**
 * DataService managing the persistence of the worker configuration data.
 * 
 * @version $Id$
 */
public interface IWorkerConfigDataService {

    String LOG_OPERATION = "WORKERCONF_OPERATION";

    /**
     * Get the worker configuration for the given worker.
     * @param workerId Id of worker
     * @param create If true, create the config
     * @return The worker configuration
     */
    WorkerConfig getWorkerProperties(int workerId, boolean create);
    
    /**
     * Remove the worker's configuration.
     * @param workerId Id of worker
     * @return True if the configuration was removed
     */
    boolean removeWorkerConfig(int workerId);

    /**
     * Sets the worker configuration.
     * @param workerId Id of worker
     * @param config  The configuration to set
     */
    void setWorkerConfig(int workerId, WorkerConfig config);

    /**
     * Create a new empty worker configuration.
     * @param workerId Id of worker
     * @param implClassName The name of the worker
     */
    void create(int workerId, String implClassName);
    
    List<Integer> findAllIds();
    
    public List<String> findAllNames();

    void populateNameColumn();

    public int findId(String workerName) throws NoSuchWorkerException;

    public List<Integer> findAllIds(WorkerType workerType);
}
