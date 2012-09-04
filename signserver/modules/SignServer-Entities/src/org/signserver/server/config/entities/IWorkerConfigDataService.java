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

import org.signserver.common.WorkerConfig;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public interface IWorkerConfigDataService {

    String LOG_OPERATION = "WORKERCONF_OPERATION";

    WorkerConfig getWorkerProperties(int workerId);
    
    boolean removeWorkerConfig(int workerId);

    void setWorkerConfig(int workerId, WorkerConfig config);

    WorkerConfig getWorkerConfig(int workerId);

    void create(int workerId, String name);
}
