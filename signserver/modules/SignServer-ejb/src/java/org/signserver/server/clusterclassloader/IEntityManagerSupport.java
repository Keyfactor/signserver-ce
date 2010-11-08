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
package org.signserver.server.clusterclassloader;

import javax.persistence.EntityManager;
import org.signserver.common.WorkerConfig;

/**
 * Interface for ClusterClassLoaders that supports EntityManagers.
 *
 * This interface was created in order to build SignServer both with and
 * without support for ExtendedClusterClassLoader.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface IEntityManagerSupport {

    /**
     * It contains a method getWorkerEntityManager that initializes
     * a worker specific entity manager with all the entity beans
     * in the module.
     * @param workerConfig the current worker configuration
     * @return a worker specific Entity Manager with all the Entity Beans
     * in the module part.
     */
    EntityManager getWorkerEntityManger(WorkerConfig workerConfig);

}
