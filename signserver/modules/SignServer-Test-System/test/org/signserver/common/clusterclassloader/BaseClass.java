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
package org.signserver.common.clusterclassloader;

import javax.persistence.EntityManager;

import org.signserver.server.annotations.WorkerEntityManager;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class BaseClass {

    @WorkerEntityManager
    protected EntityManager workerEntityManager = new TEntityManager();

    public void setWorkerEntityManager(EntityManager em) {
        workerEntityManager = em;
    }
}
