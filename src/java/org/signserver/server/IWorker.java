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

import javax.persistence.EntityManager;

import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
 
/**
 * IWorker is an interface that all signers and services should implement
 * 
 * There exists a BaseWorker that can be extended covering some of it's functions
 * 
 * 
 * @author Philip Vendil
 * $Id: IWorker.java,v 1.2 2007-11-27 06:05:04 herrvendil Exp $
 */
public interface IWorker {

	/**
	 * Initialization method that should be called directly after creation.
	 * @param workerId the unique id of the worker
	 * @param config the configuration stored in database
	 */
	public void init(int workerId, WorkerConfig config, EntityManager em);
	
	/**
	 * Should return the actual status of the worker, status could be if
	 * the signer is activated or not, or equivalent for a service.
	 * @return a WorkerStatus object.
	 */
	public WorkerStatus getStatus();
	
	
}
