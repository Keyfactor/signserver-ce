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

package org.signserver.mailsigner.core;

import java.util.Enumeration;

import org.signserver.common.WorkerConfig;
import org.signserver.server.IWorkerConfigDataService;
import org.signserver.server.PropertyFileStore;

/**
 * 
 * Mail Signer version of the worker config data service
 * 
 * @author Philip Vendil 3 aug 2008
 *
 * @version $Id$
 */

public class MailSignerWorkerConfigService implements IWorkerConfigDataService {

	private MailSignerWorkerConfigService(){}
	
	private static MailSignerWorkerConfigService instance = new MailSignerWorkerConfigService();
	public static MailSignerWorkerConfigService getInstance(){
		return instance;
	}
	/**
	 * Mail signer version of the getWorkerProperties.
	 * Returns a clone of the data so, active and current configs
	 * can be separated.
	 * 
	 * @see org.signserver.server.IWorkerConfigDataService#getWorkerProperties(int)
	 */
	public WorkerConfig getWorkerProperties(int workerId) {
		
		return cloneWorkerProperties(PropertyFileStore.getInstance().getWorkerProperties(workerId));
	}

	private WorkerConfig cloneWorkerProperties(WorkerConfig workerProperties) {
		WorkerConfig retval = new WorkerConfig();
		
		Enumeration<Object> en = workerProperties.getProperties().keys();
		while(en.hasMoreElements()){
			String key = (String) en.nextElement();
			retval.getProperties().setProperty(key, workerProperties.getProperties().getProperty(key));
		}
		
		return retval;
	}
}
