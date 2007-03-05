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

package org.signserver.server.service;

import org.apache.log4j.Logger;
import org.signserver.common.ServiceConfig;
import org.signserver.common.ServiceStatus;
import org.signserver.common.WorkerStatus;
import org.signserver.server.BaseWorker;


public abstract class BaseService extends BaseWorker implements IService {
	 
	//Private Property constants




	/** Log4j instance for actual implementation class */
    public transient Logger log = Logger.getLogger(this.getClass());
    

    
    protected BaseService(){

    }


    /**
     * @see org.signserver.server.service.IService#getNextInterval()
     */
	public long getNextInterval() {
		long retval = DONT_EXECUTE;
		String interval = config.getProperties().getProperty(ServiceConfig.INTERVAL);
		try{
			retval = Long.parseLong(interval);
		}catch(NumberFormatException e){
			log.error("Error in Service configuration, Interval must contains numbers only");
		}
		return retval;
	}


    /**
     * @see org.signserver.server.service.IService#isActive()
     */
	public boolean isActive() {
		if(config.getProperties().getProperty(ServiceConfig.ACTIVE) == null){
           return false;			
		}
		
		String active = config.getProperties().getProperty(ServiceConfig.ACTIVE);
		
		return active.trim().equalsIgnoreCase("TRUE");
	}


	/**
	 * @see org.signserver.server.service.IService#isSingleton()
	 */
	public boolean isSingleton() {
		if(config.getProperties().getProperty(ServiceConfig.SINGLETON) == null){
			return false;			
		}

		String active = config.getProperties().getProperty(ServiceConfig.SINGLETON);

		return active.trim().equalsIgnoreCase("TRUE");
	}


    public WorkerStatus getStatus() {
		ServiceStatus retval = new ServiceStatus( new ServiceConfig( config));
		
		return retval;
	}

	    

	
}
