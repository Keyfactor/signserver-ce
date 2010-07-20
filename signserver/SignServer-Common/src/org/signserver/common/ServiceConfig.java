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

package org.signserver.common;

import java.io.Serializable;
import java.util.Date;


/**
 * 
 * Class used to store service specific configuration
 * 
 * @author Philip Vendil 2007 jan 23
 *
 * @version $Id$
 */
 
public class ServiceConfig {

	private static final long serialVersionUID = 1L;

	
	/**
	 * Property if set to the value "TRUE" is runned as active.
	 */
    public static final String ACTIVE = "ACTIVE";
	
	/**
	 * Property if set to the value "TRUE" is runned as a singleton.
	 */
    public static final String SINGLETON = "SINGLETON";
    
	/**
	 * Property that should define the interval i seconds the service should run.
	 */
    public static final String INTERVAL = "INTERVAL";
    
    
	/**
	 * Property that should define a CRON expression of how often the service should run.
	 * It should conform to Unix CRON standard. See developers manual for more details.
	 */
    public static final String CRON = "CRON";
    
    /**
     * Internal setting determining the  last time the service was runned
     *
     */
    private static final String LASTRUNTIMESTAMP = "LASTRUNTIMESTAMP";
    
	private WorkerConfig workerConfig;
	
	public ServiceConfig(WorkerConfig workerConfig){
		super();
		this.workerConfig = workerConfig;
		put(WorkerConfig.CLASS, this.getClass().getName());
	}
	
	private void put(String key,Serializable value){
		workerConfig.getData().put(key, value);
	}
	
	private Serializable get(String key){
		return workerConfig.getData().get(key);
	}
	
	public Date getLastRunTimestamp() {
		String time = (String) get(LASTRUNTIMESTAMP);
		if(time == null){
			return null;
		}
		
		long timeStamp =Long.parseLong(time);
		
		return new Date(timeStamp);
	}


	public void setLastRunTimestamp(Date LastRunDate) {
		long timeStamp = LastRunDate.getTime();
		put(LASTRUNTIMESTAMP, "" +timeStamp);
	}

	public WorkerConfig getWorkerConfig() {
		return workerConfig;
	}

}
