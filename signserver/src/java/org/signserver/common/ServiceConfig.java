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

import java.util.Date;


/**
 * 
 * Class used to store service specific configuration
 * 
 * @author Philip Vendil 2007 jan 23
 *
 * @version $Id: ServiceConfig.java,v 1.1 2007-02-27 16:18:11 herrvendil Exp $
 */
 
public class ServiceConfig extends WorkerConfig {

	private static final long serialVersionUID = 1L;

	private static final float LATEST_VERSION = 2;
	
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
     * Internal setting determining the  last time the service was runned
     *
     */
    private static final String LASTRUNTIMESTAMP = "LASTRUNTIMESTAMP";
    
	public ServiceConfig(){
		super();
		data.put(CLASS, this.getClass().getName());
	}
	

	public float getLatestVersion() {		
		return LATEST_VERSION;
	}

	public void upgrade() {
		if(data.get(CLASS) == null){
			data.put(CLASS, this.getClass().getName());
		}

		data.put(VERSION, new Float(LATEST_VERSION));
	}


	public Date getLastRunTimestamp() {
		String time = (String) data.get(LASTRUNTIMESTAMP);
		if(time == null){
			return null;
		}
		
		long timeStamp =Long.parseLong(time);
		
		return new Date(timeStamp);
	}


	public void setLastRunTimestamp(Date LastRunDate) {
		long timeStamp = LastRunDate.getTime();
		data.put(LASTRUNTIMESTAMP, "" +timeStamp);
	}



}
