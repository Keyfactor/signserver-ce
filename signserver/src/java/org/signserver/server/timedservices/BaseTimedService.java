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

package org.signserver.server.timedservices;

import java.text.ParseException;
import java.util.Date;

import org.apache.log4j.Logger;
import org.quartz.CronExpression;
import org.signserver.common.ServiceConfig;
import org.signserver.common.ServiceStatus;
import org.signserver.common.WorkerStatus;
import org.signserver.server.BaseWorker;


public abstract class BaseTimedService extends BaseWorker implements ITimedService {
	 
	//Private Property constants

	/** Log4j instance for actual implementation class */
    public transient Logger log = Logger.getLogger(this.getClass());
    

    
    protected BaseTimedService(){

    }


    /**
     * @see org.signserver.server.timedservices.ITimedService#getNextInterval()
     */


    public long getNextInterval() {
    	long retval = DONT_EXECUTE;
    	String interval = config.getProperties().getProperty(ServiceConfig.INTERVAL);
    	String cronExpression = config.getProperties().getProperty(ServiceConfig.CRON);

    	if(interval == null && cronExpression == null){
    		log.warn("Warning neither an interval nor CRON expression is defined for service with id: " + workerId);
    	}

    	if(interval != null && cronExpression != null){
    		log.error("Error an interval and a CRON expression cannot both be defined for service with id: " + workerId);
    	}else{
    		if(interval != null){
    			try{
    				retval = Long.parseLong(interval) * 1000;
    			}catch(NumberFormatException e){
    				log.error("Error in Service configuration, Interval must contains numbers only");
    			}
    		}
    		if(cronExpression != null){
    			try{
    				CronExpression ce = new CronExpression(cronExpression);
    				Date nextDate = ce.getNextValidTimeAfter(new Date());						
    				retval = (long) (nextDate.getTime() - System.currentTimeMillis());
    			}catch(ParseException e){
    				log.error("Error in Service configuration, illegal CRON expression : " + cronExpression + " defined for service with id " + workerId);
    			}
    		}
    	}

    	return retval;
    }


    /**
     * @see org.signserver.server.timedservices.ITimedService#isActive()
     */
	public boolean isActive() {
		if(config.getProperties().getProperty(ServiceConfig.ACTIVE) == null){
           return false;			
		}
		
		String active = config.getProperties().getProperty(ServiceConfig.ACTIVE);
		
		return active.trim().equalsIgnoreCase("TRUE");
	}


	/**
	 * @see org.signserver.server.timedservices.ITimedService#isSingleton()
	 */
	public boolean isSingleton() {
		if(config.getProperties().getProperty(ServiceConfig.SINGLETON) == null){
			return false;			
		}

		String active = config.getProperties().getProperty(ServiceConfig.SINGLETON);

		return active.trim().equalsIgnoreCase("TRUE");
	}


    public WorkerStatus getStatus() {
		ServiceStatus retval = new ServiceStatus(workerId,  new ServiceConfig( config));
		
		return retval;
	}

	    

	
}
