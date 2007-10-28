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

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.log4j.Logger;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;


public abstract class BaseWorker implements IWorker {
	
	private transient Logger log = Logger.getLogger(this.getClass());
	
	private IGlobalConfigurationSession.ILocal globalConfigurationSession;
	
    protected IGlobalConfigurationSession.ILocal getGlobalConfigurationSession(){
    	if(globalConfigurationSession == null){
    		try{
    		  Context context = new InitialContext();
    		  globalConfigurationSession =  (org.signserver.ejb.interfaces.IGlobalConfigurationSession.ILocal) context.lookup(IGlobalConfigurationSession.ILocal.JNDI_NAME);
    		}catch(NamingException e){
    			log.error(e);
    		}
    	}
    	
    	return globalConfigurationSession;
    }
	//Private Property constants

    protected int workerId =0;
    
    protected WorkerConfig config = null; 
    
    protected BaseWorker(){

    }
    
    /**
     * Initialization method that should be called directly after creation
     */
    public void init(int workerId, WorkerConfig config){
      this.workerId = workerId;
      this.config = config;
    }
	
}
