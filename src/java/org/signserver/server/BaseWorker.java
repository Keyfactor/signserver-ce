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

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.ejbca.core.ejb.ServiceLocator;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.IGlobalConfigurationSessionLocal;
import org.signserver.ejb.IGlobalConfigurationSessionLocalHome;


public abstract class BaseWorker implements IWorker {
	
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
	     
    /**
     * Gets connection to global configuration session bean
     *
     * @return Connection
     */
    protected IGlobalConfigurationSessionLocal getGlobalConfigurationSession() {
        if (globalConfigurationSession == null) {
            try {
            	ServiceLocator locator = ServiceLocator.getInstance();
                IGlobalConfigurationSessionLocalHome globalconfigurationsessionhome = (IGlobalConfigurationSessionLocalHome) locator.getLocalHome(IGlobalConfigurationSessionLocalHome.COMP_NAME);
                globalConfigurationSession = globalconfigurationsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return globalConfigurationSession;
    } //getGlobalConfigurationSession
    
    private IGlobalConfigurationSessionLocal globalConfigurationSession = null;
	

	
	
}
