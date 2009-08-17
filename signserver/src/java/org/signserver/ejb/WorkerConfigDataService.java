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
 
package org.signserver.ejb;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;

import javax.ejb.EJBException;
import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.Base64PutHashMap;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.WorkerConfig;
import org.signserver.server.IWorkerConfigDataService;

/**
 * Entity Service class that acts as migration layer for
 * the old Home Interface for the Worker Config Entity Bean
 * 
 * Contains about the same methods as the EJB 2 entity beans home interface.
 *
 */


public class WorkerConfigDataService implements IWorkerConfigDataService {
 
	public transient Logger log = Logger.getLogger(this.getClass());
	
	private EntityManager em;
	
	public WorkerConfigDataService(EntityManager em){
		this.em = em;
	}
	
    /**
     * Entity Bean holding info about a workers (service or signer) configuration
     * 
     * @param workerId uniqe Id of the worker 
     *
     */
    public void create(int workerId, String configClassPath){
        
        log.debug("Creating worker config data, id=" + workerId);
        WorkerConfigDataBean wcdb = new WorkerConfigDataBean();
        wcdb.setSignerId(workerId);

        try {
        	setWorkerConfig(workerId, (WorkerConfig) this.getClass().getClassLoader().loadClass(configClassPath).newInstance(), wcdb);
		} catch (Exception e) {
			log.error(e);
		} 

       
    }
	

	
	
    /**
     * Returns the value object containing the information of the entity bean.
     * This is the method that should be used to worker config correctly
     * correctly.
     *
     */
    @SuppressWarnings("unchecked")
	public WorkerConfig getWorkerConfig(int workerId) {
    	WorkerConfig workerConf = null;
    	WorkerConfigDataBean wcdb = em.find(WorkerConfigDataBean.class, workerId);
    	
    	if(wcdb != null){
    		java.beans.XMLDecoder decoder;
    		try {
    			decoder =
    				new java.beans.XMLDecoder(
    						new java.io.ByteArrayInputStream(wcdb.getSignerConfigData().getBytes("UTF8")));
    		} catch (UnsupportedEncodingException e) {
    			throw new EJBException(e);
    		}

    		HashMap h = (HashMap) decoder.readObject();
    		decoder.close();
    		// Handle Base64 encoded string values
    		HashMap data = new Base64GetHashMap(h);

    		if(data.get(WorkerConfig.CLASS) == null){
    			// Special case, need to upgrade from signserver 1.0
    			workerConf = new ProcessableConfig(new WorkerConfig()).getWorkerConfig();        	
    			workerConf.loadData(data);
    			workerConf.upgrade();        	
    		}else{        	
    			try {
    				workerConf = new WorkerConfig();
    				workerConf.loadData(data);
    				workerConf.upgrade();
    			} catch (Exception e) {
    				log.error(e);
    			} 
    		}
    	}    	       
    	
        return workerConf;
    }
    
    /**
     * Method that saves the Worker Config to database.
     */
	public void setWorkerConfig(int workerId, WorkerConfig signconf){
        setWorkerConfig(workerId, signconf, null);
    }
    
    /**
     * Method that removes a worker config
     * 
     * @returns true if the removal was successful
     */
    public boolean removeWorkerConfig(int workerId){
    	boolean retval = false;
    	WorkerConfigDataBean wcdb = em.find(WorkerConfigDataBean.class, workerId);
    	if(wcdb != null){
    	  em.remove(wcdb);
    	  retval = true;
    	}
    	
    	return retval;
    }
    
    
    /**
     * Method that saves the Worker Config to database.
     */
    @SuppressWarnings("unchecked")
	private void setWorkerConfig(int workerId, WorkerConfig signconf, WorkerConfigDataBean wcdb){
        // We must base64 encode string for UTF safety
        HashMap a = new Base64PutHashMap();
        a.putAll((HashMap)signconf.saveData());
    	
    	
    	java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
    	
    	java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
    	encoder.writeObject(a);
    	encoder.close();
    	
    	try {
    		if (log.isDebugEnabled()) {
    			log.debug("WorkerConfig data: \n" + baos.toString("UTF8"));
    		}
    		if(wcdb == null){
    		  wcdb = em.find(WorkerConfigDataBean.class, workerId);
    		}
    		wcdb.setSignerConfigData(baos.toString("UTF8"));
    		em.persist(wcdb);
    	} catch (UnsupportedEncodingException e) {
    		throw new EJBException(e);
    	}	
    }
    
	/* (non-Javadoc)
	 * @see org.signserver.ejb.IWorkerConfigDataService#getWorkerProperties(int)
	 */
	public WorkerConfig getWorkerProperties(int workerId){

		WorkerConfig workerConfig = getWorkerConfig(workerId);
		if(workerConfig == null){			
			create(workerId,  WorkerConfig.class.getName());
			workerConfig = getWorkerConfig(workerId);
		}

		return workerConfig;
	}


}
