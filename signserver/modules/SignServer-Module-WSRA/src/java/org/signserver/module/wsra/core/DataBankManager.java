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
 
package org.signserver.module.wsra.core;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;

import org.apache.log4j.Logger;
import org.signserver.module.wsra.beans.DataBankDataBean;

/**
 * Class in charge of logic concerning fetching and
 * storing data in the data bank.
 * 
 * The data bank is meant to store extra configuration
 * data for the different sub parts of the WSRA that
 * don't need any fast query.
 * 
 * @author Philip Vendil 11 okt 2008
 *
 * @version $Id$
 */

public class DataBankManager {
	
	@SuppressWarnings("unused")
	private Logger log = Logger.getLogger(this.getClass());
	
	private EntityManager workerEntityManager;
	
	public DataBankManager(EntityManager workerEntityManager){
		this.workerEntityManager = workerEntityManager;
	}
	
	/**
	 * 
	 * @return all configured properties in the data bank.
	 */
	@SuppressWarnings("unchecked")
	public List<DataBankDataBean> getAllProperies(){
		List<DataBankDataBean> retval = new ArrayList<DataBankDataBean>();
    	try{
    		retval = workerEntityManager.createNamedQuery("DataBankDataBean.findAll")
    		                                    .getResultList();
    		
    	}catch(NoResultException e){}
    	
    	return retval;
	}
	
	/**
	 * Method to get all properties of one type
	 * @param type can be one of TYPE_ constants.
	 * @return all applicable properties, never null;
	 */
	@SuppressWarnings("unchecked")
	public List<DataBankDataBean> getTypeProperies(int type){
		List<DataBankDataBean> retval = new ArrayList<DataBankDataBean>();
    	try{
    		retval = workerEntityManager.createNamedQuery("DataBankDataBean.findByType")
    		                                    .setParameter(1, type).getResultList();
    		
    	}catch(NoResultException e){}
    	
    	return retval;
	}
	
	/**
	 * Method to get all properties of one type related to one
	 * foreign object.
	 * @param type can be one of TYPE_ constants.
	 * @param relatedId id of foreign object.
	 * @return all applicable properties, never null;
	 */
	@SuppressWarnings("unchecked")
	public List<DataBankDataBean> getRelatedProperies(int type, int relatedId){
		List<DataBankDataBean> retval = new ArrayList<DataBankDataBean>();
    	try{
    		retval = workerEntityManager.createNamedQuery("DataBankDataBean.findByTypeAndRelatedId")
    		                                    .setParameter(1, type)
    		                                    .setParameter(2, relatedId).getResultList();
    		
    	}catch(NoResultException e){}
    	
    	return retval;
	}
	
    /**
     * Method used to get a property from the data bank.
     * 
     * @param type can be one of TYPE_ constants.
     * @param key of property
     */
    public String getProperty(int type, String key){
    	String retval = null;
    	try{
    		DataBankDataBean persistData = (DataBankDataBean) workerEntityManager.createNamedQuery("DataBankDataBean.findByKey")
    		                                    .setParameter(1, type)
    		                                    .setParameter(2,key).getSingleResult();
    		if(persistData != null){
    			retval = persistData.getValue();
    		}
    	}catch(NoResultException e){}
    	
    	return retval;
	}
    

    
    /**
     * Method used to set a property in the data bank.
     * 
     * @param type can be one of TYPE_ constants.
     * @param key of property
     * @param value to set
     */
    public void setProperty(int type, String key, String value){
    	DataBankDataBean persistData = null;
    	try{
    		persistData = (DataBankDataBean) workerEntityManager.createNamedQuery("DataBankDataBean.findByKey")
    		                                    .setParameter(1, type)
    		                                    .setParameter(2,key).getSingleResult();
    	}catch(NoResultException e){}
		boolean persist = false;		
				
		if(persistData == null){
			persistData = new DataBankDataBean();
			persist = true;		
		}
		persistData.setType(type);
		persistData.setKey(key);		
		persistData.setValue(value);
		if(persist){
			workerEntityManager.persist(persistData);
		}				
	}
    
    /**
     * Method used to set a property in the data bank wuth
     * a relation to a foreign object
     * 
     * @param type can be one of TYPE_ constants.
     * @param relatedId id of foreign object.
     * @param key of property
     * @param value to set
     */
    public void setRelatedProperty(int type, int relatedId, String key, String value){
    	DataBankDataBean persistData = null;
    	try{
    		persistData = (DataBankDataBean) workerEntityManager.createNamedQuery("DataBankDataBean.findByTypeAndRelatedIdAndKey")
    		                                    .setParameter(1, type)
    		                                    .setParameter(2, relatedId)
    		                                    .setParameter(3,key).getSingleResult();
    	}catch(NoResultException e){}
		boolean persist = false;		
				
		if(persistData == null){
			persistData = new DataBankDataBean();
			persist = true;		
		}
		persistData.setType(type);
		persistData.setRelatedId(relatedId);
		persistData.setKey(key);		
		persistData.setValue(value);
		if(persist){
			workerEntityManager.persist(persistData);
		}				
	}
	
    /**
     * Method used to remove a property from the data bank.
     * 
     * @param type can be one of TYPE_ constants.
     * @param key of property to remove
     */
    public void removePropery(int type, String key){
    	DataBankDataBean data = null;
    	try{
    		data = (DataBankDataBean) workerEntityManager.createNamedQuery("DataBankDataBean.findByKey")
    		                                    .setParameter(1, type)
    		                                    .setParameter(2,key).getSingleResult();
    	}catch(NoResultException e){}
		
    	if(data != null){    		
    		workerEntityManager.remove(data);		    		
    	}
	}
    
    /**
     * Method used to remove a property from the data bank.
     * 
     * @param type can be one of TYPE_ constants.
     * @param key of property to remove
     */
    public void removeRelatedPropery(int type, int relatedId, String key){
    	DataBankDataBean data = null;
    	try{
    		data = (DataBankDataBean) workerEntityManager.createNamedQuery("DataBankDataBean.findByTypeAndRelatedIdAndKey")
    		                                    .setParameter(1, type)
    		                                    .setParameter(2, relatedId)
    		                                    .setParameter(3,key).getSingleResult();
    	}catch(NoResultException e){}
		
    	if(data != null){    		
    		workerEntityManager.remove(data);		    		
    	}
	}

}
