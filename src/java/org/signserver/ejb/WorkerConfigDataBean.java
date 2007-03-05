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

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.Base64PutHashMap;
import org.signserver.common.SignerConfig;
import org.signserver.common.WorkerConfig;



/**
 * Entity Bean storing each worker configuration.
 * OBS: The old columns signerId and signerConfigData is still used
 * for the database columns but their name in the application have been
 * changed to workerId and workerConfig.
 * 
 * Information stored:
 * <pre>
 * signerId (PrimaryKey, int)
 * signerConfigData (WorkerConfig in xml-encoding, String)
 * </pre>
 *
 * @version $Id: WorkerConfigDataBean.java,v 1.2 2007-03-05 06:48:32 herrvendil Exp $
 * 
 * @ejb.bean description="Entity Bean storing each signer configuration"
 * display-name="WorkerConfigDataBean"
 * name="WorkerConfigData"
 * view-type="local"
 * type="CMP"
 * reentrant="False"
 * cmp-version="2.x"
 * transaction-type="Container"
 * schema="WorkerConfigDataBean"
 * 
 * @ejb.transaction type="Required"
 *
 * @ejb.permission role-name="InternalUser"
 * 
 * @ejb.persistence table-name="signerconfigdata"
 *
 *
 * @ejb.pk class="org.signserver.ejb.WorkerConfigDataPK"
 * extends="java.lang.Object"
 * implements="java.io.Serializable"
 *
 * @ejb.home
 * generate="local"
 * local-extends="javax.ejb.EJBLocalHome"
 * local-class="org.signserver.ejb.WorkerConfigDataLocalHome"
 *
 * @ejb.interface
 * generate="local"
 * local-extends="javax.ejb.EJBLocalObject"
 * local-class="org.signserver.ejb.WorkerConfigDataLocal"
 *
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 */
public abstract class WorkerConfigDataBean extends BaseEntityBean {

    private static final Logger log = Logger.getLogger(WorkerConfigDataBean.class);
     
    /**
     * Unique Id of the signer
     *
     * @return signerId
     * @ejb.persistence
     * @ejb.interface-method
     * @ejb.pk-field 
     */
    public abstract int getSignerId();

    /**
     * Unique Id of the signer
     * Shouldn't be set after creation.
     * 
     * @param signerId signerId
     * @ejb.persistence
     */
    public abstract void setSignerId(int signerId);

    /**
     * WorkerConfig in xmlencoded String format
     * Shouldn't be used outside of entity bean, use getSignerConfig instead
     *
     * @return  xmlencoded encoded WorkerConfig
     * @ejb.persistence jdbc-type="LONGVARCHAR"
     */
    public abstract String getSignerConfigData();

    /**
     * WorkerConfig in  xmlencoded String format
     *
     * @param WorkerConfig xmlencoded encoded WorkerConfig
     * @ejb.persistence
     */
    public abstract void setSignerConfigData(String SignerConfig);
    

    //
    // Public business methods used to help us manage certificates
    //

    /**
     * Returns the value object containing the information of the entity bean.
     * This is the method that should be used to retreive cert req history 
     * correctly.
     *
     * @return certificate request history object
     * @ejb.interface-method
     */
    public WorkerConfig getWorkerConfig() {
    	    	
    	
    	
    	java.beans.XMLDecoder decoder;
    	try {
    		decoder =
    			new java.beans.XMLDecoder(
    					new java.io.ByteArrayInputStream(getSignerConfigData().getBytes("UTF8")));
    	} catch (UnsupportedEncodingException e) {
    		throw new EJBException(e);
    	}
    	
    	HashMap h = (HashMap) decoder.readObject();
        decoder.close();
        // Handle Base64 encoded string values
        HashMap data = new Base64GetHashMap(h);
        
        WorkerConfig workerConf = null;
        if(data.get(WorkerConfig.CLASS) == null){
        	// Special case, need to upgrade from signserver 1.0
        	workerConf = new SignerConfig(new WorkerConfig()).getWorkerConfig();        	
        	workerConf.loadData(data);
        	workerConf.upgrade();        	
        }else{        	
        	try {
				workerConf = (WorkerConfig) this.getClass().getClassLoader().loadClass(WorkerConfig.class.getName()).newInstance();				
        	    workerConf.loadData(data);
        	    workerConf.upgrade();
			} catch (Exception e) {
				log.error(e);
			} 
        }
    		    	       
    	
        return workerConf;
    }
    
    /**
     * Method that saves the Worker Config to database.
     * @ejb.interface-method 
     */
    public void setWorkerConfig(WorkerConfig signconf){
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
    		setSignerConfigData(baos.toString("UTF8"));
    	} catch (UnsupportedEncodingException e) {
    		throw new EJBException(e);
    	}
    	
    	
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding info about a workers (service or signer) configuration
     * 
     * @param workerId uniqe Id of the worker 
     *
     * @return primary key
     * @ejb.create-method
     */
    public WorkerConfigDataPK ejbCreate(int workerId, String configClassPath)
        throws CreateException {
        
        log.debug("Creating worker config data, id=" + workerId);
        this.setSignerId(workerId);
                
        
        try {
			this.setWorkerConfig((WorkerConfig) this.getClass().getClassLoader().loadClass(configClassPath).newInstance());
		} catch (Exception e) {
			log.error(e);
		} 

        return null;
    }

    /**
     * required method, does nothing
     *
     * @param incert certificate
     * @param UserDataVO, the data used to issue the certificate. 
     */
    public void ejbPostCreate(int workerId, String configClassPath) {
        // Do nothing. Required.
    }



}
