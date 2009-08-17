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
import java.util.List;
import java.util.Vector;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ResyncException;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.mailsigner.IMailProcessor;
import org.signserver.mailsigner.MailSignerContext;
import org.signserver.server.IWorker;
import org.signserver.server.PropertyFileStore;
import org.signserver.server.WorkerFactory;
import org.signserver.server.timedservices.ITimedService;

/**
 * Class in charge of the Non-EJB representation of the global configuration.
 * The class should externally act in the same way as the EJB GlobalConfiguration.
 * 
 * But advanced features such as resync isn't supported.
 * 
 * @author Philip Vendil
 * $id$
 */
public class NonEJBGlobalConfigurationSession implements IGlobalConfigurationSession{
	
	/** Log4j instance for actual implementation class */
	private transient Logger log = Logger.getLogger(this.getClass());
	private GlobalConfiguration cachedGlobalConfiguration;	
	private ConcurrentHashMap<Integer, Vector<Integer>> workersTypes = new ConcurrentHashMap<Integer, Vector<Integer>>();
	
	
	private static NonEJBGlobalConfigurationSession instance = null;
	/**
	 * Method used to fetch the non EJB global SessionBean.
	 */
	public static NonEJBGlobalConfigurationSession getInstance(){
		if(instance == null){
			instance = new NonEJBGlobalConfigurationSession();
		}
		
		return instance;
	}
	
	private NonEJBGlobalConfigurationSession(){}
	
	/**
	 * Method setting a global configuration property. 
	 * For node. prefix will the node id be appended.
	 * 
	 * @param scope one of the GlobalConfiguration.SCOPE_ constants
	 * @param key of the property should not have any scope prefix, never null
	 * @param value the value, never null.
	 */
	public void setProperty(String scope, String key, String value) {									           
		PropertyFileStore.getInstance().setGlobalProperty(scope, key, value);
		cachedGlobalConfiguration = null;
		workersTypes = new ConcurrentHashMap<Integer, Vector<Integer>>();
	}
	
	

	
	
	/**
	 * Method used to remove a property from the global configuration.
	 * 
	 * @param scope one of the GlobalConfiguration.SCOPE_ constants
	 * @param key of the property should start with either glob. or node., never null
	 * @return true if removal was successful, otherwise false.
	 */
	public boolean removeProperty(String scope, String key){
		boolean retval = false;
		
		if(getGlobalConfiguration().getProperty(scope, key) != null){
		  PropertyFileStore.getInstance().removeGlobalProperty(scope, key);
		  cachedGlobalConfiguration = null;
		  workersTypes = new ConcurrentHashMap<Integer, Vector<Integer>>();
		  retval = true;
		}

		return retval;
	}
	
	/**
	 * Method that returns all the global properties with
	 * Global Scope and Node scopes properties for this node.
	 * 
	 * @return A GlobalConfiguration Object, never5d null
	 */ 
	public GlobalConfiguration getGlobalConfiguration(){

		if(cachedGlobalConfiguration  == null){
			cachedGlobalConfiguration = PropertyFileStore.getInstance().getGlobalConfiguration();
		}
				
		return cachedGlobalConfiguration;
	}
	
	/**
	 * Help method that returns all worker, either signers
	 * or services defined in the global configuration.
	 * 
	 * @param workerType can either be GlobalConfiguration.WORKERTYPE_ALL, _SIGNERS or _SERVICES
	 * 
	 * @return A List if Integers of worker Ids, never null.
	 */
	public List<Integer> getWorkers(int workerType){
		Vector<Integer> retval = null;
		
		retval = workersTypes.get(workerType);
		
		if(retval == null){
			retval = new Vector<Integer>();
			GlobalConfiguration gc = getGlobalConfiguration();

			Enumeration<String> en = gc.getKeyEnumeration();
			while(en.hasMoreElements()){
				String key = (String) en.nextElement();  
				log.debug("getWorkers, processing key : " + key);
				if(key.startsWith("GLOB.WORKER")){
					retval = (Vector<Integer>) getWorkerHelper(retval,gc,key,workerType);
				}

			}
			
			workersTypes.put(workerType, retval);
			
		}
        return retval;
	}
	
	private List<Integer> getWorkerHelper(List<Integer> retval, GlobalConfiguration gc, String key, int workerType){
				
			String strippedKey = key.substring("GLOB.WORKER".length());
			String[] splittedKey = strippedKey.split("\\.");
			if(splittedKey.length > 1){
				if(splittedKey[1].equals("CLASSPATH")){
					int id = Integer.parseInt(splittedKey[0]);
					if(workerType == GlobalConfiguration.WORKERTYPE_ALL){
						retval.add(new Integer(id));
					}else{
						IWorker worker = WorkerFactory.getInstance().getWorker(id, MailSignerWorkerConfigService.getInstance(), NonEJBGlobalConfigurationSession.getInstance(), MailSignerContext.getInstance());
						if(workerType == GlobalConfiguration.WORKERTYPE_MAILSIGNERS){
							if(worker instanceof IMailProcessor){
								log.debug("Adding Mail Signer " + id);
								retval.add(new Integer(id));        			   
							}
						}
						if(workerType == GlobalConfiguration.WORKERTYPE_SERVICES){							
							if(worker instanceof ITimedService){
								log.debug("Adding Mail Signer " + id);
								retval.add(new Integer(id));        			   
							}
						}
					}
				}
			}


		return retval;
	}

	
	
	/**
	 * Method to reload all data from database.
	 * 
	 */
	public void reload() {
        PropertyFileStore.getInstance().reload();
        cachedGlobalConfiguration = null;
        workersTypes = new ConcurrentHashMap<Integer, Vector<Integer>>();
        WorkerFactory.getInstance().flush();
	}

	/**
	 * Method not supported
	 */
	public void resync() throws ResyncException {		
	}
	




	

}
