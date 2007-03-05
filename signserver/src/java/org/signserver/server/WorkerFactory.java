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

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;

import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ServiceConfig;
import org.signserver.common.SignerConfig;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.IGlobalConfigurationSessionLocal;
import org.signserver.ejb.WorkerConfigDataLocal;
import org.signserver.ejb.WorkerConfigDataLocalHome;
import org.signserver.ejb.WorkerConfigDataPK;
import org.signserver.server.service.IService;
import org.signserver.server.signers.ISigner;


/**
 * Class used to manage different signers used in the system, uses the configuration in
 * GlobalConfigurationFileParser as a backup.
 * 
 * @author Philip Vendil
 *
 */
public class WorkerFactory {
	/** Log4j instance for actual implementation class */
	public static transient Logger log = Logger.getLogger(WorkerFactory.class);
  
	private static HashMap workerStore = null;
	private static HashMap nameToIdMap = null;
	
	private WorkerFactory(){}
	
	/**
	 * Method returning a worker given it's id. The signer should be defined in 
	 * the global configuration along with it's id.
	 * 
	 * 
	 * The worker will only be created upon first call, then it's stored in memory until
	 * the flush method is called.
	 * 
	 * @param signerId the Id that should match the one in the config file.
	 * @param workerConfigHome The home interface of the signer config entity bean
	 * @return A ISigner as defined in the configuration file, or null if no configuration
	 * for the specified signerId could be found.
	 */
	public static IWorker getWorker(int workerId, WorkerConfigDataLocalHome workerConfigHome, IGlobalConfigurationSessionLocal gCSession){	   
	   Integer id = new Integer(workerId);	
			
	   loadWorkers(workerConfigHome,gCSession);
		
	   return (IWorker) workerStore.get(id);
	}
	
	/**
	 * Method returning a signer given it's name. The signers NAME should be defined in 
	 * the signers configuration as the property NAME.
	 * 
	 * 
	 * The signer will only be created upon first call, then it's stored in memory until
	 * the flush method is called.
	 * 
	 * @param signerId the Id that should match the one in the config file.
	 * @param workerConfigHome The home interface of the signer config entity bean
	 * @return A ISigner as defined in the configuration file, or null if no configuration
	 * for the specified signerId could be found.
	 */
	public static ISigner getSigner(String signerName, WorkerConfigDataLocalHome workerConfigHome, IGlobalConfigurationSessionLocal gCSession){	   
	   ISigner retval = null;
	   			   
	   loadWorkers(workerConfigHome,gCSession);
	   if(nameToIdMap.get(signerName) != null){
		   retval = (ISigner) workerStore.get(nameToIdMap.get(signerName));
	   }
		
	   return retval;
	}
	
	/**
	 * Method returning a id of a named signer
	 * 
	 * 
	 * The signer will only be created upon first call, then it's stored in memory until
	 * the flush method is called.
	 * 
	 * @param signerName the name of a named signer.
	 * @param workerConfigHome The home interface of the signer config entity bean
	 * @return the id of the signer or null if no worker with the name is found.
	 */
	public static int getSignerIdFromName(String signerName, WorkerConfigDataLocalHome workerConfigHome, IGlobalConfigurationSessionLocal gCSession){	   
	   int retval = 0;		 	   
	   loadWorkers(workerConfigHome,gCSession);
		
	   if(nameToIdMap.get(signerName) == null){
		   return retval;
	   }
	   
	   retval = ((Integer)nameToIdMap.get(signerName)).intValue();
	   log.debug("getSignerIdFromName : returning " + retval); 
	   return retval;
	}
	
	/**
	 * Method to load all available signers
	 */
	private static void loadWorkers(WorkerConfigDataLocalHome workerConfigHome, IGlobalConfigurationSessionLocal gCSession){
		   if(workerStore == null){
			  workerStore = new HashMap();
			  nameToIdMap = new HashMap();
			   
			  Collection workers = gCSession.getWorkers(GlobalConfiguration.WORKERTYPE_ALL);
			  GlobalConfiguration gc = gCSession.getGlobalConfiguration();
			  Iterator iter = workers.iterator();
			  while(iter.hasNext()){
				  Integer nextId = (Integer) iter.next();				   
				  try{	
					  String classpath = gc.getWorkerClassPath(nextId.intValue());						
					  if(classpath != null){					
						  Class implClass = Class.forName(classpath);
						  Object obj = implClass.newInstance();
						  
						  WorkerConfig config = null;
						  if(obj instanceof ISigner){
							  config = getWorkerProperties(nextId.intValue(), workerConfigHome);
							  if(config.getProperties().getProperty(SignerConfig.NAME) != null){
								  nameToIdMap.put(config.getProperties().getProperty(SignerConfig.NAME).toUpperCase(), nextId); 
							  }  
						  }
						  if(obj instanceof IService){
							  config = getWorkerProperties(nextId.intValue(), workerConfigHome);
						  }

						  ((IWorker) obj).init(nextId.intValue(), config);						  
						  workerStore.put(nextId,obj);
					  }  
				  }catch(ClassNotFoundException e){
					  throw new EJBException(e);
				  }
				  catch(IllegalAccessException iae){
					  throw new EJBException(iae);
				  }
				  catch(InstantiationException ie){
					  throw new EJBException(ie);
				  } 
			  }
		   }
	}
	

	
	/**
	 * Method used to force reinitialization of all the signers.
	 * Should be called from the GlobalConfigurationFileParser.reloadConfiguration() method
	 *
	 */
	public static void flush(){
		if(workerStore != null){
			workerStore = null;
			nameToIdMap = null;			
		}
		
		

	}
	
	private static WorkerConfig getWorkerProperties(int workerId, WorkerConfigDataLocalHome workerConfigHome){
		
		WorkerConfigDataLocal workerConfig = null;
	    try {	    	
			workerConfig = workerConfigHome.findByPrimaryKey(new WorkerConfigDataPK(workerId));
		} catch (FinderException e) {
			try {				
				workerConfig = workerConfigHome.create(workerId,  WorkerConfig.class.getName());
			} catch (CreateException e1) {
               throw new EJBException(e1);
			}
		}
		
		return workerConfig.getWorkerConfig();
	}

}
