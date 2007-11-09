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
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.SignerConfig;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.WorkerConfigDataService;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.server.service.IService;
import org.signserver.server.signers.ISigner;


/**
 * Class used to manage different signers used in the system, uses the configuration in
 * GlobalConfigurationFileParser as a backup.
 * 
 * @author Philip Vendil
 *
 */
public  class WorkerFactory {
	/** Log4j instance for actual implementation class */
	public static transient Logger log = Logger.getLogger(WorkerFactory.class);
  
	private static WorkerFactory instance = new WorkerFactory();
	
	public static WorkerFactory getInstance(){
		return instance;
	}
	
	private Map<Integer, IWorker> workerStore = null;
	private Map<String, Integer> nameToIdMap = null;
	
	
	
	/**
	 * Method returning a worker given it's id. The signer should be defined in 
	 * the global configuration along with it's id.
	 * 
	 * 
	 * The worker will only be created upon first call, then it's stored in memory until
	 * the flush method is called.
	 * 
	 * @param signerId the Id that should match the one in the config file.
	 * @param workerConfigHome The service interface of the signer config entity bean
	 * @return A ISigner as defined in the configuration file, or null if no configuration
	 * for the specified signerId could be found.
	 */
	public IWorker getWorker(int workerId, WorkerConfigDataService workerConfigHome, IGlobalConfigurationSession.ILocal gCSession){	   
	   Integer id = new Integer(workerId);	
			
	   loadWorkers(workerConfigHome,gCSession);
	   synchronized(workerStore){			   
		   return (IWorker) workerStore.get(id);
	   }

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
	public ISigner getSigner(String signerName, WorkerConfigDataService workerConfigHome, IGlobalConfigurationSession.ILocal gCSession){	   
	   ISigner retval = null;

	   loadWorkers(workerConfigHome,gCSession);
		
	   synchronized(nameToIdMap){	
		   synchronized(workerStore){
			   if(nameToIdMap.get(signerName) != null){
				   retval = (ISigner) workerStore.get(nameToIdMap.get(signerName));
			   }
		   }
	   }
		
	   return retval;
	}
	
	/**
	 * Method returning a id of a named Worker
	 * 
	 * 
	 * The worker will only be created upon first call, then it's stored in memory until
	 * the flush method is called.
	 * 
	 * @param workerName the name of a named worker.
	 * @param workerConfigHome The home interface of the signer config entity bean
	 * @return the id of the signer or 0 if no worker with the name is found.
	 */
	public int getWorkerIdFromName(String workerName, WorkerConfigDataService workerConfigHome, IGlobalConfigurationSession.ILocal gCSession){	   
	   int retval = 0;		 	   
	   loadWorkers(workerConfigHome,gCSession);
	   synchronized(nameToIdMap){	
		   synchronized(workerStore){
			   if(nameToIdMap.get(workerName) == null){
				   return retval;
			   }

			   retval = ((Integer)nameToIdMap.get(workerName)).intValue();
		   }
	   }
	   log.debug("getSignerIdFromName : returning " + retval); 
	   return retval;
	}
	
	/**
	 * Method to load all available signers
	 */
	private void loadWorkers(WorkerConfigDataService workerConfigHome, IGlobalConfigurationSession.ILocal gCSession){
		   if(workerStore == null){
              workerStore = new HashMap<Integer, IWorker>();
              nameToIdMap = new HashMap<String,Integer>();
			   
			  Collection<Integer> workers = gCSession.getWorkers(GlobalConfiguration.WORKERTYPE_ALL);
			  GlobalConfiguration gc = gCSession.getGlobalConfiguration();
			  Iterator<Integer> iter = workers.iterator();
			  while(iter.hasNext()){
				  Integer nextId = (Integer) iter.next();				   
				  try{	
					  String classpath = gc.getWorkerClassPath(nextId.intValue());						
					  if(classpath != null){					
						  Class<?> implClass =  Class.forName(classpath);
						  Object obj = implClass.newInstance();
						  
						  WorkerConfig config = null;
						  if(obj instanceof ISigner){
							  config = getWorkerProperties(nextId.intValue(), workerConfigHome);
							  if(config.getProperties().getProperty(SignerConfig.NAME) != null){
								  
								  getNameToIdMap().put(config.getProperties().getProperty(SignerConfig.NAME).toUpperCase(), nextId); 
							  }  
						  }
						  if(obj instanceof IService){
							  config = getWorkerProperties(nextId.intValue(), workerConfigHome);
						  }

						  ((IWorker) obj).init(nextId.intValue(), config);						  
						  getWorkerStore().put(nextId,(IWorker) obj);
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
	public void flush(){
		if(workerStore != null){
			workerStore = null;
			nameToIdMap = null;			
		}
	}
	
	/**
	 * Method used to force a reload of worker. 
	 * @param id of worker
	 */
	public void reloadWorker(int id,WorkerConfigDataService workerConfigHome, IGlobalConfigurationSession.ILocal gCSession){

		if(workerStore == null){
			workerStore = Collections.synchronizedMap(new HashMap<Integer, IWorker>());
			nameToIdMap = Collections.synchronizedMap(new HashMap<String, Integer>());
		}
		synchronized(nameToIdMap){	
			synchronized(workerStore){
				if(id != 0){
					workerStore.put(new Integer(id),null);
					Iterator<String> iter = nameToIdMap.keySet().iterator();
					while(iter.hasNext()){
						String next = (String) iter.next();
						if(nameToIdMap.get(next) != null && 
								((Integer) nameToIdMap.get(next)).intValue() == id){
							iter.remove();
						}
					}
				}
				GlobalConfiguration gc = gCSession.getGlobalConfiguration();

				try{	
					String classpath = gc.getWorkerClassPath(id);						
					if(classpath != null){					
						Class<?> implClass = Class.forName(classpath);
						Object obj = implClass.newInstance();

						WorkerConfig config = null;
						if(obj instanceof ISigner){
							config = getWorkerProperties(id, workerConfigHome);
							if(config.getProperties().getProperty(SignerConfig.NAME) != null){
								getNameToIdMap().put(config.getProperties().getProperty(SignerConfig.NAME).toUpperCase(), new Integer(id)); 
							}  
						}
						if(obj instanceof IService){
							config = getWorkerProperties(id, workerConfigHome);
						}

						((IWorker) obj).init(id, config);						  
						getWorkerStore().put(new Integer(id),(IWorker) obj);
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



	
	private WorkerConfig getWorkerProperties(int workerId, WorkerConfigDataService workerConfigHome){

		WorkerConfig workerConfig = workerConfigHome.getWorkerConfig(workerId);
		if(workerConfig == null){			
			workerConfigHome.create(workerId,  WorkerConfig.class.getName());
			workerConfig = workerConfigHome.getWorkerConfig(workerId);
		}

		return workerConfig;
	}
	
	private Map<String, Integer> getNameToIdMap(){
		if(nameToIdMap == null){
			nameToIdMap =  Collections.synchronizedMap(new HashMap<String, Integer>());
		}
		return nameToIdMap;
		
	}
	
	private Map<Integer, IWorker> getWorkerStore(){
		if(workerStore == null){
			workerStore = Collections.synchronizedMap(new HashMap<Integer, IWorker>());
		}
		return workerStore;
		
	}

}
