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

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.SignServerConstants;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.server.clusterclassloader.ExtendedClusterClassLoader;


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
	
	private WorkerFactory(){}
	
	public static WorkerFactory getInstance(){
		return instance;
	}
	
	private Map<Integer, IWorker> workerStore = null;
	private Map<Integer, IAuthorizer> authenticatorStore = null;
	private Map<String, Integer> nameToIdMap = null;
	private Map<Integer, ClassLoader> workerClassLoaderMap = null;
	
	
	
	
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
	 * @param mailSignerContext 
	 * @return A ISigner as defined in the configuration file, or null if no configuration
	 * for the specified signerId could be found.
	 */
	public IWorker getWorker(int workerId, IWorkerConfigDataService workerConfigHome, IGlobalConfigurationSession gCSession, WorkerContext workerContext){	   
	   Integer id = new Integer(workerId);	
			
	   loadWorkers(workerConfigHome,gCSession,workerContext);
	   synchronized(workerStore){			   
		   IWorker ret = (IWorker) workerStore.get(id);
		   if (ret == null) {
			   log.info("Trying to get worker with Id that does not exist: "+workerId);
		   }
		   return ret;
	   }

	}
	
	/**
	 * Method returning a signer given it's name. The signers NAME should be defined in 
	 * the signers configuration as the property NAME.
	 * 
	 * 
	 * The worker will only be created upon first call, then it's stored in memory until
	 * the flush method is called.
	 * 
	 * @param workerName the name that should match the one in the config file.
	 * @param workerConfigHome The home interface of the signer config entity bean
	 * @return A ISigner as defined in the configuration file, or null if no configuration
	 * for the specified signerId could be found.
	 */
	/*
	public IProcessable getProcessable(String workerName, IWorkerConfigDataService workerConfigHome, IGlobalConfigurationSession.ILocal gCSession, EntityManager em, WorkerContext workerContext){	   
	   IProcessable retval = null;

	   loadWorkers(workerConfigHome,gCSession,em, workerContext);
		
	   synchronized(nameToIdMap){	
		   synchronized(workerStore){
			   if(nameToIdMap.get(workerName) != null){
				   retval = (IProcessable) workerStore.get(nameToIdMap.get(workerName));
			   }
		   }
	   }
		
	   return retval;
	}*/
	
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
	public int getWorkerIdFromName(String workerName, IWorkerConfigDataService workerConfigHome, IGlobalConfigurationSession gCSession, WorkerContext workerContext){	   
	   int retval = 0;		 	   
	   loadWorkers(workerConfigHome,gCSession, workerContext);
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
	private synchronized void loadWorkers(IWorkerConfigDataService workerConfigHome, IGlobalConfigurationSession gCSession, WorkerContext workerContext){
		   if(workerStore == null){
              workerStore = new HashMap<Integer, IWorker>();
              nameToIdMap = new HashMap<String,Integer>();
              workerClassLoaderMap=  new HashMap<Integer,ClassLoader>();
			   
			  Collection<Integer> workers = gCSession.getWorkers(GlobalConfiguration.WORKERTYPE_ALL);
			  GlobalConfiguration gc = gCSession.getGlobalConfiguration();
			  Iterator<Integer> iter = workers.iterator();
			  while(iter.hasNext()){
				  Integer nextId = (Integer) iter.next();				   
				  try{	
					  String classpath = gc.getWorkerClassPath(nextId.intValue());						
					  if(classpath != null){
						  WorkerConfig config = workerConfigHome.getWorkerProperties(nextId.intValue());
						  						  
						  EntityManager em = null;
						  if(workerContext instanceof SignServerContext){
							  em = ((SignServerContext) workerContext).getEntityManager();
						  }
						  ClassLoader cl = getClassLoader(em, nextId,config);
						  Class<?>  implClass =  cl.loadClass(classpath);
						  
						  Object obj = implClass.newInstance();
						  
						  if(obj instanceof IProcessable || obj.getClass().getSimpleName().equals("IMailProcessor")){
							  config = workerConfigHome.getWorkerProperties(nextId.intValue());
							  if(config.getProperties().getProperty(ProcessableConfig.NAME) != null){
								  
								  getNameToIdMap().put(config.getProperties().getProperty(ProcessableConfig.NAME).toUpperCase(), nextId); 
							  }  
						  }

						  if(getClassLoader(em, nextId.intValue(),config) instanceof ExtendedClusterClassLoader){
							  ((IWorker) obj).init(nextId.intValue(), config, workerContext,((ExtendedClusterClassLoader) getClassLoader(em, nextId,config)).getWorkerEntityManger(config));
						  }else{
							  ((IWorker) obj).init(nextId.intValue(),config, workerContext,null);
						  }
						  getWorkerStore().put(nextId,(IWorker) obj);
					  }  
				  }catch(ClassNotFoundException e){
					  log.error("Error loading workers : " + e.getMessage(), e);
				  }
				  catch(IllegalAccessException e){
					  log.error("Error loading workers : " + e.getMessage(), e);
				  }
				  catch(InstantiationException e){
					  log.error("Error loading workers : " + e.getMessage(), e);
				  } 
			  }
		   }
	}
	

	/**
	 * Method that manages all available class loaders in the system.
	 * 
	 * It looks up the version used in the worker configuration by the 
	 * properties MODULENAME, and MODULEVERSION, the the setting doesn't exist will
	 * the latest available version be used.
	 * 
	 * If MODULENAME isn't specified will the default app server
	 * class loader be used.
	 * 
	 * @param config the worker configuration
	 * @return the class loader specific for the given worker.
	 */	
	public ClassLoader getClassLoader(EntityManager em, int workerId, WorkerConfig config) {
		ClassLoader retval = workerClassLoaderMap.get(workerId);
		if(retval == null){
			retval = this.getClass().getClassLoader();
			String moduleName = config.getProperty(SignServerConstants.MODULENAME);
			if(GlobalConfiguration.isClusterClassLoaderEnabled() && config.getProperty("MODULENAME") != null){
				Integer moduleVersion = null;
				try{
					if(config.getProperty(SignServerConstants.MODULEVERSION) != null){
						moduleVersion = Integer.parseInt(config.getProperty(SignServerConstants.MODULEVERSION));
					}
				}catch(NumberFormatException e){
					log.error("Error: Worker with id " + workerId + " is missconfigured property " + SignServerConstants.MODULEVERSION + " should only contain digits but has the value "
							+ config.getProperty(SignServerConstants.MODULEVERSION));
				}

				if(moduleVersion == null){
					retval = new ExtendedClusterClassLoader(this.getClass().getClassLoader(),em,moduleName,"server");
				}else{
					retval = new ExtendedClusterClassLoader(this.getClass().getClassLoader(),em,moduleName,"server",moduleVersion);
				}
			}
			
			workerClassLoaderMap.put(workerId, retval);

		}
		return retval;
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
			authenticatorStore = null;
			workerClassLoaderMap = null;
		}
	}
	
	/**
	 * Method used to force a reload of worker. 
	 * @param id of worker
	 */
	public void reloadWorker(int id,IWorkerConfigDataService workerConfigHome, IGlobalConfigurationSession gCSession, WorkerContext workerContext){

		if(workerStore == null){
			workerStore = Collections.synchronizedMap(new HashMap<Integer, IWorker>());
			nameToIdMap = Collections.synchronizedMap(new HashMap<String, Integer>());
			
		}
		
		if(authenticatorStore == null){
			authenticatorStore = Collections.synchronizedMap(new HashMap<Integer, IAuthorizer>());
		}
		
		if(workerClassLoaderMap == null){
			workerClassLoaderMap = Collections.synchronizedMap(new HashMap<Integer, ClassLoader>());
		}
		
		synchronized(nameToIdMap){	
			synchronized(workerStore){
				synchronized(authenticatorStore){
					synchronized(workerClassLoaderMap){
						if(id != 0){

							workerStore.put(id,null);
							authenticatorStore.put(id, null);
							workerClassLoaderMap.put(id, null);
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
								WorkerConfig config = workerConfigHome.getWorkerProperties(id);
								EntityManager em = null;
								if(workerContext instanceof SignServerContext){
									em = ((SignServerContext) workerContext).getEntityManager();
								}
								ClassLoader cl = getClassLoader(em, id,config);
								Class<?>  implClass =  cl.loadClass(classpath);

								Object obj = implClass.newInstance();

								if(obj instanceof IProcessable || obj.getClass().getSimpleName().equals("IMailProcessor")){
									if(config.getProperties().getProperty(ProcessableConfig.NAME) != null){
										getNameToIdMap().put(config.getProperties().getProperty(ProcessableConfig.NAME).toUpperCase(), new Integer(id)); 
									}  
								}

								if(getClassLoader(em, id,config) instanceof ExtendedClusterClassLoader){
								  ((IWorker) obj).init(id, config, workerContext, ((ExtendedClusterClassLoader) getClassLoader(em, id,config)).getWorkerEntityManger(config));
								}else{
								  ((IWorker) obj).init(id, config, workerContext,null);
								}
								getWorkerStore().put(new Integer(id),(IWorker) obj);
							}  
						}catch(ClassNotFoundException e){
							log.error("Error reloading worker : " + e.getMessage(), e);
						}
						catch(IllegalAccessException e){
							log.error("Error reloading worker : " + e.getMessage(), e);
						}
						catch(InstantiationException e){
							log.error("Error reloading worker : " + e.getMessage(), e);
						} 
					}
				}
			}
		}
	}		

	/**
	 * Returns the configured authorizer for the given worker.
	 * 
	 * @param workerId id of worker 
	 * @param authType one of ISigner.AUTHTYPE_ constants or class path to custom implementation
	 * @return initialized authorizer.
	 */
	public IAuthorizer getAuthenticator(int workerId, String authType, WorkerConfig config, EntityManager em) throws IllegalRequestException{
		if(getAuthenticatorStore().get(workerId) == null){
			IAuthorizer auth = null;
			if(authType.equalsIgnoreCase(IProcessable.AUTHTYPE_NOAUTH)){
				auth = new NoAuthorizer();				
			}else if (authType.equalsIgnoreCase(IProcessable.AUTHTYPE_CLIENTCERT)){
				auth = new ClientCertAuthorizer();
			}else{

				try {
					Class<?> c = getClassLoader(em,workerId,config).loadClass(authType);
					auth = (IAuthorizer) c.newInstance();
				} catch (ClassNotFoundException e) {
					log.error("Error worker with id " + workerId + " missconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.",e);
					throw new IllegalRequestException("Error worker with id " + workerId + " missconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.");
				} catch (InstantiationException e) {
					log.error("Error worker with id " + workerId + " missconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.",e);
					throw new IllegalRequestException("Error worker with id " + workerId + " missconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.");
				} catch (IllegalAccessException e) {
					log.error("Error worker with id " + workerId + " missconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.",e);
					throw new IllegalRequestException("Error worker with id " + workerId + " missconfiguration, AUTHTYPE setting : " + authType + " is not a correct class path.");
				}
				
			}
			try {
				auth.init(workerId, config, em);
			} catch (SignServerException e) {
				log.error("Error initializing authorizer for worker " + workerId + " with authtype " + authType + ", message : " + e.getMessage(),e );
			}
			getAuthenticatorStore().put(workerId, auth);
		}
		return getAuthenticatorStore().get(workerId);
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
	
	private Map<Integer, IAuthorizer> getAuthenticatorStore(){
		if(authenticatorStore == null){
			authenticatorStore = Collections.synchronizedMap(new HashMap<Integer, IAuthorizer>());
		}
		return authenticatorStore;
		
	}


}
