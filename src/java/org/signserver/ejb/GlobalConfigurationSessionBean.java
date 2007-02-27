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

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.RemoveException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseSessionBean;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ResyncException;
import org.signserver.common.SignServerUtil;
import org.signserver.server.GlobalConfigurationCache;
import org.signserver.server.GlobalConfigurationFileParser;
import org.signserver.server.service.IService;
import org.signserver.server.signers.ISigner;

/**
 * The main session bean
 * 
 * @ejb.bean name="GlobalConfigurationSession"
 *           display-name="Global Configuration"
 *           description="GlobalConfigurationFileParser"
 *           jndi-name="GlobalConfigurationSession"
 *           local-jndi-name="GlobalConfigurationSessionLocal"
 *           type="Stateless"
 *           view-type="both"
 *           transaction-type="Container"
 *
 * @ejb.transaction type="Supports"                  
 *           
 * @ejb.ejb-external-ref
 *   description="GlobalConfigurationFileParser Entity Bean"
 *   view-type="local"
 *   ejb-name="GlobalConfigurationDataLocal"
 *   type="Entity"
 *   home="org.signserver.ejb.GlobalConfigurationDataLocalHome"
 *   business="org.signserver.ejb.GlobalConfigurationDataLocal"
 *   link="GlobalConfigurationData"
 *   
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.signserver.ejb.IGlobalConfigurationSessionLocalHome"
 *   remote-class="org.signserver.ejb.IGlobalConfigurationSessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.signserver.ejb.IGlobalConfigurationSessionLocal"
 *   remote-class="org.signserver.ejb.IGlobalConfigurationSession"
 * 
 * 
 * 
 * @ejb.security-identity
 *           run-as="InternalUser"
 *           
 * @version $id$
 */
public class GlobalConfigurationSessionBean extends BaseSessionBean {


	private static final long serialVersionUID = 1L;
	
	static{
		SignServerUtil.installBCProvider();
	}
	

	/**
	 * Environment variable pointing to the node id.
	 */
	private static final String NODEID_ENVVAR = "SIGNSERVER_NODEID";


	/** Log4j instance for actual implementation class */
	public transient Logger log = Logger.getLogger(this.getClass());

    /** The local home interface of Global Configuration entity bean. */
    private GlobalConfigurationDataLocalHome globalConfigHome = null;
    
 
	/**
	 * 
	 */
	public GlobalConfigurationSessionBean() {
		super();
		// Do Nothing     
	}
	
	/**
	 * Method setting a global configuration property. 
	 * For node. prefix will the node id be appended.
	 * 
	 * @param scope, one of the GlobalConfiguration.SCOPE_ constants
	 * @param key of the property should not have any scope prefix, never null
	 * @param value the value, never null.
	 * @ejb.interface-method
	 */
	public void setProperty(String scope, String key, String value) {				
		if(GlobalConfigurationCache.getCurrentState().equals(GlobalConfiguration.STATE_OUTOFSYNC)){
			GlobalConfigurationCache.getCachedGlobalConfig().setProperty(propertyKeyHelper(scope, key), value);
		}else{									            
			setPropertyHelper(propertyKeyHelper(scope, key), value);				
		}						
	}
	
	
	private String propertyKeyHelper(String scope, String key){
		String retval = null;
		String tempKey = key.toUpperCase();
		
		if(scope.equals(GlobalConfiguration.SCOPE_NODE)){            
			retval = GlobalConfiguration.SCOPE_NODE + getNodeId() + "." + tempKey;
		}else{
			if(scope.equals(GlobalConfiguration.SCOPE_GLOBAL)){
				retval = GlobalConfiguration.SCOPE_GLOBAL + tempKey;
			}else{
				log.error("Error : Invalid scope " + scope );
			}
		}
		
		return retval;
	}
	
	
	/**
	 * Method used to remove a property from the global configuration.
	 * 
	 * @param scope, one of the GlobalConfiguration.SCOPE_ constants
	 * @param key of the property should start with either glob. or node., never null
	 * @return true if removal was successful, othervise false.
	 * @ejb.interface-method
	 */
	public boolean removeProperty(String scope, String key){
		boolean retval = false;
		
		if(GlobalConfigurationCache.getCurrentState().equals(GlobalConfiguration.STATE_OUTOFSYNC)){
			GlobalConfigurationCache.getCachedGlobalConfig().remove(propertyKeyHelper(scope, key));
		}else{				
			try {
				globalConfigHome.remove(propertyKeyHelper(scope, key));
				GlobalConfigurationCache.setCachedGlobalConfig(null);
				retval = true;
			}catch (RemoveException e) {
			} catch (Throwable e) {
				log.error("Error connecting to database, configuration is un-syncronized", e);
				GlobalConfigurationCache.setCurrentState(GlobalConfiguration.STATE_OUTOFSYNC);
				GlobalConfigurationCache.getCachedGlobalConfig().remove(propertyKeyHelper(scope, key));
			}
		}
		return retval;
	}
	
	/**
	 * Method that returns all the global properties with
	 * Global Scope and Node scopes properties for this node.
	 * 
	 * @return A GlobalConfiguration Object, nevel null
	 * @ejb.interface-method
	 */ 
	public GlobalConfiguration getGlobalConfiguration(){
		GlobalConfiguration retval = null;
		
		if(GlobalConfigurationCache.getCachedGlobalConfig()  == null){
			GlobalConfigurationFileParser staticConfig = GlobalConfigurationFileParser.getInstance();
			Properties properties = staticConfig.getStaticGlobalConfiguration();

			try {
				Iterator iter = globalConfigHome.findAll().iterator();
				while(iter.hasNext()){
					GlobalConfigurationDataLocal data = (GlobalConfigurationDataLocal) iter.next();
					String rawkey = data.getPropertyKey();
					if(rawkey.startsWith(GlobalConfiguration.SCOPE_NODE)){
						String key = rawkey.replaceFirst(getNodeId() + ".", "");
						properties.setProperty(key, data.getPropertyValue());
					}else{
						if(rawkey.startsWith(GlobalConfiguration.SCOPE_GLOBAL)){
							properties.setProperty(rawkey, data.getPropertyValue());				
						}else{
							log.error("Illegal property in Global Configuration " + rawkey);
						}
					}				
				}
				
				GlobalConfigurationCache.setCachedGlobalConfig(properties);

			} catch (FinderException e) {
				log.error("Error fetching properties in the dynamic global configuration store",e);
			}
		}

		retval = new GlobalConfiguration(GlobalConfigurationCache.getCachedGlobalConfig(),GlobalConfigurationCache.getCurrentState());
		
		return retval;
	}
	
	/**
	 * Help method that returns all worker, either signers
	 * or services defined in the global configuration.
	 * 
	 * @param workerType can either be GlobalConfiguration.WORKERTYPE_ALL, _SIGNERS or _SERVICES
	 * 
	 * @return A List if Integers of worker Ids, never null.
	 * @ejb.interface-method
	 */
	public List getWorkers(int workerType){
		ArrayList retval = new ArrayList();
        GlobalConfiguration gc = getGlobalConfiguration();
        
        Iterator iter = gc.getKeyIterator();
        while(iter.hasNext()){
        	String key = (String) iter.next();  
        	debug("getWorkers, processing key : " + key);
        	if(key.startsWith("GLOB.WORKER")){
                retval = (ArrayList) getWorkerHelper(retval,gc,key,workerType,false);
        	}
        	if(key.startsWith("GLOB.SIGNER")){
        		retval = (ArrayList) getWorkerHelper(retval,gc,key,workerType,true);
        	}
        }
        
        return retval;
	}
	
	private List getWorkerHelper(List retval, GlobalConfiguration gc, String key, int workerType, boolean signersOnly){
		try{
   		String unScopedKey = key.substring("GLOB.".length());
   		log.debug("unScopedKey : " + unScopedKey);
		String strippedKey = key.substring("GLOB.WORKER".length());
		log.debug("strippedKey : " + strippedKey);
		String[] splittedKey = strippedKey.split("\\.");
		log.debug("splittedKey : " + splittedKey.length + ", " + splittedKey[0]);
		if(splittedKey.length > 1){
			if(splittedKey[1].equals("CLASSPATH")){
				int id = Integer.parseInt(splittedKey[0]);
				if(workerType == GlobalConfiguration.WORKERTYPE_ALL){
					retval.add(new Integer(id));
				}else{
					if(workerType == GlobalConfiguration.WORKERTYPE_SIGNERS){
						String classPath = gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, unScopedKey);
						log.debug("Found Classpath " + classPath);
						Object obj = this.getClass().getClassLoader().loadClass(classPath).newInstance();
						if(obj instanceof ISigner){
							log.debug("Adding Signer " + id);
							retval.add(new Integer(id));        			   
						}
					}else{
						if(workerType == GlobalConfiguration.WORKERTYPE_SERVICES && !signersOnly){
							String classPath = gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, unScopedKey);
							log.debug("Found Classpath " + classPath);
							Object obj = this.getClass().getClassLoader().loadClass(classPath).newInstance();
							if(obj instanceof IService){
								log.debug("Adding Service " + id);
								retval.add(new Integer(id));        			   
							}
						}
					}
				}

			}
		}
		} catch (ClassNotFoundException e) {
			error("Error in global configuration for configurared workers, classpath not found",e);
		} catch (InstantiationException e) {
			error("Error in global configuration for configurared workers, classpath not found",e);
		} catch (IllegalAccessException e) {
			error("Error in global configuration for configurared workers, classpath not found",e);
		}
		
		return retval;
	}

	
	/**
	 * Method that is used after a database crash to restore
	 * all cached data to database.
	 * 
	 * @return true if resync was successfull
	 * @ejb.interface-method
	 * @ejb.transaction
	 *   type="NotSupported"
	 */
	public void resync() throws ResyncException{
		
		if(GlobalConfigurationCache.getCurrentState() != GlobalConfiguration.STATE_OUTOFSYNC){
			  String message = "Error it is only possible to resync a database that have the state " + GlobalConfiguration.STATE_OUTOFSYNC;
			  log.error(message);
			  throw new ResyncException(message);
		}
		if(GlobalConfigurationCache.getCachedGlobalConfig()  == null){
		  String message = "Error resyncing database, cached global configuration doesn't exist.";
		  log.error(message);
		  throw new ResyncException(message);
		}
		
		String thisNodeConfig = GlobalConfiguration.SCOPE_NODE+getNodeId()+".";
		// remove all global and node specific properties
		try {
			Collection allProperties = ((GlobalConfigurationDataLocalHome) getLocator().getLocalHome(GlobalConfigurationDataLocalHome.COMP_NAME)).findAll();
			Iterator iter = allProperties.iterator();
			while(iter.hasNext()){
				GlobalConfigurationDataLocal data = (GlobalConfigurationDataLocal) iter.next();
				if(data.getPropertyKey().startsWith(GlobalConfiguration.SCOPE_GLOBAL)){
					data.remove();
				}else{
					if(data.getPropertyKey().startsWith(thisNodeConfig)){
						data.remove();
					}
				}
			}
			
		} catch (FinderException e) {
			  String message = e.getMessage();
			  log.error(message);
			  throw new ResyncException(message);
		} catch (EJBException e) {
			  String message = e.getMessage();
			  log.error(message);
			  throw new ResyncException(message);
		} catch (RemoveException e) {
			  String message = e.getMessage();
			  log.error(message);
			  throw new ResyncException(message);
		}
				

		
			

		// add all properties
		Iterator keySet = GlobalConfigurationCache.getCachedGlobalConfig().keySet().iterator();
		while(keySet.hasNext()){
			String fullKey = (String) keySet.next();

			if(fullKey.startsWith(GlobalConfiguration.SCOPE_GLOBAL)){
				String scope = GlobalConfiguration.SCOPE_GLOBAL;
				String key = fullKey.substring(GlobalConfiguration.SCOPE_GLOBAL.length());
				
				setProperty(scope, key, GlobalConfigurationCache.getCachedGlobalConfig().getProperty(fullKey));
			}else{
				if(fullKey.startsWith(GlobalConfiguration.SCOPE_NODE)){
					String scope = GlobalConfiguration.SCOPE_NODE;
					String key = fullKey.substring(thisNodeConfig.length());
					setProperty(scope, key, GlobalConfigurationCache.getCachedGlobalConfig().getProperty(fullKey));
				}				
			}
		}
		
		// Set the state to insync.
		GlobalConfigurationCache.setCurrentState(GlobalConfiguration.STATE_INSYNC);

		
	}
	
	/**
	 * Method to reload all data from database.
	 * 
	 * @ejb.interface-method

	 */
	public void reload() {
        GlobalConfigurationFileParser.getInstance().reloadConfiguration();
        GlobalConfigurationCache.setCachedGlobalConfig(null);
        getGlobalConfiguration();
		
		// Set the state to insync.
		GlobalConfigurationCache.setCurrentState(GlobalConfiguration.STATE_INSYNC);		
	}
	

	/**
	 * Helper method used to set properties in a table.
	 * @param tempKey
	 * @param value
	 * @throws SQLException 
	 */
	private void setPropertyHelper(String key, String value){
		try{
			try {
				GlobalConfigurationDataLocal globalConfigLocal = globalConfigHome.findByPrimaryKey(key);
				globalConfigLocal.setPropertyValue(value);
				GlobalConfigurationCache.setCachedGlobalConfig(null);
			} catch (FinderException e) {
				try {
					globalConfigHome.create(key, value);
					GlobalConfigurationCache.setCachedGlobalConfig(null);
				} catch (CreateException e1) {
					log.error("Error creating global property " + key,e1);
				}
			}
		}catch(Throwable e){
			String message = "Error connecting to database, configuration is un-syncronized :"; 
			log.error(message, e);
			GlobalConfigurationCache.setCurrentState(GlobalConfiguration.STATE_OUTOFSYNC);
			GlobalConfigurationCache.getCachedGlobalConfig().setProperty(key, value);			
		}
		
	}

	/**
	 * @return Method retreving the Node id from the SIGNSERVER_NODEID environment
	 * valiable
	 * 
	 */
	private String getNodeId(){
		if(nodeId != null){
			nodeId = System.getenv(NODEID_ENVVAR);
			
			if(nodeId == null){
				log.error("Error, required environment variable " + NODEID_ENVVAR + " isn't set.");
			}
		}
		
		return nodeId;
	}
    private static String nodeId = null;

	

	/**
	 * Create method
	 * @ejb.create-method  
	 */
	public void ejbCreate() throws javax.ejb.CreateException {
		globalConfigHome = (GlobalConfigurationDataLocalHome) getLocator().getLocalHome(GlobalConfigurationDataLocalHome.COMP_NAME);
		
	}
	

}
