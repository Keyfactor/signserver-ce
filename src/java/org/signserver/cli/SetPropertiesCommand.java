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


package org.signserver.cli;

import java.io.FileInputStream;
import java.rmi.RemoteException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Properties;

import org.signserver.common.GlobalConfiguration;

 

/**
 * Sets properties from a given property file.
 * 
 * See the manual for the syntax of the property file
 *
 * @version $Id: SetPropertiesCommand.java,v 1.4 2007-11-09 15:45:13 herrvendil Exp $
 */
public class SetPropertiesCommand extends BaseCommand {
	
	private static final String GLOBAL_PREFIX = "GLOB.";
	private static final String NODE_PREFIX = "NODE.";
	private static final String WORKER_PREFIX = "WORKER";
	private static final String OLDWORKER_PREFIX = "SIGNER";
	private static final String REMOVE_PREFIX = "-";
	private static final String GENID = "GENID";
	
    /**
     * Creates a new instance of SetPropertyCommand
     *
     * @param args command line arguments
     */
    public SetPropertiesCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length != 2) {
	       throw new IllegalAdminCommandException("Usage: signserver setproperties <-host hostname (optional)>  <propertyfile>\n" + 
	       		                                  "Example 1: signserver setproperties mysettings.properties\n" +
	    		                                  "Example 2: signserver setproperties -host node3.someorg.com mysettings.properties\n\n");	       
	    }	
        try {            
         
        	
        	Properties properties = loadProperties(args[1]);
        
        	getOutputStream().println("Configuring properties as defined in the file : " + args[1]);
        	Enumeration<?> iter = properties.keys();
        	while(iter.hasMoreElements()){
        		String key = (String) iter.nextElement();
        		processKey(hostname, key.toUpperCase(), properties.getProperty(key));
        	}

        	this.getOutputStream().println("\n\n");

        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }



	private void processKey(String hostname, String key, String value) throws RemoteException, Exception {
		if(isRemoveKey(key)){
			String newkey = key.substring(REMOVE_PREFIX.length());
			processKey(hostname, key, newkey,value,false);
		}else{
			processKey(hostname, key, key,value,true);
		}
		
	}

	private boolean isRemoveKey(String key) {
		return key.startsWith(REMOVE_PREFIX);
	}

	private void processKey(String hostname, String originalKey,String key, String value, boolean add) throws RemoteException, Exception {
		if(key.startsWith(GLOBAL_PREFIX)){
			String strippedKey = key.substring(GLOBAL_PREFIX.length());
			processGlobalProperty(hostname, GlobalConfiguration.SCOPE_GLOBAL,strippedKey,value,add);
		}else{
			if(key.startsWith(NODE_PREFIX)){
				String strippedKey = key.substring(NODE_PREFIX.length());
				processGlobalProperty(hostname, GlobalConfiguration.SCOPE_NODE,strippedKey,value,add);
			}else{
				if(key.startsWith(WORKER_PREFIX)){
					String strippedKey = key.substring(WORKER_PREFIX.length());
					processWorkerProperty(hostname, originalKey, strippedKey,value,add);
				}else{
					if(key.startsWith(OLDWORKER_PREFIX)){
						String strippedKey = key.substring(OLDWORKER_PREFIX.length());
						processWorkerProperty(hostname, originalKey, strippedKey,value,add);
					}else{
						getOutputStream().println("Error in propertyfile syntax, check : " + originalKey);
					}
				}
			}
		}
		
	}



	private void processWorkerProperty(String hostname, String originalKey, String strippedKey, String value, boolean add) throws RemoteException, Exception {
		String splittedKey = strippedKey.substring(0,strippedKey.indexOf('.'));
		String propertykey = strippedKey.substring(strippedKey.indexOf('.')+1);
		int workerid = 0;
    	if(splittedKey.substring(0, 1).matches("\\d")){
    		workerid = Integer.parseInt(splittedKey);
    		            		
    	}else{
    	  if(splittedKey.startsWith(GENID)){
    		workerid = getGenId( hostname, splittedKey);
    	  }else{
    		  workerid = getCommonAdminInterface(hostname).getWorkerId(splittedKey);
    	  }
    	}
    	
    	if(workerid == 0){
    		getOutputStream().println("Error in propertyfile syntax, couldn't find worker for key : " + originalKey );
    	}else{
    		if(add){
    			setWorkerProperty(workerid,  hostname, propertykey,value);
    		}else{
    			removeWorkerProperty(workerid,  hostname, propertykey);
    		}
    	}
		
	}

	private HashMap<String, Integer> genIds = new HashMap<String, Integer>();
	private int getGenId(String hostname, String splittedKey) throws RemoteException, Exception {
		if(genIds.get(splittedKey) == null){
			int genid = getCommonAdminInterface(hostname).genFreeWorkerId();
			genIds.put(splittedKey, new Integer(genid));
		}
		return ((Integer) genIds.get(splittedKey)).intValue();
	}

	private void processGlobalProperty(String hostname, String scope, String strippedKey, String value, boolean add) throws RemoteException, Exception {
		String key = strippedKey;
		if(strippedKey.startsWith(WORKER_PREFIX+GENID) ||
		   strippedKey.startsWith(OLDWORKER_PREFIX+GENID)){
			if(strippedKey.startsWith(WORKER_PREFIX)){
				strippedKey = strippedKey.substring(WORKER_PREFIX.length());
			}
			if(strippedKey.startsWith(OLDWORKER_PREFIX)){
				strippedKey = strippedKey.substring(OLDWORKER_PREFIX.length());
			}
			String splittedKey = strippedKey.substring(0,strippedKey.indexOf('.'));
			String propertykey = strippedKey.substring(strippedKey.indexOf('.')+1);
			
			key = WORKER_PREFIX + getGenId(hostname, splittedKey) + "." + propertykey;
			
		}else{
			if(strippedKey.startsWith(WORKER_PREFIX) || strippedKey.startsWith(OLDWORKER_PREFIX)){
				String strippedKey2 = null;
				if(strippedKey.startsWith(WORKER_PREFIX)){
					strippedKey2 = strippedKey.substring(WORKER_PREFIX.length());
				}else{
					strippedKey2 = strippedKey.substring(OLDWORKER_PREFIX.length());
				}
				
				String splittedKey = strippedKey2.substring(0,strippedKey2.indexOf('.'));
				String propertykey = strippedKey2.substring(strippedKey2.indexOf('.')+1);
				int workerid = 0;
		    	if(splittedKey.substring(0, 1).matches("\\d")){
		    		workerid = Integer.parseInt(splittedKey);		    		            		
		    	}else{
		    		workerid = getCommonAdminInterface(hostname).getWorkerId(splittedKey);		    	  
		    	}				
				key = WORKER_PREFIX + workerid + "." + propertykey;
			}
		}
		
		
		if(add){
			setGlobalProperty(scope, hostname, key, value);
		}else{
			removeGlobalProperty(scope, hostname, key);
		}
		
	}


	private Properties loadProperties(String path) {
		Properties retval = new Properties();
		try {
			retval.load(new FileInputStream(path));
		} catch (Exception e) {
			getOutputStream().println("Error reading property file : " + path);
			System.exit(-1);
		}
		
		return retval;
	}

	private void setGlobalProperty(String scope, String hostname, String key, String value) throws RemoteException, Exception {
    	this.getOutputStream().println("Setting the global property " + key + " to " + value +" with scope " + scope );    	    
    	getCommonAdminInterface(hostname).setGlobalProperty(scope, key, value);
		
	}
	
	private void removeGlobalProperty(String scope, String hostname, String key) throws RemoteException, Exception {
    	this.getOutputStream().println("Removing the global property " + key + " with scope " + scope );    	    
    	getCommonAdminInterface(hostname).removeGlobalProperty(scope, key);		
	}

	// execute
    
	public int getCommandType() {
		return TYPE_EXECUTEONMASTER;
	}
	
	private void setWorkerProperty(int workerId, String hostname, String propertykey, String propertyvalue) throws RemoteException, Exception{
    	this.getOutputStream().println("Setting the property " + propertykey + " to " + propertyvalue +" for worker " + workerId );    	
    	getCommonAdminInterface(hostname).setWorkerProperty(workerId,propertykey,propertyvalue);
	}
	private void removeWorkerProperty(int workerId, String hostname, String propertykey) throws RemoteException, Exception{
    	this.getOutputStream().println("Removing the property " + propertykey + "  for worker " + workerId);    	
    	getCommonAdminInterface(hostname).removeWorkerProperty(workerId,propertykey);
	}
}
