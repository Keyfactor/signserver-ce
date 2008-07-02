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

import java.io.PrintStream;
import java.rmi.RemoteException;
import java.util.HashMap;

import org.signserver.common.GlobalConfiguration;

/**
 * Helper class containing methods to parse a set properties file 
 * used from different locations.
 * 
 * 
 * @author Philip Vendil 19 maj 2008
 *
 * 
 */

public class SetPropertiesHelper {

	private static final String GLOBAL_PREFIX = "GLOB.";
	private static final String NODE_PREFIX = "NODE.";
	private static final String WORKER_PREFIX = "WORKER";
	private static final String OLDWORKER_PREFIX = "SIGNER";
	private static final String REMOVE_PREFIX = "-";
	private static final String GENID = "GENID";
	private HashMap<String, Integer> genIds = new HashMap<String, Integer>();
	private PrintStream out;
	private CommonAdminInterface commonAdminInterface;
	
	public SetPropertiesHelper(PrintStream out, CommonAdminInterface commonAdminInterface){
		this.out=out;
		this.commonAdminInterface=commonAdminInterface;
	}

	public void processKey(String key, String value) throws RemoteException, Exception {
		if(isRemoveKey(key)){
			String newkey = key.substring(REMOVE_PREFIX.length());
			processKey(key, newkey,value,false);
		}else{
			processKey(key, key,value,true);
		}
		
	}

	private boolean isRemoveKey(String key) {
		return key.startsWith(REMOVE_PREFIX);
	}

	private void processKey(String originalKey,String key, String value, boolean add) throws RemoteException, Exception {
		if(key.startsWith(GLOBAL_PREFIX)){
			String strippedKey = key.substring(GLOBAL_PREFIX.length());
			processGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,strippedKey,value,add);
		}else{
			if(key.startsWith(NODE_PREFIX)){
				String strippedKey = key.substring(NODE_PREFIX.length());
				processGlobalProperty(GlobalConfiguration.SCOPE_NODE,strippedKey,value,add);
			}else{
				if(key.startsWith(WORKER_PREFIX)){
					String strippedKey = key.substring(WORKER_PREFIX.length());
					processWorkerProperty(originalKey, strippedKey,value,add);
				}else{
					if(key.startsWith(OLDWORKER_PREFIX)){
						String strippedKey = key.substring(OLDWORKER_PREFIX.length());
						processWorkerProperty(originalKey, strippedKey,value,add);
					}else{
						out.println("Error in propertyfile syntax, check : " + originalKey);
					}
				}
			}
		}
		
	}



	private void processWorkerProperty(String originalKey, String strippedKey, String value, boolean add) throws RemoteException, Exception {
		String splittedKey = strippedKey.substring(0,strippedKey.indexOf('.'));
		String propertykey = strippedKey.substring(strippedKey.indexOf('.')+1);
		int workerid = 0;
    	if(splittedKey.substring(0, 1).matches("\\d")){
    		workerid = Integer.parseInt(splittedKey);
    		            		
    	}else{
    	  if(splittedKey.startsWith(GENID)){
    		workerid = getGenId(splittedKey);
    	  }else{
    		  workerid = commonAdminInterface.getWorkerId(splittedKey);
    	  }
    	}
    	
    	if(workerid == 0){
    		out.println("Error in propertyfile syntax, couldn't find worker for key : " + originalKey );
    	}else{
    		if(add){
    			setWorkerProperty(workerid, propertykey,value);
    		}else{
    			removeWorkerProperty(workerid, propertykey);
    		}
    	}
		
	}
	
	private int getGenId(String splittedKey) throws RemoteException, Exception {
		if(genIds.get(splittedKey) == null){
			int genid = commonAdminInterface.genFreeWorkerId();
			genIds.put(splittedKey, new Integer(genid));
		}
		return ((Integer) genIds.get(splittedKey)).intValue();
	}

	private void processGlobalProperty(String scope, String strippedKey, String value, boolean add) throws RemoteException, Exception {
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
			
			key = WORKER_PREFIX + getGenId(splittedKey) + "." + propertykey;
			
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
		    		workerid = commonAdminInterface.getWorkerId(splittedKey);		    	  
		    	}				
				key = WORKER_PREFIX + workerid + "." + propertykey;
			}
		}
		
		
		if(add){
			setGlobalProperty(scope, key, value);
		}else{
			removeGlobalProperty(scope, key);
		}
		
	}

	private void setGlobalProperty(String scope, String key, String value) throws RemoteException, Exception {
		out.println("Setting the global property " + key + " to " + value +" with scope " + scope );    	    
		commonAdminInterface.setGlobalProperty(scope, key, value);
		
	}
	
	private void removeGlobalProperty(String scope, String key) throws RemoteException, Exception {
		out.println("Removing the global property " + key + " with scope " + scope );    	    
		commonAdminInterface.removeGlobalProperty(scope, key);		
	}
	
	private void setWorkerProperty(int workerId,  String propertykey, String propertyvalue) throws RemoteException, Exception{
		out.println("Setting the property " + propertykey + " to " + propertyvalue +" for worker " + workerId );    	
		commonAdminInterface.setWorkerProperty(workerId,propertykey,propertyvalue);
	}
	private void removeWorkerProperty(int workerId, String propertykey) throws RemoteException, Exception{
		out.println("Removing the property " + propertykey + "  for worker " + workerId);    	
		commonAdminInterface.removeWorkerProperty(workerId,propertykey);
	}
}
