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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.signserver.common.AuthorizedClient;
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
	
	public static final String SIGNERCERTIFICATE = ".SIGNERCERTIFICATE";
	public static final String SIGNERCERTCHAIN = ".SIGNERCERTCHAIN";
	public static final String AUTHCLIENT = ".AUTHCLIENT";


	public static final String GLOBAL_PREFIX = "GLOB.";
	public static final String NODE_PREFIX = "NODE.";
	public static final String WORKER_PREFIX = "WORKER";
	public static final String OLDWORKER_PREFIX = "SIGNER";
	public static final String REMOVE_PREFIX = "-";
	public static final String GENID = "GENID";
	private HashMap<String, Integer> genIds = new HashMap<String, Integer>();
	private PrintStream out;
	private CommonAdminInterface commonAdminInterface;
	private List<Integer> workerDeclarations = new ArrayList<Integer>();
	
	public SetPropertiesHelper(PrintStream out, CommonAdminInterface commonAdminInterface){
		this.out=out;
		this.commonAdminInterface=commonAdminInterface;
	}
	
	public void process(Properties properties) throws RemoteException, Exception {
    	Enumeration<?> iter = properties.keys();
    	while(iter.hasMoreElements()){
    		String key = (String) iter.nextElement();
    		processKey(key.toUpperCase(), properties.getProperty(key));
    	}    	
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
				removeWorkerProperty(workerid, propertykey, value);
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
			
	    	if(propertykey.equalsIgnoreCase(GlobalConfiguration.WORKERPROPERTY_CLASSPATH.substring(1))){
                workerDeclarations.add(getGenId(splittedKey));		    		
		    }
			
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
		    	
		    	if(propertykey.equalsIgnoreCase(GlobalConfiguration.WORKERPROPERTY_CLASSPATH.substring(1))){
                   workerDeclarations.add(workerid);		    		
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
		if(propertykey.startsWith(AUTHCLIENT.substring(1))){
			String values[] = propertyvalue.split(";");
			AuthorizedClient ac = new AuthorizedClient(values[0],values[1]);
			out.println("Adding Authorized Client with certificate serial " + ac.getCertSN() + " and issuer DN " + ac.getIssuerDN() + " to " + propertyvalue +" for worker " + workerId );
			commonAdminInterface.addAuthorizedClient(workerId, ac);
		}else{
			if(propertykey.startsWith(SIGNERCERTIFICATE.substring(1))){
               commonAdminInterface.uploadSignerCertificate(workerId,(X509Certificate)CertTools.getCertfromByteArray(Base64.decode(propertyvalue.getBytes())),GlobalConfiguration.SCOPE_GLOBAL);
			}else{
				if(propertykey.startsWith(SIGNERCERTCHAIN.substring(1))){
					String certs[] = propertyvalue.split(";");
					ArrayList<Certificate> chain = new ArrayList<Certificate>();
					for(String base64cert : certs){
						X509Certificate cert = (X509Certificate)CertTools.getCertfromByteArray(Base64.decode(base64cert.getBytes()));
						chain.add(cert);
					}
					commonAdminInterface.uploadSignerCertificateChain(workerId, chain, GlobalConfiguration.SCOPE_GLOBAL);
				}else{
					out.println("Setting the property " + propertykey + " to " + propertyvalue +" for worker " + workerId );    	
					commonAdminInterface.setWorkerProperty(workerId,propertykey,propertyvalue);
				}
			}
		}
	}
	private void removeWorkerProperty(int workerId, String propertykey,String propertyvalue) throws RemoteException, Exception{
		if(propertykey.startsWith(AUTHCLIENT.substring(1))){
			String values[] = propertyvalue.split(";");
			AuthorizedClient ac = new AuthorizedClient(values[0],values[1]);
			out.println("Removing authorized client with certificate serial " + ac.getCertSN() + " and issuer DN " + ac.getIssuerDN() + " from " + propertyvalue +" for worker " + workerId );
			commonAdminInterface.removeAuthorizedClient(workerId, ac);
		}else{
			if(propertykey.startsWith(SIGNERCERTIFICATE.substring(1))){
				out.println("Removal of signing certificates isn't supported, skipped.");
			}else{
				if(propertykey.startsWith(SIGNERCERTCHAIN.substring(1))){
					out.println("Removal of signing certificate chains isn't supported, skipped.");
				}else{
					out.println("Removing the property " + propertykey + "  for worker " + workerId);    	
					commonAdminInterface.removeWorkerProperty(workerId,propertykey);
				}
			}
		}
	}

	/**
	 * Method that returns a list of all worker declarations that
	 * have been sent through this set property helper until now.
	 * 
	 * @return workerId a list of worker id's.
	 */
	public List<Integer> getKeyWorkerDeclarations() {
		return workerDeclarations;
	}
	

	
}
