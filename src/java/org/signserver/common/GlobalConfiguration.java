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


package org.signserver.common;

import java.io.Serializable;
import java.util.Iterator;
import java.util.Map;


/**
 * Value object containing the global configuration, both global and
 * node scoped.
 * 
 * Contains a merge of static and dynamically defined global properties
 * 
 * @author Philip Vendil
 * $Id: GlobalConfiguration.java,v 1.1 2007-02-27 16:18:10 herrvendil Exp $
 */
public class GlobalConfiguration implements Serializable{
   
  private static final long serialVersionUID = 1L;
  
  private Map config;  
  private String state;
    
  public static final String SCOPE_GLOBAL = "GLOB.";
  public static final String SCOPE_NODE = "NODE.";
 
  public static final String STATE_INSYNC = "INSYNC"; 
  public static final String STATE_OUTOFSYNC = "OUTOFSYNC";
  
  public static final int WORKERTYPE_ALL = 1; 
  public static final int WORKERTYPE_SIGNERS = 2;
  public static final int WORKERTYPE_SERVICES = 3;
  
  public static final String WORKERPROPERTY_BASE = "WORKER";
  public static final String WORKERPROPERTY_CLASSPATH = ".CLASSPATH";
  
  private static final String SIGNTOKENPROPERTY_BASE = ".SIGNERTOKEN";
  public static final String SIGNTOKENPROPERTY_CLASSPATH = ".CLASSPATH"; 
  
	// Current version of the application.    
  public static final String VERSION = "@signserver.version@";

  
  /**
   * Constructor that should only be called within
   * the GlobalConfigurationSessionBean.
   */
  public GlobalConfiguration(Map config, String state){
	  this.config = config;
	  this.state = state;
  }
  
  /**
   * Returns the currently set global property
   * @param scope one of the SCOPE_ constants
   * @param property the actual property (with no glob. or node. prefixes)
   * @return the currently set global property or null if it doesn't exist.
   */
  public String getProperty(String scope, String property) {
	return (String) config.get(scope + property);
  }
  
  /**
   * Returns the currently set global property with a scoped property
   * 
   * Use this method only if you know what you are doing.
   * 
   * @param property the actual property (with  GLOB. or NODE. prefixes)
   * @return the currently set global property or null if it doesn't exist.
   */
  public String getProperty(String propertyWithScope) {
	return (String) config.get(propertyWithScope);
  }
 
  /**
   * @return Returns an iterator to all configured properties
   */
  public Iterator getKeyIterator(){	  
	  return config.keySet().iterator();
  }
 
  /**
   * @return Returns the current state of the global configuration
   * one of the STATE_ constants.
   */
  public String getState() {
	return state;
  }
  
  /**
   * Returns the classpath of the worker with id
   * 
   * Is backward compatible with the version 1 global configuration syntax
   * @param workerId
   * @return the defined classpath or null of it couldn't be found.
   */
  public String getWorkerClassPath(int workerId){ 
	return getProperty(SCOPE_GLOBAL, WORKERPROPERTY_BASE + workerId + WORKERPROPERTY_CLASSPATH);
  }
  
  /**
   * Returns the property specific to a signertoken,
   * This should only be used with signers and not with
   * signtokens.
   * 
   * @param signerId
   * @param signertokenproperty
   * @return
   */
  public String getSignTokenProperty(int signerId, String signertokenproperty){    	
  	String key = WORKERPROPERTY_BASE + signerId + SIGNTOKENPROPERTY_BASE + signertokenproperty;  	
  	return getProperty(SCOPE_GLOBAL, key);
  }
  
  /**
   * Returns the version of the server
   */
  public String getAppVersion(){
	  return VERSION;
  }
	
	
}
