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
import java.util.Enumeration;
import java.util.Properties;

import org.apache.log4j.Logger;


/**
 * Value object containing the global configuration, both global and
 * node scoped.
 * 
 * Contains a merge of static and dynamically defined global properties
 * 
 * @author Philip Vendil
 * $Id$
 */
public class GlobalConfiguration implements Serializable{
	
  private static transient Logger log = Logger.getLogger(GlobalConfiguration.class);
  
  private static final transient String BUILDMODE = "@BUILDMODE@";
   
  private static final long serialVersionUID = 1L;
  
  private Properties config;  
  private String state;
    
  public static final String SCOPE_GLOBAL = "GLOB.";
  public static final String SCOPE_NODE = "NODE.";
 
  public static final String STATE_INSYNC = "INSYNC"; 
  public static final String STATE_OUTOFSYNC = "OUTOFSYNC";
  
  public static final int WORKERTYPE_ALL = 1; 
  public static final int WORKERTYPE_PROCESSABLE = 2;
  public static final int WORKERTYPE_SERVICES = 3;
  public static final int WORKERTYPE_MAILSIGNERS = 4;
  
  public static final String WORKERPROPERTY_BASE = "WORKER";
  public static final String WORKERPROPERTY_CLASSPATH = ".CLASSPATH";
  
  public static final String CRYPTOTOKENPROPERTY_BASE = ".CRYPTOTOKEN";
  public static final String OLD_CRYPTOTOKENPROPERTY_BASE = ".SIGNERTOKEN";
  public static final String CRYPTOTOKENPROPERTY_CLASSPATH = ".CLASSPATH"; 
  
	// Current version of the application.    
  public static final String VERSION = "@signserver.version@";
	// Indicates if ClusterClassLoading should be enabled    
  public static final String CLUSTERCLASSLOADERENABLED = "@signserver.useclusterclassloader@";

  private static Boolean clusterClassLoaderEnabled = null;
  public static boolean isClusterClassLoaderEnabled(){
	  if(clusterClassLoaderEnabled == null){
		  if(CLUSTERCLASSLOADERENABLED.startsWith("@signserver.useclusterclassloader")){
			  clusterClassLoaderEnabled=true;
		  }else{
			  clusterClassLoaderEnabled= Boolean.parseBoolean(CLUSTERCLASSLOADERENABLED.trim());
		  }
	  }
	  return clusterClassLoaderEnabled;
  }
  
	// Indicates if ClusterClassLoading should support class versions    
  public static final String USECLASSVERSIONS = "@signserver.useclassversions@";

  private static Boolean useClassVersions = null;
  public static boolean isUseClassVersions(){
	  if(useClassVersions == null){
		  if(USECLASSVERSIONS.startsWith("@signserver.useclassversions")){
			  useClassVersions=true;
		  }else{
			  useClassVersions= Boolean.parseBoolean(USECLASSVERSIONS.trim());
		  }
	  }
	  return useClassVersions;
  }

  
	// Indicates if ClusterClassLoading should require signing   
  public static final String REQUIRESIGNING = "@signserver.requiresignature@";

  private static Boolean requireSigning = null;
  public static boolean isRequireSigning(){
	  if(requireSigning == null){
		  if(REQUIRESIGNING.startsWith("@signserver.requiresignature")){
			  requireSigning=false;
		  }else{
			  requireSigning= Boolean.parseBoolean(REQUIRESIGNING.trim());
		  }
	  }
	  return requireSigning;
  }


  // Indicates if ClusterClassLoading the full path to the jks trust store 
  public static final String PATHTOTRUSTSTORE = "@signserver.pathtotruststore@";

  private static String pathToTrustStore = null;
  public static String getPathToTrustStore(){
	  if(pathToTrustStore == null){
		  if(!PATHTOTRUSTSTORE.startsWith("@signserver.pathtotruststore")){
			  pathToTrustStore= PATHTOTRUSTSTORE;
		  }
	  }
	  return pathToTrustStore;
  }

//The password to unlock the truststore password
  
  // Indicates if ClusterClassLoading the full path to the jks trust store 
  public static final String CCLTRUSTSTOREPWD = "@signserver.truststorepwd@";

  private static char[] cclTrustStorePWD = null;
  public static char[] getCCLTrustStorePasswd() {
	  if(cclTrustStorePWD == null){
		  if(CCLTRUSTSTOREPWD.startsWith("@signserver.truststorepwd") || CCLTRUSTSTOREPWD.trim().equals("")){
			  log.error("Error cluster classloader truststore password isn't configured");
		  }else{
			  cclTrustStorePWD= CCLTRUSTSTOREPWD.toCharArray();			  
		  }
	  }
	  return cclTrustStorePWD;
  }
  
  
  /**
   * Constructor that should only be called within
   * the GlobalConfigurationSessionBean.
   */
  public GlobalConfiguration(Properties config, String state){
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
	return (String) config.getProperty((scope + property).toUpperCase());
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
	return (String) config.getProperty(propertyWithScope);
  }
 
  /**
   * @return Returns an iterator to all configured properties
   */
  @SuppressWarnings("unchecked")
public Enumeration<String> getKeyEnumeration(){	  
	  return (Enumeration<String>) config.propertyNames();
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
   * Returns the property specific to a cryptotoken,
   * This should only be used with signers and not with
   * cryptotokens.
   * 
   * @param workerId
   * @param cryptotokenproperty
   * @return return the given cryptotoken property or null.
   */
  public String getCryptoTokenProperty(int workerId, String cryptotokenproperty){    	
  	String key = WORKERPROPERTY_BASE + workerId + CRYPTOTOKENPROPERTY_BASE + cryptotokenproperty;
  	if(getProperty(SCOPE_GLOBAL, key) == null){
  		key = WORKERPROPERTY_BASE + workerId + OLD_CRYPTOTOKENPROPERTY_BASE + cryptotokenproperty;
  	}
  	return getProperty(SCOPE_GLOBAL, key);
  }
  
  /**
   * Returns the version of the server
   */
  public String getAppVersion(){
	  return VERSION;
  }


  private static transient String buildMode = null;
  public static String getBuildMode(){
	  if(buildMode== null){
		  if(BUILDMODE.startsWith("@BUILDMODE")){
			  buildMode = "SIGNSERVER";
		  }else{
			  buildMode = BUILDMODE;
		  }
	  }
	  return buildMode;
  }

	
	
}
