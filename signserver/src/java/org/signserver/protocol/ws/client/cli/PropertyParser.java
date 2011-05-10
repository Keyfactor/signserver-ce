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

package org.signserver.protocol.ws.client.cli;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import org.signserver.cli.IllegalAdminCommandException;
import org.signserver.protocol.ws.client.ISignServerWSClient;

/**
 * Help class reading configuration properties from
 * the properties file used by the Web Service client.
 * 
 * 
 * @author Philip Vendil 17 dec 2007
 *
 * @version $Id$
 */

public class PropertyParser {

	private Properties props;
	
	private static final String PROPERTYFILE_PATH = "./wsclient.properties";
	
	PropertyParser() throws IllegalAdminCommandException{
		props = new Properties();
		try {
			props.load(new FileInputStream(PROPERTYFILE_PATH));
		} catch (FileNotFoundException e) {
			throw new IllegalAdminCommandException("The property file " + PROPERTYFILE_PATH + " couldn't be found.");
		} catch (IOException e) {
			throw new IllegalAdminCommandException("Problem reading " + PROPERTYFILE_PATH + " : " + e.getMessage());
		}
	}
	
	Properties getProperites(){
		return props;
	}
	
	/**
	 * See property file for explanations
	 * 
	 * @throws ParseException if the property file is missconfigured.
	 */
	String[] getHosts() throws ParseException{
		if(props.getProperty("wsclient.hosts") != null){
			String[] retval = props.getProperty("wsclient.hosts").split(";");
			if(retval[0].trim().equals("")){
				throw new ParseException("Bad configuration of property file, property 'wsclient.hosts' must contain one or more hostnames of signserver nodes to connect to");
			}
			return retval;
		}else{
			throw new ParseException("Bad configuration of property file, property 'wsclient.hosts' must contain one or more hostnames of signserver nodes to connect to");
		}
	}
	
	/**
	 * See property file for explanations
	 * 
	 * @throws ParseException if the property file is missconfigured.
	 */
	int getPort() throws ParseException{
		if(props.getProperty("wsclient.port") != null){
			try{
				int retval = Integer.parseInt(props.getProperty("wsclient.port").trim());
				return retval;
			}catch(NumberFormatException e){
				throw new ParseException("Bad configuration of property file, property 'wsclient.port' must be a integer.");				
			}			 
		}else{
			throw new ParseException("Bad configuration of property file, property 'wsclient.port' must be a integer.");
		}
	}
	
	/**
	 * See property file for explanations
	 * 
	 * @throws ParseException if the property file is missconfigured.
	 */
	boolean useHTTPS() throws ParseException{
		String value = props.getProperty("wsclient.usehttps","false");
		if(value.trim().equalsIgnoreCase("false")){
		  return false;	
		}
		if(value.trim().equalsIgnoreCase("true")){
			return true;	
		}		
		throw new ParseException("Bad configuration of property file, property 'wsclient.usehttps' should either be 'true' or 'false'.");
	}
	
	String getURIPath() throws ParseException{
		if(props.getProperty("wsclient.uripath") != null){
			return 	props.getProperty("wsclient.uripath").trim();	 
		}else{
			throw new ParseException("Bad configuration of property file, property 'wsclient.uripath' must exist and point to the WDSL location.");
		}
	}
	
	/**
	 * See property file for explanations
	 * 
	 * @throws ParseException if the property file is missconfigured.
	 */
	int getTimeout() throws ParseException{
		if(props.getProperty("wsclient.timeout") != null){
			try{
				int retval = Integer.parseInt(props.getProperty("wsclient.timeout").trim());
				return retval;
			}catch(NumberFormatException e){
				throw new ParseException("Bad configuration of property file, property 'wsclient.timeout' must be a integer.");				
			}			 
		}else{
			throw new ParseException("Bad configuration of property file, property 'wsclient.timeout' must be a integer.");
		}
	}
	
	/**
	 * See property file for explanations
	 * 
	 * @throws ParseException if the property file is missconfigured.
	 */
	String getLoadBalancePolicy() throws ParseException{
		String errorMessage = "Bad configuration of property file, property 'wsclient.loadbalancepolicy' must exist and be a classpath of a ISignServerWSClient implementation.";
		if(props.getProperty("wsclient.loadbalancepolicy") != null){
			String retval = props.getProperty("wsclient.loadbalancepolicy").trim(); 
			try{
				Class<?> c = this.getClass().getClassLoader().loadClass(retval);
				Object o = c.newInstance();
				if(!(o instanceof ISignServerWSClient)){
					throw new ParseException(errorMessage);
				}
				return 	retval;
			}catch(Exception e){
				throw new ParseException(errorMessage);
			}
		}else{
			throw new ParseException(errorMessage);
		}
	}
	
	/**
	 * See property file for explanations
	 * 
	 * @throws ParseException if the property file is missconfigured.
	 */
	IWSRequestGenerator getWSRequestGenerator() throws ParseException{
		String errorMessage = "Bad configuration of property file, property 'wsclient.wsrequestgenerator' must exist and be a classpath of a IWSRequestGenerator implementation.";
		if(props.getProperty("wsclient.wsrequestgenerator") != null){
			String classPath = props.getProperty("wsclient.wsrequestgenerator").trim(); 
			try{
				Class<?> c = this.getClass().getClassLoader().loadClass(classPath);
				Object o = c.newInstance();
				if(!(o instanceof IWSRequestGenerator)){
					throw new ParseException(errorMessage);
				}
				return 	(IWSRequestGenerator) o;
			}catch(Exception e){
				throw new ParseException(errorMessage);
			}	 
		}else{
			throw new ParseException(errorMessage);
		}
	}
	
	/**
	 * See property file for explanations
	 * 
	 * @throws ParseException if the property file is missconfigured.
	 */
	String getLogFilePath() throws ParseException{
		if(props.getProperty("wsclient.log.filepath") != null){
			return 	props.getProperty("wsclient.log.filepath").trim();	 
		}else{
			throw new ParseException("Bad configuration of property file, property 'wsclient.log.filepath' must exist and point to the location the log file will be written to.");
		}
	}
	
	/**
	 * See property file for explanations
	 * 
	 * @throws ParseException if the property file is missconfigured.
	 */
	String getKeyStorePath() throws ParseException{
		if(props.getProperty("wsclient.keystore.path") != null){
			String path = props.getProperty("wsclient.keystore.path").trim();
			File f = new File(path);
			if(!f.exists()){
				throw new ParseException("Bad configuration of property file, property 'wsclient.keystore.path' points to a non-existing file.");	
			}
			return path;
		}else{
			return null;
		}
	}
	
	/**
	 * See property file for explanations
	 * 
	 * @throws ParseException if the property file is missconfigured.
	 */
	String getKeyStorePassword() throws ParseException{
		if(props.getProperty("wsclient.keystore.password") != null){
			String password = props.getProperty("wsclient.keystore.password").trim();			
			return password;
		}else{
			throw new ParseException("Bad configuration of property file, property 'wsclient.keystore.password' must exist.");
		}
	}
	
	
}
