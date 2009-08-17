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
 
package org.signserver.module.wsra.ca.connectors;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.module.wsra.common.WSRAConstants;
import org.signserver.server.cryptotokens.ICryptoToken;

/**
 * Class in charge of managing all available CA Connectors.
 * 
 * 
 * @author Philip Vendil 20 okt 2008
 *
 * @version $Id$
 */

public class CAConnectionManager {
	
	private Logger log = Logger.getLogger(this.getClass());
	
	private HashMap<String,ICAConnector> cAConnectors = new HashMap<String,ICAConnector>();
	
	public CAConnectionManager(int workerId,Properties props,ICryptoToken ct) throws SignServerException{
		for(int i=0;i<100;i++){
			Properties connectorProps = getConnectorProperties(i,props);
			if(connectorProps != null){
				if(connectorProps.getProperty(WSRAConstants.SETTING_CACONNECTOR_CLASSPATH) != null){
					String classPath = connectorProps.getProperty(WSRAConstants.SETTING_CACONNECTOR_CLASSPATH);
					try {
						Class<?> c = getClass().getClassLoader().loadClass(classPath);
						ICAConnector o = (ICAConnector) c.newInstance();
						o.init(workerId, i, connectorProps, ct);
						List<String> supportedIssuerDNs = o.getSupportedIssuerDN();
						for(String issuerDN : supportedIssuerDNs){
							cAConnectors.put(CertTools.stringToBCDNString(issuerDN), o);
						}
					} catch (ClassNotFoundException e) {						
						log.error("Error CA Connector with id " + i + ", problem when creating " + classPath, e);
						throw new SignServerException("Error CA Connector with id " + i + ", problem when creating " + classPath, e);
					} catch (InstantiationException e) {
						log.error("Error CA Connector with id " + i + ", problem when creating " + classPath, e);
						throw new SignServerException("Error CA Connector with id " + i + ", problem when creating " + classPath, e);
					} catch (IllegalAccessException e) {
						log.error("Error CA Connector with id " + i + ", problem when creating " + classPath, e);
						throw new SignServerException("Error CA Connector with id " + i + ", problem when creating " + classPath, e);
					} 
				}else{
					log.error("Error CA Connector with id " + i + " missconfiguration no " + WSRAConstants.SETTING_CACONNECTOR_CLASSPATH + " configured.");
					throw new SignServerException("Error CA Connector with id " + i + " missconfiguration no " + WSRAConstants.SETTING_CACONNECTOR_CLASSPATH + " configured.");
				}
			}
		}
	}
	
	public ICAConnector getCAConnector(String issuerDN) throws IllegalRequestException{
		String searchIssuer = CertTools.stringToBCDNString(issuerDN);
		if(cAConnectors.get(searchIssuer)== null){
             throw new IllegalRequestException("Error unsupported issuer : " + issuerDN );
		}
		
		return cAConnectors.get(searchIssuer);
	}

	/**
	 * Method returning a CA connector properties from a worker properties.
	 * 
	 * It will work in the following manner:
	 * <ul>
	 * <li>All properties starting with 'CACONNECTOR"<connectorId>.'  will have
	 *   the following keys added without the 'CACONNECTOR...' prefix.
	 * <li>All properties without 'CACONNECTOR...' prefix will be added if the key doesn't exist already. I.e
	 * all properties with keys starting 'CACONNECTOR..' overrides general properties.
	 * <li>If no 'CACONNECTOR<connectorId>.' exists for the given id then, null will be returned.
	 * </ul>
	 * @param config a worker config containing all properties
	 * @return a Propertes according to above specification or 'null' if no property with 'CACONNECTOR...' exists
	 * in configuration.
	 */
	static Properties getConnectorProperties(int connectorId, Properties workerProperties){
		Properties retval = new Properties();
		
		boolean foundConnectorId = false;
		// find issuer properties
		Enumeration<?> en = workerProperties.propertyNames();
		while(en.hasMoreElements()){
			String next = (String) en.nextElement();
			String strippedKey = connectorPrefix(connectorId,next);
			if(strippedKey != null){
				foundConnectorId = true;
				retval.setProperty(strippedKey, workerProperties.getProperty(next));
			}
		}
		if(foundConnectorId){
			// Separate general properties from issuer specific and add if they already doesn't exist.
			en = workerProperties.propertyNames();
			while(en.hasMoreElements()){
				String next = (String) en.nextElement();
				if(connectorPrefix(0, next) == null){
					if(retval.getProperty(next) == null){
						retval.setProperty(next, workerProperties.getProperty(next));
					}
				}
			}
		}else{
			retval = null;
		}

		return retval;
	}
	
	/**
	 * Returns the value after the CACONNECTOR prefix
	 * @param next input property key
	 * @return the subset of the property key with connector prefix removed, or null if no
	 * connector prefix could be found.
	 */
	private static String connectorPrefix(int connectorId, String key ) {
		String retval = null;
		
		if(key.length() > WSRAConstants.SETTING_CACONNECTOR_PREFIX.length() +2){
			String tmp = key.substring(0, WSRAConstants.SETTING_CACONNECTOR_PREFIX.length());
			if(tmp.equalsIgnoreCase(WSRAConstants.SETTING_CACONNECTOR_PREFIX)){
				if(key.substring(WSRAConstants.SETTING_CACONNECTOR_PREFIX.length()).substring(0, 1).matches("\\d")){
					try{
					  int id = Integer.parseInt(key.substring(WSRAConstants.SETTING_CACONNECTOR_PREFIX.length(),key.indexOf('.')));
					  if(id == connectorId || connectorId == 0){
					    retval = key.substring(key.indexOf('.')+1);
					  }
					}catch(NumberFormatException e){}
				}
			}
		}

		return retval;
	}
}
