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
package org.signserver.validationservice.server;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Properties;

import javax.persistence.EntityManager;

import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.validationservice.common.ValidationServiceConstants;

/**
 * Class containing helper methods for the validation service sub framework
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class ValidationHelper {
	
	private static final String VALIDATOR_PREFIX1 = "validator";
	private static final String VALIDATOR_PREFIX2 = "val";
	
	private static final String ISSUER_PREFIX = "issuer";
	
	private static final int SUPPORTED_NUMBER_OF_VALIDATORS = 255;
	
	/**
	 * Method returning a validation properties from a worker properties.
	 * 
	 * It will work in the following manner:
	 * <ul>
	 * <li>All properties starting with 'validator<validatorId>.' or 'val<validatorId>.' will have
	 *   the following keys added without the 'val...' prefix.
	 * <li>All properties without 'val...' prefix will be added if the key doesn't exist already. I.e
	 * all properties with keys starting 'val..' overrides general properties.
	 * <li>If no 'validator<validatorId>.' exists for the given id then, null will be returned.
	 * </ul>
	 * @param config a worker config containing all properties
	 * @return a Propertes according to above specification or 'null' if no property with 'val...' exists
	 * in configuration.
	 */
	public static Properties getValidatorProperties(int validatorId, WorkerConfig config){
		Properties retval = new Properties();
		Properties workerProps = config.getProperties();
		
		boolean foundValidatorId = false;
		// find validator properties
		Enumeration<?> en = config.getProperties().propertyNames();
		while(en.hasMoreElements()){
			String next = (String) en.nextElement();
			String strippedKey = validatorPrefix(validatorId,next);
			if(strippedKey != null){
				foundValidatorId = true;
				retval.setProperty(strippedKey, workerProps.getProperty(next));
			}
		}
		if(foundValidatorId){
			// Separate general properties from validator specific and add if they already doesn't exist.
			en = config.getProperties().propertyNames();
			while(en.hasMoreElements()){
				String next = (String) en.nextElement();
				if(validatorPrefix(0, next) == null){
					if(retval.getProperty(next) == null){
						retval.setProperty(next, workerProps.getProperty(next));
					}
				}
			}
		}else{
			retval = null;
		}

		return retval;
	}

	/**
	 * Returns the value after the validator_prefix
	 * @param next input property key
	 * @return the subset of the property key with validator prefix removed, or null if no
	 * validator prefix could be found.
	 */
	private static String validatorPrefix(int validatorId, String key ) {
		String retval = null;
		
		if(key.length() > VALIDATOR_PREFIX1.length() +2){
			String tmp = key.substring(0, VALIDATOR_PREFIX1.length());
			if(tmp.equalsIgnoreCase(VALIDATOR_PREFIX1)){
				if(key.substring(VALIDATOR_PREFIX1.length()).substring(0, 1).matches("\\d")){
					try{
					  int id = Integer.parseInt(key.substring(VALIDATOR_PREFIX1.length(),key.indexOf('.')));
					  if(id == validatorId || validatorId == 0){
					    retval = key.substring(key.indexOf('.')+1);
					  }
					}catch(NumberFormatException e){}
				}
			}
		}
		if(key.length() > VALIDATOR_PREFIX2.length() +2){
			String tmp = key.substring(0, VALIDATOR_PREFIX2.length());
			if(tmp.equalsIgnoreCase(VALIDATOR_PREFIX2)){
				if(key.substring(VALIDATOR_PREFIX2.length()).substring(0, 1).matches("\\d")){
					try{
						int id = Integer.parseInt(key.substring(VALIDATOR_PREFIX2.length(),key.indexOf('.')));
						if(id == validatorId || validatorId == 0){
							retval = key.substring(key.indexOf('.')+1);			
						}
					}catch(NumberFormatException e){}
				}
			}
		}

		return retval;
	}
	
	/**
	 * Help method instantiating all configured validators and initializes them and
	 * returns a HashMap containing all available validators by validatorId as key.
	 * 
	 * @param workerId current workerId
	 * @param config worker config for the ValidationServiceWorker
	 * @return available validators, never null
	 * @throws SignServerException if validators are missconfigured.
	 */
	public static HashMap<Integer, IValidator> genValidators(int workerId, WorkerConfig config, EntityManager em, ICryptoToken ct) throws SignServerException{
		HashMap<Integer, IValidator> retval = new HashMap<Integer, IValidator>();
		
		for(int i=1;i<=SUPPORTED_NUMBER_OF_VALIDATORS;i++){
			Properties valprops = getValidatorProperties(i,config);
			if(valprops != null){
				String classpath = valprops.getProperty(ValidationServiceConstants.VALIDATOR_SETTING_CLASSPATH);
				if(classpath != null){
					try {
						Class<?> c = ValidationHelper.class.getClassLoader().loadClass(classpath);
						IValidator v = (IValidator) c.newInstance();
						v.init(workerId, i, valprops, em, ct);
						retval.put(i, v);
					} catch (ClassNotFoundException e) {
						throw new SignServerException("Error validator with validatorId " +i + " with workerId " + workerId + " have got the required setting " + ValidationServiceConstants.VALIDATOR_SETTING_CLASSPATH + " set correctly.");
					} catch (InstantiationException e) {
						throw new SignServerException("Error validator with validatorId " +i + " with workerId " + workerId + " have got the required setting " + ValidationServiceConstants.VALIDATOR_SETTING_CLASSPATH + " set correctly.");
					} catch (IllegalAccessException e) {
						throw new SignServerException("Error validator with validatorId " +i + " with workerId " + workerId + " have got the required setting " + ValidationServiceConstants.VALIDATOR_SETTING_CLASSPATH + " set correctly.");
					}				
				}else{
					throw new SignServerException("Error validator with validatorId " +i + " with workerId " + workerId + " have got the required setting " + ValidationServiceConstants.VALIDATOR_SETTING_CLASSPATH + " set correctly.");
				}
			}
		}
		
		return retval;
	}
	
	/**
	 * Method returning a validation properties from a validation properties.
	 * 
	 * It will work in the following manner:
	 * <ul>
	 * <li>All properties starting with 'issuer<issuerId>.'  will have
	 *   the following keys added without the 'issuer...' prefix.
	 * <li>All properties without 'issuer...' prefix will be added if the key doesn't exist already. I.e
	 * all properties with keys starting 'issuer..' overrides general properties.
	 * <li>If no 'issuer<issuerId>.' exists for the given id then, null will be returned.
	 * </ul>
	 * @param config a worker config containing all properties
	 * @return a Propertes according to above specification or 'null' if no property with 'issuer...' exists
	 * in configuration.
	 */
	public static Properties getIssuerProperties(int issuerId, Properties validatorProperties){
		Properties retval = new Properties();
		
		boolean foundIssuerId = false;
		// find issuer properties
		Enumeration<?> en = validatorProperties.propertyNames();
		while(en.hasMoreElements()){
			String next = (String) en.nextElement();
			String strippedKey = issuerPrefix(issuerId,next);
			if(strippedKey != null){
				foundIssuerId = true;
				retval.setProperty(strippedKey, validatorProperties.getProperty(next));
			}
		}
		if(foundIssuerId){
			// Separate general properties from issuer specific and add if they already doesn't exist.
			en = validatorProperties.propertyNames();
			while(en.hasMoreElements()){
				String next = (String) en.nextElement();
				if(issuerPrefix(0, next) == null){
					if(retval.getProperty(next) == null){
						retval.setProperty(next, validatorProperties.getProperty(next));
					}
				}
			}
		}else{
			retval = null;
		}

		return retval;
	}
	
	/**
	 * Returns the value after the issuer prefix
	 * @param next input property key
	 * @return the subset of the property key with issuer prefix removed, or null if no
	 * issuer prefix could be found.
	 */
	private static String issuerPrefix(int issuerId, String key ) {
		String retval = null;
		
		if(key.length() > ISSUER_PREFIX.length() +2){
			String tmp = key.substring(0, ISSUER_PREFIX.length());
			if(tmp.equalsIgnoreCase(ISSUER_PREFIX)){
				if(key.substring(ISSUER_PREFIX.length()).substring(0, 1).matches("\\d")){
					try{
					  int id = Integer.parseInt(key.substring(ISSUER_PREFIX.length(),key.indexOf('.')));
					  if(id == issuerId || issuerId == 0){
					    retval = key.substring(key.indexOf('.')+1);
					  }
					}catch(NumberFormatException e){}
				}
			}
		}

		return retval;
	}
}
