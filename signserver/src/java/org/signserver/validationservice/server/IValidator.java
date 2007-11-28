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


import java.net.ConnectException;
import java.security.cert.Certificate;
import java.util.Properties;

import javax.persistence.EntityManager;

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.validationservice.common.Validation;

/**
 * Interface all types of validators should implement, this could be 
 * a OCSP Validator or CRL validator or simply a database were the certificate
 * status is lookup up.
 * 
 * It's main method is validate(Certificate cert)
 * 
 * @author Philip Vendil
 *  
 * @version $Id: IValidator.java,v 1.1 2007-11-28 12:21:49 herrvendil Exp $
 *
 */
public interface IValidator {
	
	/**
	 * Setting indicating the class path to the validator to instantiate. 
	 */
	public static final String SETTING_CLASSPATH = "CLASSPATH";
	
	/**
	 * Initialization method that should be called directly after creation.
	 * @param workerId the unique id of the worker
	 * @param validatorId the id of this validator, a positive integer.
	 * @param props a subset of the worker properties only containing this validators properties, 
	 * for instance worker1.val1.propkey will show up as property key 'propkey' in this properies
	 * @param em reference to the entity manager
	 * @param ct the extended crypto token used by the validation service.
	 * @throws SignServerException if unexpected error occurred during initialization.
	 */
	void init(int workerId, int validatorId, Properties props, EntityManager em, ICryptoToken ct) throws SignServerException;

	/**
	 * Main method of a Group Key Service responsible for fetching keys from
	 * the database.
	 * 
	 * @param cert the certificate to validate.
	 * @return a Validation object or null if the certificate couldn't be looked up in this validator.
	 * @throws IllegalRequestException if data in the request didn't conform with the specification.
	 * @throws CryptoTokenOfflineException if the crypto token isn't online. 
	 * @throws SignServerException for general failure exception during validation.
	 */
	Validation validate(Certificate cert) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException;
	
	/**
	 * Optional method used to test the connection to a specific underlying validator implementation.
	 * 
	 * @throws ConnectException if connection to underlying validator implementation failed.
	 * @throws SignServerException for general failure exception during validation.
	 */
	void testConnection() throws ConnectException, SignServerException;
}
