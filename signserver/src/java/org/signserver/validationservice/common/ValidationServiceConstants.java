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
package org.signserver.validationservice.common;

/**
 * Class containing constants common for the ValidationService part of the SignServer.
 * 
 * @author Philip Vendil
 * $Id: ValidationServiceConstants.java,v 1.1 2007-12-02 20:35:17 herrvendil Exp $
 */
public class ValidationServiceConstants {
	
	/**
	 * No specific certificate type.
	 */
	public static String CERTTYPE_ANY = "ANY"; 
		
	/**
	 * Certificate type used by client that want to check that the requested 
	 * certificate might be used for signing.
	 */
	public static String CERTTYPE_ELECTRONIC_SIGNATURE = "ELECTRONIC_SIGNATURE"; 
	/**
	 * Certificate type used by client that want to check that the requested 
	 * certificate might be used for identification.
	 */
	public static String CERTTYPE_IDENTIFICATION = "IDENTIFICATION";

	/**
	 * Setting indicating the type of validation service to instantiate when
	 * initializing.
	 * 
	 * Default: org.signserver.validation.server.DefaultValidationService
	 */
	public static final String VALIDATIONSERVICE_TYPE = "TYPE";
	public static final String DEFAULT_TYPE = "org.signserver.validationservice.server.DefaultValidationService";
	
	/**
	 * ';' separated string containing the issuer string of all issuers that should be cached.
	 */
	public static final String VALIDATIONSERVICE_CACHEDISSUERS = "CACHEDISSUERS";
	
	/**
	 * Setting defining the number of seconds a cached validation should be stored
	 * 
	 * Default: 10
	 */
	public static final String VALIDATIONSERVICE_TIMEINCACHE = "TIMEINCACHE";
	public static final String DEFAULT_TIMEINCACHE = "10";
	
	public static final int NUM_OF_SUPPORTED_ISSUERS = 255;
	
	/**
	 * Required setting for each issuer containing a Base64 encoded byte array containing 
	 * a full certificate chain.
	 */
	public static final String VALIDATIONSERVICE_ISSUERCERTCHAIN = "CERTCHAIN";
	
	/**
	 * Setting indicating the class path to the validator to instantiate. 
	 */
	public static final String VALIDATOR_SETTING_CLASSPATH = "CLASSPATH";
	
	/**
	 * Setting indicating the which cert type checker to instantiate
	 */
	public static final String VALIDATIONSERVICE_CERTTYPECHECKER = "CERTTYPECHECKER";
	public static final String DEFAULT_CERTTYPECHECKER = "org.signserver.validationservice.server.DefaultX509CertTypeChecker";
}
