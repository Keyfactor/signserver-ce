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
 * @version $Id$
 */
public class ValidationServiceConstants {

    /**
     * Dont check for any specific certificate purpose
     */
    public static String CERTPURPOSE_NO_PURPOSE = null;
    
    /**
     * Certificate purpose used by client that want to check that the requested 
     * certificate might be used for signing.
     */
    public static String CERTPURPOSE_ELECTRONIC_SIGNATURE = "ELECTRONIC_SIGNATURE";
    
    /**
     * Certificate type used by client that want to check that the requested 
     * certificate might be used for identification.
     */
    public static String CERTPURPOSE_IDENTIFICATION = "IDENTIFICATION";
    
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
    public static final String VALIDATIONSERVICE_CERTPURPOSECHECKER = "CERTPURPOSECHECKER";
    public static final String DEFAULT_CERTPURPOSECHECKER = "org.signserver.validationservice.server.DefaultX509CertPurposeChecker";
    
    /**
     * Setting indicating crl paths for given issuer , crls should be VALIDATIONSERVICE_ISSUERCRLPATHSDELIMITER delimited URLs 
     */
    public static final String VALIDATIONSERVICE_ISSUERCRLPATHS = "CRLPATHS";
    
    /**
     * Setting indicating what delimiter is used for specifying multiple CRLs in VALIDATIONSERVICE_ISSUERCRLPATHS property
     */
    public static final String VALIDATIONSERVICE_ISSUERCRLPATHSDELIMITER = ",";
    
    /**
     * Setting indicating the max number of Authorized OCSP Responder certificates , that can be enlisted in properties of OCSP Validator
     */
    public static final int NUM_OF_SUPPORTED_AUTHORIZED_OCSP_RESPONDER_CERTS = 5;
    
    /**
     * Setting indicating the prefix that should be used to indicate an  Authorized OCSP Responder certificate, in OCSP Validator
     */
    public static final String AUTHORIZED_OCSP_RESPONDER_CERT_PREFIX = "AUTHORIZEDOCSPRESPONDERCERT";
}
