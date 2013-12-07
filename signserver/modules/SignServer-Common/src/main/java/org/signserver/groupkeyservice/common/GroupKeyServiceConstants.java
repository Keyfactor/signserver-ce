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
package org.signserver.groupkeyservice.common;

/**
 * Class containing constants common for the GroupKeyService part of the SignServer.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class GroupKeyServiceConstants {

    /**
     * Indicates the full symmetric key should be fetched.
     * 
     * Key part constants indicating which part of a key
     * that should be fetched.
     */
    public static final int KEYPART_SYMMETRIC = 0;
    
    /**
     * Indicates the public key of an asymmetric key pair should be fetched.
     * 
     * Key part constants indicating which part of a key
     * that should be fetched.
     */
    public static final int KEYPART_PUBLIC = 1;
    
    /**
     * Indicates the private key of an asymmetric key pair should be fetched.
     * 
     * Key part constants indicating which part of a key
     * that should be fetched.
     */
    public static final int KEYPART_PRIVATE = 2;
    
    /**
     * Threshold indication after how many encryptions the encryption key should be swiched.
     */
    public static final String GROUPKEYDATASERVICE_KEYSWITCHTHRESHOLD = "KEYSWITCHTHRESHOLD";
    public static final long DEFAULT_KEYSWITCHTHRESHOLD = 100000;
    
    /**
     * Setting describing which algorithm that should be used for encryption of the group keys.
     * If not set will the default algorithm AES be used.
     */
    public static final String GROUPKEYDATASERVICE_ENCKEYALG = "ENCKEYALG";
    public static final String DEFAULT_ENCKEYALG = "AES";
    
    /**
     * Setting describing the specification of the key that should be used for encryption of the group keys.
     * If not set will a key specification of "256" be used.
     */
    public static final String GROUPKEYDATASERVICE_ENCKEYSPEC = "ENCKEYSPEC";
    public static final String DEFAULT_ENCKEYSPEC = "256";
    
    /**
     * Setting describing which algorithm that should be used when generating group keys.
     * If not set will the default algorithm AES be used.
     */
    public static final String GROUPKEYDATASERVICE_GROUPKEYALG = "GROUPKEYALG";
    public static final String DEFAULT_GROUPKEYALG = "AES";
    
    /**
     * Setting describing the specification of the key that should be used when generating  group keys.
     * If not set will a key specification of "256" be used.
     */
    public static final String GROUPKEYDATASERVICE_GROUPKEYSPEC = "GROUPKEYSPEC";
    public static final String DEFAULT_GROUPKEYSPEC = "256";
    
    /**
     * Setting indication if pregeneration of keys should be used or not.
     * The setting can have the values of "TRUE" or "FALSE"
     * Default: TRUE
     */
    public static final String GROUPKEYDATASERVICE_USEPREGENERATION = "USEPREGENERATION";
    public static final String DEFAULT_USEPREGENERATION = "TRUE";
    
    /**
     * Setting indicating the type of group key service to instantiate when
     * Initializing.
     * 
     * Default: org.signserver.groupkeyservice.server.DefaultGroupKeyService
     */
    public static final String GROUPKEYDATASERVICE_TYPE = "TYPE";
    public static final String DEFAULT_TYPE = "org.signserver.groupkeyservice.server.DefaultGroupKeyService";
}
