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
 
package org.signserver.module.wsra.common;

/**
 * 
 * 
 * 
 * @author Philip Vendil 15 okt 2008
 *
 * @version $Id$
 */

public class WSRAConstants {
	
	/**
	 * Setting indicating that WS calls (that support it) should be sent
	 * for debiting
	 * 
	 * Default: FALSE
	 */
	public static final String SETTING_DEBITWSCALLS = "DEBITWSCALLS";
	public static final String SETTING_DEFAULT_DEBITWSCALLS = "FALSE";
	

	
	
	/**
	 * Setting indicating that the a regular user is allowed
	 * to perform some actions on their own tokens/certificate
	 * such as revoke.
	 * 
	 * Default: FALSE
	 */
	public static final String SETTING_SELFADMINISTRATION = "SELFADMINISTRATION";
	public static final String SETTING_DEFAULT_SELFADMINISTRATION = "FALSE";
	
	
	/**
	 * Setting indicating that the property is a CACONNECTOR setting.
	 * Such a setting should be built like CACONNECTOR<id>.<setting>
	 * where id is a positive integer between 1 and 100.
	 */
	public static final String SETTING_CACONNECTOR_PREFIX = "CACONNECTOR";
	
	/**
	 * Setting indicating the class path of the CA Connector implementation.
	 */
	public static final String SETTING_CACONNECTOR_CLASSPATH = "CLASSPATH";
	
	/**
	 * Setting indicating the class path of the request data checker that should be used.
	 */
	public static final String SETTING_REQUESTDATACHECKER_CLASSPATH = "REQUESTDATACHECKERCLASSPATH";
	
	/**
	 * Worker configuration setting that indicates that the sensitive token data
	 * should be stored encrypted in database.
	 */
	public static final String SETTING_ENCRYPTTOKENDATA = "SETTING_ENCRYPTTOKENDATA";
	

	/**
	 * Setting used to import test data from an XML file into database.
	 * Should contain the full path to the XML data file.
	 */
	public static final String SETTING_TESTDATA = "TESTDATA";	
	

	
	/**
	 * Constant used as matchType in findUsersByAlias indicating
	 * that the user alias should equal the search alias value.
	 */
	public static final String MATCHTYPE_EQUALS = "EQUALS";
	
	/**
	 * Constant used as matchType in findUsersByAlias indicating
	 * that the user alias should contain the search alias value.
	 */
	public static final String MATCHTYPE_CONTAINS = "CONTAINS";
	
    /** Certificate doesn't belong to anyone */
    public static final int CERTSTATUS_UNASSIGNED = 0;

    /** Assigned, but not yet active */
    public static final int CERTSTATUS_INACTIVE = 10;

    /** Certificate is active and assigned */
    public static final int CERTSTATUS_ACTIVE = 20;
    
    /** Certificate is still active and the user is notified that it 
     * will soon expire. */
    public static final int CERTSTATUS_NOTIFIEDABOUTEXPIRATION = 21;

    /** Certificate is expired */
    public static final int CERTSTATUS_EXPIRED = 50;

    /** Certificate is expired and kept for archive purpose */
    public static final int CERTSTATUS_ARCHIVED = 60;
    
    /** Certificate is a X509 Certificate */
    public static final int CERTTYPE_X509 = 1;
    
    public static final int REVOKATION_REASON_NOT_REVOKED                            = -1;
    public static final int REVOKATION_REASON_UNSPECIFIED          = 0;
    public static final int REVOKATION_REASON_KEYCOMPROMISE        = 1;
    public static final int REVOKATION_REASON_CACOMPROMISE         = 2;
    public static final int REVOKATION_REASON_AFFILIATIONCHANGED   = 3;
    public static final int REVOKATION_REASON_SUPERSEDED           = 4;
    public static final int REVOKATION_REASON_CESSATIONOFOPERATION = 5;
    public static final int REVOKATION_REASON_CERTIFICATEHOLD      = 6;
    public static final int REVOKATION_REASON_REMOVEFROMCRL        = 8;
    public static final int REVOKATION_REASON_PRIVILEGESWITHDRAWN  = 9;
    public static final int REVOKATION_REASON_AACOMPROMISE         = 10;

    public enum UserStatus {
    	/**
    	 * Status of user indicating that it is ready for certificate generation.
    	 */
    	READYFORGENERATION(10),
    	/**
    	 * Status of user indicating that certificate is generated for user.
    	 */
    	GENERATED(20),

    	/**
    	 * Status of user indicating that the user isn't active currently
    	 */
    	DISABLED(30),

    	/**
    	 * Status that the user isn't used any more and is only there
    	 * for historical purposes.
    	 */
    	ARCHIVED(40);

    	UserStatus(int intValue){
    		this.intValue = intValue;
    	}

    	private int intValue;

    	public int getIntValue(){
    		return intValue;
    	}
    	
    	public static UserStatus findByIntValue(int intValue){
    		for(UserStatus o : UserStatus.values()){
    			if(o.intValue == intValue){
    				return o;
    			}
    		}
    		
    		return null;
    	}
    }

	
    public enum OrganizationStatus {
    	/**
         * Status of organization indicating this is an active organization.
         */
    	ACTIVE(10),

    	/**
         * Status of organization indicating that the organization isn't related currently
         */
    	INACTIVE(20),

    	/**
         * Status that the organization isn't used any more and is only there
         * for historical purposes.
         */
    	ARCHIVED(30);

    	OrganizationStatus(int intValue){
    		this.intValue = intValue;
    	}

    	private int intValue;

    	public int getIntValue(){
    		return intValue;
    	}
    	
    	public static OrganizationStatus findByIntValue(int intValue){
    		for(OrganizationStatus o : OrganizationStatus.values()){
    			if(o.intValue == intValue){
    				return o;
    			}
    		}
    		
    		return null;
    	}
    }

    public enum PricingStatus {
    	/**
         * Status of price indicating this is an active price.
         */
    	ACTIVE(1),

    	/**
         * Status of price indicating that the price isn't valid anymore
         */
    	DISABLED(2),

    	/**
         * Status of price indicating this is an archived price and not 
         * used anymore.
         */
    	ARCHIVED(3);

    	PricingStatus(int intValue){
    		this.intValue = intValue;
    	}

    	private int intValue;

    	public int getIntValue(){
    		return intValue;
    	}
    	
    	public static PricingStatus findByIntValue(int intValue){
    		for(PricingStatus o : PricingStatus.values()){
    			if(o.intValue == intValue){
    				return o;
    			}
    		}
    		
    		return null;
    	}
    }
	

    public enum ProductStatus {
    	/**
    	 * The product is currently sold
    	 */
    	SOLD(1),

    	/**
    	 * The product is not sold currently
    	 */
    	NOTSOLD (2),

    	/**
    	 * The product is not used any more and only stored for
    	 * historical purposes.
    	 */
    	ARCHIVED(3);

    	ProductStatus(int intValue){
    		this.intValue = intValue;
    	}

    	private int intValue;

    	public int getIntValue(){
    		return intValue;
    	}
    	
    	public static ProductStatus findByIntValue(int intValue){
    		for(ProductStatus o : ProductStatus.values()){
    			if(o.intValue == intValue){
    				return o;
    			}
    		}
    		
    		return null;
    	}
    }
	
	/**
	 * Transaction haven't been processed for invoicing or equivalent.
	 */
    public static final int TRANSACTIONSTATUS_UNPROCESSED = 10;
    /**
	 * Transaction is currently being processed for invoicing or equivalent.
	 */
    public static final int TRANSACTIONSTATUS_PROCESSING  = 20;
    /**
	 * Transaction have been processed for invoicing or equivalent.
	 */
    public static final int TRANSACTIONSTATUS_PROCESSED   = 30;
    /**
	 * Transaction is not relevant any more and only stored for historical purposes.
	 */
    public static final int TRANSACTIONSTATUS_ARCHIVED    = 90;
	
	/**
	 * Common serial number for all tokens were the token serial number
	 * isn't known.
	 */
	public static final String USERGENERATED_TOKENSERIALNUMBER = "USERGEN:";
    
	/**
	 * Type indicating that the key doesn't belong to any specific area
	 * of the WSRA data.
	 */
	public static final int DATABANKTYPE_GENERAL = 0;
	
	/**
	 * Type indicating that the key is related to a specific user.
	 */
	public static final int DATABANKTYPE_USER = 1;
	
	/**
	 * Type indicating that the key is related to a specific organization.
	 */
	public static final int DATABANKTYPE_ORGANIZATION = 2;
	
	/**
	 * Type indicating that the key is related to a specific organization.
	 */
	public static final int DATABANKTYPE_TOKEN = 3;
	
	/**
	 * Type indicating that the key is related to a specific product.
	 */
	public static final int DATABANKTYPE_PRODUCT = 4;
	
	/**
	 * Type indicating that the key is related to a specific price.
	 */
	public static final int DATABANKTYPE_PRICE = 5;
	
	/**
	 * Type indicating that the key is related to a specific product mapping.
	 */
	public static final int DATABANKTYPE_PRODUCTMAPPING = 6;
	
	  public enum OrganizationType {
		   /**
			 * Indicates that this organization is the owner of this system.
			 */
		   SYSTEMOWNER(1),

		   /**
			 * Indicates that this organization is a customer to the organization
			 */
		   CUSTOMER(2),

		   /**
			 * Indicates that this organization is the partner to the organization
			 */
		   PARTNER(3),
		   /**
			* Indicates that this organization is the supplier to the organization
			*/
		   SUPPLIER(4),
		   /**
			* Indicates that this organization is none of the defined types
			*/
		   OTHER(100);
		   
	    	OrganizationType(int intValue){
	    		this.intValue = intValue;
	    	}

	    	private int intValue;

	    	public int getIntValue(){
	    		return intValue;
	    	}
	    	
	    	public static OrganizationType findByIntValue(int intValue){
	    		for(OrganizationType o : OrganizationType.values()){
	    			if(o.intValue == intValue){
	    				return o;
	    			}
	    		}
	    		
	    		return null;
	    	}
	    }
	   

	/**
	 * A debit event that's generated after a certificate have been issued.
	 */
	public static final String DEBITEVENT_GENCERT = "GENCERT";
	

}
