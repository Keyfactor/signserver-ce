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

/**
 * Class containing general constants in common for most components
 * in the signserver
 * @author Philip Vendil
 * $Id$
 *
 */
public class SignServerConstants {

	/**
	 * Property indicating that the signserver shouldn't be used.
	 * Set propery to TRUE to disable the signer.
	 */
	public static final String DISABLED          = "DISABLED";
	
	/**
	 * Constant indicating that the signserver archive the response data.
	 * Set propery to TRUE to start archiving
	 */
	public static final String ARCHIVE          = "ARCHIVE";
	
	/**
	 * Constant indicating which module that should be used with
	 * the cluster class loader.
	 */
	public static final String MODULENAME          = "MODULENAME";
	
	/**
	 * Constant indicating which module version that should be used
	 * by the cluster class loader for the given worker.
	 * 
	 * If no module version is specified will the latest available
	 * version be used.
	 */
	public static final String MODULEVERSION          = "MODULEVERSION";
	
	/**
	 * Constant indicating if JPA should be used with the cluster
	 * class loader, it is used to create DB access for a specific
	 * worker in a MAR file.
	 * 
	 * 
	 */
	public static final String USEWORKERENTITYMANAGER = "USEWORKERENTITYMANAGER";
	
	/**
	 * Constant indicating that a signers certificate should be checked for validity.
	 * Set property to FALSE to ignore if the validity is not yet valid or has expired.
	 */
	public static final String CHECKCERTVALIDITY          = "CHECKCERTVALIDITY";

	/**
	 * Constant indicating that a signers certificate should be checked for validity of the private key (using the PrivateKeyUsagePeriod).
	 * Set property to FALSE to ignore if the private key usage period is not yet valid or has expired.
	 */
	public static final String CHECKCERTPRIVATEKEYVALIDITY          = "CHECKCERTPRIVATEKEYVALIDITY";

	/**
	 * Constant defining a minimum remaining certificate validity period for the signer to work. If the signer certificate has 
	 * less days validity remaining than the number of days specified by this property, the signer will not work.
	 * if ( (days until cert.getNotAfter) <  MINREMAININGCERTVALIDITY ) throw exception.
	 * A value of 0 means unlimited, i.e. the property is not used.
	 */
	public static final String MINREMAININGCERTVALIDITY          = "MINREMAININGCERTVALIDITY";

	
}
