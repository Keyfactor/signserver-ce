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
 * $Id: SignServerConstants.java,v 1.1 2007-12-12 15:13:37 herrvendil Exp $
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
}
