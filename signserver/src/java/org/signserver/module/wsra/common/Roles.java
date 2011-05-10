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
 * Class defining all default Roles in the WSRA system.
 * These roles are the one used by default it is still
 * possible for developers to use custom roles.
 * 
 * Important, a role name cannot contain the ',' character.
 * 
 * 
 * @author Philip Vendil 11 okt 2008
 *
 * @version $Id$
 */

public class Roles {

	/**
	 * Role defining that the user is a SMTP server.
	 */
	public static final String SMTPSERVER = "SMTPSERVER";
	
	/**
	 * Role defining that the user is a SUPERADMIN, this
	 * is usually defining "All access" and is the equivalent
	 * as root in 'Unix' systems. Have access to all organizations.
	 */
	public static final String SUPERADMIN = "SUPERADMIN";
	
	/**
	 * Role defining that the user is a main Admin,
	 * this is usually defining that the admin is allowed
	 * all access related to one organization only.
	 */
	public static final String MAINADMIN = "MAINADMIN";
	
	/**
	 * Role defining that the user is a RA Admin,
	 * this is usually defining that the admin is allowed
	 * to manage certificates.
	 */
	public static final String RAADMIN = "RAADMIN";
	
	/**
	 * Role defining that the user is a SMTP Server Admin,
	 * this is usually defining that the admin is allowed
	 * to manage SMTP key store certificates
	 */
	public static final String SMTPADMIN = "SMTPADMIN";
	
	/**
	 * Role defining that the user is a regular user
	 * with no specific administrative rights.
	 */
	public static final String USER = "USER";
	

}
