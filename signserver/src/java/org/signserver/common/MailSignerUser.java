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

import java.io.Serializable;

import org.apache.james.services.User;

/**
 * Class representing a SMTP authenticated user.
 * 
 * 
 * @author Philip Vendil 24 dec 2007
 *
 * @version $Id$
 */

public class MailSignerUser implements User, Serializable {

	private static final long serialVersionUID = 1L;
	private String username;
	private String password;
	
	
	
	public MailSignerUser(String username, String password) {
		super();
		this.username = username;
		this.password = password;
	}

	/**
	 * @see org.apache.james.services.User#getUserName()
	 */
	public String getUserName() {		
		return username;
	}

	/**
	 * @see org.apache.james.services.User#setPassword(java.lang.String)
	 */
	public boolean setPassword(String password) {
		this.password = password;
		return true;
	}

	/**
	 * @see org.apache.james.services.User#verifyPassword(java.lang.String)
	 */
	public boolean verifyPassword(String password) {
		return this.password.endsWith(password);
	}

}
