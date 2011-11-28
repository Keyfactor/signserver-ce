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
 
package org.signserver.module.wsra.common.tokenprofiles;

/**
 * Class representing that the certificat on the token
 * was custom user generated and not placed on any to the system
 * known token.
 * 
 * 
 * @author Philip Vendil 20 okt 2008
 *
 * @version $Id$
 */

public class UserGeneratedTokenProfile implements ITokenProfile {

	public static final String PROFILEID = "USERGENERATEDPROFILE";;
	
	/**
	 * @see org.signserver.module.wsra.common.tokenprofiles.ITokenProfile#getProfileIdentifier()
	 */
	public String getProfileIdentifier() {
		return PROFILEID;
	}
	/**
	 * Do not store user generated token profile
	 */
	public boolean storeSensitiveData() {
		return false;
	}
}
