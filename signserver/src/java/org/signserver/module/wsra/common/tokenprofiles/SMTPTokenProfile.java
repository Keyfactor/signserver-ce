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
 * 
 * 
 * 
 * @author Philip Vendil 24 okt 2008
 *
 * @version $Id$
 */

public class SMTPTokenProfile extends JKSTokenProfile {
	
	public static final String PROFILEID = "SMTPTOKENPROFILE";
	

	
	/**
	 * Do not store SMTP token profile
	 */
	public boolean storeSensitiveData() {
		return true;
	}



	/**
	 * @see org.signserver.module.wsra.common.tokenprofiles.ITokenProfile#getProfileIdentifier()
	 */
	public String getProfileIdentifier() {
		return PROFILEID;
	}
}
