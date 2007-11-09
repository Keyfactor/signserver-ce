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
 * $Id: GroupKeyServiceConstants.java,v 1.1 2007-11-09 15:46:45 herrvendil Exp $
 */
public class GroupKeyServiceConstants {
	
	/**
	 * Keytype constants specifing the type of key used.
	 */
	public static final int KEYTYPE_DEFAULT = 0;
	public static final int KEYTYPE_AES256 = 1;
	public static final int KEYTYPE_RSA2048 = 2;

}
