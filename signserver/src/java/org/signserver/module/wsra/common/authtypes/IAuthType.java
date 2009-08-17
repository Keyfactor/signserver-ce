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
package org.signserver.module.wsra.common.authtypes;


import org.signserver.common.RequestContext;

/**
 * Class that all authentication types should 
 * implement.
 * 
 * 
 * @author Philip Vendil 11 okt 2008
 *
 * @version $Id$
 */
public interface IAuthType {
	
	/**
	 * Method that from the request context should
	 * calculate a value that should be compared
	 * with the authentication value data in database to
	 * se if the request belongs to a user.
	 * 
	 * @param requestContext the request context.
	 * @return a value that should be compared
	 * with the authentication value data in database. if
	 * no value can be calculated should null be returned.
	 */
	String getMatchValue(RequestContext requestContext);
	
	/**
	 * @return Method that should return a unique id of this type
	 * of authentication.
	 * 
	 */
	int getAuthType();

}
