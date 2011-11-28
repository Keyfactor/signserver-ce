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
 * Interface that all token profiles must implement.
 * 
 * This is the most basic version of the profile
 * and contains all method that is required
 * for peristense of tokens of this profile
 * 
 * 
 * @author Philip Vendil 15 okt 2008
 *
 * @version $Id$
 */
public interface ITokenProfile {
	
	/**
	 * Method that should return a unique identifier
	 * of this class.
	 */
	String getProfileIdentifier();
	
	/**
	 * If true will the tokens sensitive data be stored in database
	 * after token have been generated. This could be the actual soft 
	 * key store or PUK data for hard tokens.
	 */
	boolean storeSensitiveData();
		
}
