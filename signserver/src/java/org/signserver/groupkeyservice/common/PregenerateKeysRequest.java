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

import org.signserver.common.IProcessRequest;

/**
 * Request to a GroupKeyService to pregenerate unassigned keys into database.
 * 
 * Special care should be taken to the number of keys generated in one requests so
 * no transaction timeout occurs.
 * 
 * @author Philip Vendil
 * 
 * $Id: PregenerateKeysRequest.java,v 1.2 2007-11-27 06:05:05 herrvendil Exp $
 */
public class PregenerateKeysRequest implements IProcessRequest{

	private static final long serialVersionUID = 1L;

    int numberOfKeys;
    
    
    /**
     * Constructor pregenerating unassigned keys with default key type.
     *  
     * Special care should be taken to the number of keys generated in one requests so
     * no transaction timeout occurs.
     * 
     * @param numberOfKeys number of keys to generate
     */
	public PregenerateKeysRequest(int numberOfKeys) {
		super();
		this.numberOfKeys = numberOfKeys;
	}
	

	
	/**
	 * @return number of keys to generate
	 */
	public int getNumberOfKeys() {
		return numberOfKeys;
	}
	

    
    

}
