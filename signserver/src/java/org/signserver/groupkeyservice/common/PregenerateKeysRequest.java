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

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;

import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestAndResponseManager;

/**
 * Request to a GroupKeyService to pregenerate unassigned keys into database.
 * 
 * Special care should be taken to the number of keys generated in one requests so
 * no transaction timeout occurs.
 * 
 * @author Philip Vendil
 * 
 * $Id$
 */
public class PregenerateKeysRequest extends ProcessRequest{

	private static final long serialVersionUID = 1L;

    int numberOfKeys;
    
    /**
     * Default constructor used during serialization
     */
    public PregenerateKeysRequest(){}
    
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


	public void parse(DataInput in) throws IOException {
		in.readInt();
		this.numberOfKeys = in.readInt();
	}

	public void serialize(DataOutput out) throws IOException {
        out.writeInt(RequestAndResponseManager.REQUESTTYPE_GKS_PREGENKEYS);
        out.writeInt(numberOfKeys);
	}

}
