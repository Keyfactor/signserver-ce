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

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

import org.signserver.common.IProcessRequest;
import org.signserver.common.RequestAndResponseManager;

/**
 * Request to a GroupKeyService to pregenerate unassigned keys into database.
 * 
 * Special care should be taken to the number of keys generated in one requests so
 * no transaction timeout occurs.
 * 
 * @author Philip Vendil
 * 
 * $Id: PregenerateKeysRequest.java,v 1.3 2007-12-11 05:36:58 herrvendil Exp $
 */
public class PregenerateKeysRequest implements IProcessRequest{

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



	public void readExternal(ObjectInput in) throws IOException,
			ClassNotFoundException {
		in.readInt();
		this.numberOfKeys = in.readInt();
		
	}

	public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(RequestAndResponseManager.REQUESTTYPE_GKS_PREGENKEYS);
        out.writeInt(numberOfKeys);
	}

}
