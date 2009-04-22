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

import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestAndResponseManager;

/**
 * SwitchEncKeyResponse is given by a GroupKeyService processing a SwitchEncKeyRequest if
 * all the processing was successful.
 * 
 * @author phive
 *
 * @author Philip Vendil
 * $Id$
 */
public class SwitchEncKeyResponse extends ProcessResponse{
	private static final long serialVersionUID = 1L;

	private String newKeyIndex;
		
    /**
     * Default constructor used during serialization
     */
	public SwitchEncKeyResponse(){}
	
	/**
	 * Main constructor for the FetchKeyResponse
	 * @param newKeyIndex the index of the new encryption key used.
	 */
	public SwitchEncKeyResponse(String newKeyIndex) {
		this.newKeyIndex = newKeyIndex;
	}


	/**
	 * @return the index of the new encryption key used.
	 */
	public String getNewKeyIndex() {
		return newKeyIndex;
	}


	public void parse(DataInput in) throws IOException {
		in.readInt();
		int stringLen = in.readInt();
		byte[] stringData = new byte[stringLen];
		in.readFully(stringData);
		this.newKeyIndex = new String(stringData,"UTF-8");
	}

	public void serialize(DataOutput out) throws IOException {
		out.writeInt(RequestAndResponseManager.RESPONSETYPE_GKS_SWITCHENCKEY);
		byte[] stringData = newKeyIndex.getBytes("UTF-8");
		out.writeInt(stringData.length);
		out.write(stringData);
	}


	

}
