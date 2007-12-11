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

import org.signserver.common.IProcessResponse;
import org.signserver.common.RequestAndResponseManager;

/**
 * FetchKeyResponse is given by a GroupKeyService processing a FetchKeyRequest if
 * all the processing was successful.
 * 
 * @author phive
 *
 * @author Philip Vendil
 * $Id: FetchKeyResponse.java,v 1.3 2007-12-11 05:36:58 herrvendil Exp $
 */
public class FetchKeyResponse implements IProcessResponse{
	private static final long serialVersionUID = 1L;

	private String documentId;
	private byte[] groupKey;
	
    /**
     * Default constructor used during serialization
     */
	public FetchKeyResponse(){}
		
	/**
	 * Main constructor for the FetchKeyResponse
	 * @param documentId the unique documentId that is related to the group key
	 * @param groupKey the actual key, decrypted and object serialized.
	 */
	public FetchKeyResponse(String documentId, byte[] groupKey) {
		this.documentId = documentId;
		this.groupKey = groupKey;
	}

	/**
	 * @return documentId the unique documentId that is related to the group key
	 */
	public String getDocumentId() {
		return documentId;
	}

	/**
	 * @return the actual key, decrypted.
	 */
	public byte[] getGroupKey(){
		return  groupKey;
	}

	public void readExternal(ObjectInput in) throws IOException,
			ClassNotFoundException {
		in.readInt();
		int stringLen = in.readInt();
		byte[] stringData = new byte[stringLen];
		in.readFully(stringData);
		this.documentId = new String(stringData,"UTF-8");
		int keySize = in.readInt();
		groupKey = new byte[keySize];
		in.readFully(groupKey);		
	}

	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(RequestAndResponseManager.RESPONSETYPE_GKS_FETCHKEY);
		byte[] stringData = documentId.getBytes("UTF-8");
		out.writeInt(stringData.length);
		out.write(stringData);
		out.writeInt(groupKey.length);
		out.write(groupKey);
	}
	

}
