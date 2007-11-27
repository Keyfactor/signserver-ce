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

import java.io.Serializable;

import org.signserver.common.IProcessResponse;

/**
 * FetchKeyResponse is given by a GroupKeyService processing a FetchKeyRequest if
 * all the processing was successful.
 * 
 * @author phive
 *
 * @author Philip Vendil
 * $Id: FetchKeyResponse.java,v 1.2 2007-11-27 06:05:06 herrvendil Exp $
 */
public class FetchKeyResponse implements IProcessResponse{
	private static final long serialVersionUID = 1L;

	private String documentId;
	private byte[] groupKey;
		
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

	public Serializable getProcessedData() {
		return groupKey;
	}
	

}
