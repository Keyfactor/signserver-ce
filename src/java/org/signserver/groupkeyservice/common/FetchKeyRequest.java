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
 * FetchKeyRequest is a process request sent to GroupKeyService in order to fetch a 
 * group key given a documentId.
 * 
 * @author Philip Vendil
 * $Id: FetchKeyRequest.java,v 1.1 2007-11-09 15:46:45 herrvendil Exp $
 */
public class FetchKeyRequest implements IProcessRequest {
	
	private static final long serialVersionUID = 1L;
	// Not really used in this case.	
	private String documentId;
	private boolean genKeyIfNotExist = false;
	private int keyType = GroupKeyServiceConstants.KEYTYPE_DEFAULT;
	
	/**
	 * Default constructor used to fetch a key using the default key type.
	 * 
	 * @param documentId unique identifier of a document
	 * @param genKeyIfNotExist if key doesn't exists should a unassigned key be used, otherwise
	 * will a IllegalRequestException be thrown.
	 */
	public FetchKeyRequest(String documentId, boolean genKeyIfNotExist) {
		super();
		this.documentId = documentId;
		this.genKeyIfNotExist = genKeyIfNotExist;
	}
	
	/**
	 * Default constructor used to fetch a key using the default key type.
	 * 
	 * @param documentId unique identifier of a document
	 * @param genKeyIfNotExist if key doesn't exists should a unassigned key be used, otherwise
	 * will a IllegalRequestException be thrown.
	 * @param keyType one of GroupKeyServiceConstants.KEYTYPE_ constants
	 */
	public FetchKeyRequest(String documentId, boolean genKeyIfNotExist, int keyType) {
		super();
		this.documentId = documentId;
		this.genKeyIfNotExist = genKeyIfNotExist;
		this.keyType = keyType;
	}

	/**
	 * 
	 * @return unique identifier of a document
	 */
	public String getDocumentId() {
		return documentId;
	}

	/**
	 * @return genKeyIfNotExist if key doesn't exists should a unassigned key be used, otherwise
	 * will a IllegalRequestException be thrown.
	 */
	public boolean isGenKeyIfNotExist() {
		return genKeyIfNotExist;
	}


	/**
	 * 
	 * @return one of GroupKeyServiceConstants.KEYTYPE_ constants
	 */
	public int getKeyType() {
		return keyType;
	}

}
