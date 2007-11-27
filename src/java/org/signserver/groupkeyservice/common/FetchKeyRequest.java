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
 * $Id: FetchKeyRequest.java,v 1.2 2007-11-27 06:05:06 herrvendil Exp $
 */
public class FetchKeyRequest implements IProcessRequest {
	
	private static final long serialVersionUID = 1L;
	// Not really used in this case.	
	private String documentId;
	private boolean genKeyIfNotExist = false;	
	private int keyPart = GroupKeyServiceConstants.KEYPART_SYMMETRIC;

	
	/**
	 * Default constructor used to fetch a key using the default key type.
	 * 
	 * @param documentId unique identifier of a document
	 * @param keyPart one of GroupKeyServiceConstants.KEYPART constants indicating part of key to fetch.
	 * @param genKeyIfNotExist if key doesn't exists should a unassigned key be used, otherwise
	 * will a IllegalRequestException be thrown.
	 */
	public FetchKeyRequest(String documentId, int keyPart, boolean genKeyIfNotExist) {
		super();
		this.documentId = documentId;
		this.keyPart = keyPart;
		this.genKeyIfNotExist = genKeyIfNotExist;
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
	 * @return one of GroupKeyServiceConstants.KEYPART_ constants indicating part of key to fetch.
	 */
	public int getKeyPart() {
		return keyPart;
	}
	
	

}
