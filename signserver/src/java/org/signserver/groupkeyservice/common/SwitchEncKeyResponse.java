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
 * SwitchEncKeyResponse is given by a GroupKeyService processing a SwitchEncKeyRequest if
 * all the processing was successful.
 * 
 * @author phive
 *
 * @author Philip Vendil
 * $Id: SwitchEncKeyResponse.java,v 1.2 2007-11-27 06:05:06 herrvendil Exp $
 */
public class SwitchEncKeyResponse implements IProcessResponse{
	private static final long serialVersionUID = 1L;

	private String newKeyIndex;
		
	/**
	 * Main constructor for the FetchKeyResponse
	 * @param newKeyIndex the index of the new encryption key used.
	 */
	public SwitchEncKeyResponse(String newKeyIndex) {
		this.newKeyIndex = newKeyIndex;
	}

	/**
	 * Not implemented or used.
	 */
	public Serializable getProcessedData() {
		return null;
	}

	/**
	 * @return the index of the new encryption key used.
	 */
	public String getNewKeyIndex() {
		return newKeyIndex;
	}


	

}
