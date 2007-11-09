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
 * Response sent after processing the PregenerateKeysRequest
 * 
 * @author Philip Vendil
 * $Id: PregenerateKeysResponse.java,v 1.1 2007-11-09 15:46:45 herrvendil Exp $
 */
public class PregenerateKeysResponse implements IProcessResponse {

	private static final long serialVersionUID = 1L;
	
	int numberOfKeysGenerated;
	int keyType;
	

	
   /**
    * Main constructor
    * 
    * @param numberOfKeysGenerated number of keys that were generated.
    * @param keyType the type of key actually generated
    */
	public PregenerateKeysResponse(int numberOfKeysGenerated, int keyType) {
		super();
		this.numberOfKeysGenerated = numberOfKeysGenerated;
		this.keyType = keyType;
	}

	/**
	 * @return number of keys that were generated.
	 */
	public int getNumberOfKeysGenerated() {
		return numberOfKeysGenerated;
	}

	/**
	 * 
	 * @return the type of key actually generated    
	 */
	public int getKeyType() {
		return keyType;
	}

	/**
	 * Not implemented
	 * @see org.signserver.common.IProcessResponse#getProcessedData()
	 */
	public Serializable getProcessedData() {	
		return null;
	}

}
