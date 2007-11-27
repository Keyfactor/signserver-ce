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
 * $Id: PregenerateKeysResponse.java,v 1.2 2007-11-27 06:05:06 herrvendil Exp $
 */
public class PregenerateKeysResponse implements IProcessResponse {

	private static final long serialVersionUID = 1L;
	
	int numberOfKeysGenerated;
	

	
   /**
    * Main constructor
    * 
    * @param numberOfKeysGenerated number of keys that were generated.
    */
	public PregenerateKeysResponse(int numberOfKeysGenerated) {
		super();
		this.numberOfKeysGenerated = numberOfKeysGenerated;
	}

	/**
	 * @return number of keys that were generated.
	 */
	public int getNumberOfKeysGenerated() {
		return numberOfKeysGenerated;
	}



	/**
	 * Not implemented
	 * @see org.signserver.common.IProcessResponse#getProcessedData()
	 */
	public Serializable getProcessedData() {	
		return null;
	}

}
