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
 * Response sent after processing the PregenerateKeysRequest
 * 
 * @author Philip Vendil
 * $Id: PregenerateKeysResponse.java,v 1.3 2007-12-11 05:36:58 herrvendil Exp $
 */
public class PregenerateKeysResponse implements IProcessResponse {

	private static final long serialVersionUID = 1L;
	
	int numberOfKeysGenerated;
	
    /**
     * Default constructor used during serialization
     */
	public PregenerateKeysResponse(){}
	
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



	public void readExternal(ObjectInput in) throws IOException,
			ClassNotFoundException {
         in.readInt();
         numberOfKeysGenerated = in.readInt();
		
	}

	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(RequestAndResponseManager.RESPONSETYPE_GKS_PREGENKEYS);
		out.writeInt(numberOfKeysGenerated);
	}



}
