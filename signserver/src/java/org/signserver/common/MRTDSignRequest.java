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

 
package org.signserver.common;

import java.util.ArrayList;

/**
 * Class used to send data to the signSession.signData method and contain information
 * specific to MRTD signing.
 * 
 * 
 * @author Philip Vendil
 * $Id: MRTDSignRequest.java,v 1.3 2007-11-09 15:45:49 herrvendil Exp $
 */

public class MRTDSignRequest implements IProcessRequest {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private int requestID = 0;
	private ArrayList<?> signRequestData = null;
	
	private static final String signatureAlgorithm = "RSASSA-PSS";
	
	
	/**
	 * Main constuctor.
	 * 
	 * @param requestID a unique id of the request
	 * @param signRequestData the data about to sign. Should be of type byte[]
	 */
	public MRTDSignRequest(int requestID, ArrayList<?> signRequestData){
	  this.requestID = requestID;
	  this.signRequestData = signRequestData;
	}
	
	/**
	 * 
	 * @see org.signserver.common.IProcessRequest#getRequestID()
	 */
	
	public int getRequestID() {
		return requestID;
	}

	/**
	 * Returns the signed data as an ArrayList of document objects to sign.
	 */
	public Object getRequestData() {
		return signRequestData;
	}

	public String getSignatureAlgorithm(){
		return signatureAlgorithm;
	}
	
}
