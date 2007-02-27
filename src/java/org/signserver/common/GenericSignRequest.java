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

/**
 * A Generic sign request class impelmenting the minimal required functionality.
 * 
 * Could be used for TimeStamp Request.
 * 
 * @author philip
 * $Id: GenericSignRequest.java,v 1.1 2007-02-27 16:18:11 herrvendil Exp $
 */
public class GenericSignRequest implements ISignRequest {


	private static final long serialVersionUID = 1L;

	private int requestID;
	private Object signRequestData;
	
	/**
	 * Creates a GenericSignRequest, works as a simple VO.
	 * 
	 * @param requestID
	 * @param signRequestData
	 * @see org.signserver.common.ISignRequest
	 */
	public GenericSignRequest(int requestID, Object signRequestData){
		this.requestID = requestID;
		this.signRequestData = signRequestData;
	}
	
	/**
	 * @see org.signserver.common.ISignRequest
	 */
	public int getRequestID() {		
		return requestID;
	}

	/**
	 * @see org.signserver.common.ISignRequest
	 */
	public Object getSignRequestData() {	
		return signRequestData;
	}

}
