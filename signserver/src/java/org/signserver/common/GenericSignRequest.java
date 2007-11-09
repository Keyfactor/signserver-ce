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
 * A Generic work request class implementing the minimal required functionality.
 * 
 * Could be used for TimeStamp Request.
 * 
 * @author philip
 * $Id: GenericSignRequest.java,v 1.2 2007-11-09 15:45:50 herrvendil Exp $
 */
public class GenericSignRequest implements ISignRequest {


	private static final long serialVersionUID = 1L;

	private int requestID;
	private Object requestData;
	
	/**
	 * Creates a GenericSignRequest, works as a simple VO.
	 * 
	 * @param requestID
	 * @param requestData
	 * @see org.signserver.common.IProcessRequest
	 */
	public GenericSignRequest(int requestID, Object requestData){
		this.requestID = requestID;
		this.requestData = requestData;
	}
	
	/**
	 * @see org.signserver.common.IProcessRequest
	 */
	public int getRequestID() {		
		return requestID;
	}

	/**
	 * @see org.signserver.common.IProcessRequest
	 */
	public Object getRequestData() {	
		return requestData;
	}

}
