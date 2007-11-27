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

package org.signserver.protocol.ws;

import javax.xml.bind.annotation.XmlTransient;

import org.ejbca.util.Base64;

/**
 * 
 * WebService representation of a signature request, corresponding
 * the the existing GeneralSignatureRequest class.
 * 
 * @author Philip Vendil 28 okt 2007
 *
 * @version $Id: ProcessRequestWS.java,v 1.1 2007-11-27 06:05:07 herrvendil Exp $
 */

public class ProcessRequestWS {

	private int requestID;
	private String signRequestDataBase64;
	
	public ProcessRequestWS() {
	}

	public ProcessRequestWS(int requestID, byte[] signRequestData) {
		super();
		this.requestID = requestID;
		setSignRequestData(signRequestData);
	}
	


	
	/**
	 * 
	 * @return the request id sent in the request to identify the response if more
	 * than one request was called in one call.
	 */
	public int getRequestID() {
		return requestID;
	}
	
	/**
	 * @param requestID the request id sent in the request to identify the response if more
	 * than one request was called in one call.
	 */
	public void setRequestID(int requestID) {
		this.requestID = requestID;
	}

	/**
	 * 
	 * @return Base64 encoded string containing the signature request data.
	 */
	public String getSignRequestDataBase64() {
		return signRequestDataBase64;
	}

	/**
	 * 
	 * @param signRequestDataBase64 encoded string containing the signature request data.
	 */
	public void setSignRequestDataBase64(String signRequestDataBase64) {
		this.signRequestDataBase64 = signRequestDataBase64;
	}
	
	/**
	 * Help method used to set the signature request from binary form. 
	 * @param signedData the data to base64 encode
	 */
	@XmlTransient
	public void setSignRequestData(byte[] signRequestData){
		if(signRequestData != null){
		  this.signRequestDataBase64 = new String(Base64.encode(signRequestData));
		}
	}
	
	/**
	 * Help method returning the signature request data in binary form. 
	 * @param signedData the actual data
	 */	
	public byte[] getSignRequestData(){
		if(signRequestDataBase64 == null){
			return null;
		}
		return Base64.decode(signRequestDataBase64.getBytes());
	}
	
}
