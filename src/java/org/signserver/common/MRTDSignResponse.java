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

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.ArrayList;

/**
 * Class used for the response of the signSession.signData method and contain information
 * specific to MRTD signing.
 * 
 * 
 * @author Philip Vendil
 * $Id: MRTDSignResponse.java,v 1.1 2007-02-27 16:18:10 herrvendil Exp $
 */

public class MRTDSignResponse implements ISignResponse {
	
	private static final long serialVersionUID = 1L;
	
	private int requestID = 0;
	private ArrayList signedData = null;
	private Certificate signerCertificate = null;

	/**
	 * Main Constuctor
	 */
	public MRTDSignResponse(int requestID, ArrayList signedData, Certificate signerCertificate){
	  this.requestID = requestID;
	  this.signedData = signedData;
	  this.signerCertificate = signerCertificate;
	}
	
	/**
	 * 
	 * @see org.signserver.common.ISignResponse#getRequestID()
	 */
	public int getRequestID() {
		return requestID;
	}

	/**
	 * Returns the signed data in an ArrayList class.
	 * 
	 * @return ArrayList of signed Hashes in byte[] format
	 */
	public Serializable getSignedData() {
		return signedData;
	}

	/**
	 * Returns the certificate of the signer.
	 * 
	 * @return the X509Certificate that was used for the signing.
	 */
	public Certificate getSignerCertificate() {
		return signerCertificate;
	}

	/**
	 * Not supported, always returns null.
	 */
	public ArchiveData getArchiveData() {
		return null;
	}

	/**
	 * Not supported, always returns null.
	 */	
	public String getArchiveId() {
		return null;
	}

}
