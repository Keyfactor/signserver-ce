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

/**
 * A generic sign response class impelmenting the minimal required functionality.
 * 
 * Could be used for TimeStamp Responses.
 * 
 * @author philip
 * $Id: GenericSignResponse.java,v 1.1 2007-02-27 16:18:09 herrvendil Exp $
 */
public class GenericSignResponse implements ISignResponse {

	private static final long serialVersionUID = 1L;
	private int requestID;
	private Serializable signedData;
	private Certificate signerCertificate;
	private ArchiveData archiveData;
	private String archiveId;
	
	
	/**
	 * Creates a GenericSignResponse, works as a simple VO.
	 * 
	 * @see org.signserver.common.ISignRequest
	 */
	public GenericSignResponse(int requestID, Serializable signedData, 
			                   Certificate signerCertificate, 
			                   String archiveId, ArchiveData archiveData) {
		this.requestID = requestID;
		this.signedData = signedData;
		this.signerCertificate = signerCertificate;
		this.archiveData = archiveData;
		this.archiveId = archiveId;
	}

	/**
	 * @see org.signserver.common.ISignResponse#getRequestID()
	 */
	public int getRequestID() {
		return requestID;
	}

	/**
	 * @see org.signserver.common.ISignResponse#getSignedData()
	 */
	public Serializable getSignedData() {	
		return signedData;
	}

	/**
	 * @see org.signserver.common.ISignResponse#getSignerCertificate()
	 */
	public Certificate getSignerCertificate() {
		return signerCertificate;
	}

	/**
	 * @see org.signserver.common.ISignResponse#getArchiveData()
	 */	
	public ArchiveData getArchiveData() {
		return archiveData;
	}
	
	/**
	 * @see org.signserver.common.ISignResponse#getArchiveId()
	 */	
	public String getArchiveId() {
		return archiveId;
	}

}
