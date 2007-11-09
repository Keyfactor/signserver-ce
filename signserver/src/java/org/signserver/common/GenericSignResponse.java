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
 * A generic work response class implementing the minimal required functionality.
 * 
 * Could be used for TimeStamp Responses.
 * 
 * @author philip
 * $Id: GenericSignResponse.java,v 1.2 2007-11-09 15:45:49 herrvendil Exp $
 */
public class GenericSignResponse implements ISignResponse {

	private static final long serialVersionUID = 1L;
	private int requestID;
	private Serializable processedData;
	private Certificate signerCertificate;
	private ArchiveData archiveData;
	private String archiveId;
	
	
	/**
	 * Creates a GenericWorkResponse, works as a simple VO.
	 * 
	 * @see org.signserver.common.IProcessRequest
	 */
	public GenericSignResponse(int requestID, Serializable processedData, 
			                   Certificate signerCertificate, 
			                   String archiveId, ArchiveData archiveData) {
		this.requestID = requestID;
		this.processedData = processedData;
		this.signerCertificate = signerCertificate;
		this.archiveData = archiveData;
		this.archiveId = archiveId;
	}

	/**
	 * @see org.signserver.common.IProcessResponse#getRequestID()
	 */
	public int getRequestID() {
		return requestID;
	}

	/**
	 * @see org.signserver.common.IProcessResponse#getProcessedData()
	 */
	public Serializable getProcessedData() {	
		return processedData;
	}

	/**
	 * @see org.signserver.common.IProcessResponse#getSignerCertificate()
	 */
	public Certificate getSignerCertificate() {
		return signerCertificate;
	}

	/**
	 * @see org.signserver.common.IProcessResponse#getArchiveData()
	 */	
	public ArchiveData getArchiveData() {
		return archiveData;
	}
	
	/**
	 * @see org.signserver.common.IProcessResponse#getArchiveId()
	 */	
	public String getArchiveId() {
		return archiveId;
	}

}
