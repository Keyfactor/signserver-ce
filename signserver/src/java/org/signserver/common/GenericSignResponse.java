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

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import org.ejbca.util.CertTools;

/**
 * A generic work response class implementing the minimal required functionality.
 * 
 * Could be used for TimeStamp Responses.
 * 
 * @author philip
 * $Id: GenericSignResponse.java,v 1.3 2007-12-11 05:36:58 herrvendil Exp $
 */
public class GenericSignResponse implements ISignResponse {

	private static final long serialVersionUID = 1L;
	private int requestID;
	private Serializable processedData;
	private Certificate signerCertificate;
	private ArchiveData archiveData;
	private String archiveId;
	
    /**
     * Default constructor used during serialization
     */
	public GenericSignResponse(){}
	
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

	
	public void readExternal(ObjectInput in) throws IOException,
			ClassNotFoundException {
		in.readInt();
		this.requestID = in.readInt();
		processedData = (Serializable) in.readObject();
		int certSize = in.readInt();
		byte[] certData = new byte[certSize];
		in.readFully(certData);
		try {
			this.signerCertificate = CertTools.getCertfromByteArray(certData);
		} catch (CertificateException e) {
			throw new IOException(e);
		}
		
	}

	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(RequestAndResponseManager.RESPONSETYPE_GENERICSIGNRESPONSE);
		out.writeInt(this.requestID);
		out.writeObject(processedData);
		try {
			byte[] certData = this.signerCertificate.getEncoded();
			out.writeInt(certData.length);
			out.write(certData);
		} catch (CertificateEncodingException e) {
			throw new IOException(e);
		}
	}

	/**
	 * @return the processedData
	 */
	public Serializable getProcessedData() {
		return processedData;
	}



}
