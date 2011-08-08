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

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
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
 * $Id$
 */
public class GenericSignResponse extends ProcessResponse implements ISignResponse {

	private static final long serialVersionUID = 2L;
    protected int tag = RequestAndResponseManager.RESPONSETYPE_GENERICSIGNRESPONSE;
	private int requestID;
	private byte[] processedData;
    private transient Certificate signerCertificate;
    private byte[] signerCertificateBytes;
	private ArchiveData archiveData;
	private String archiveId;
	
    /**
     * Default constructor used during serialization.
     */
	public GenericSignResponse(){}
	
	/**
	 * Creates a GenericWorkResponse, works as a simple VO.
	 * 
	 * @see org.signserver.common.ProcessRequest
	 */
	public GenericSignResponse(int requestID, byte[] processedData, 
			                   Certificate signerCertificate, 
			                   String archiveId, ArchiveData archiveData) {
            try {
                this.requestID = requestID;
                this.processedData = processedData;
                this.signerCertificate = signerCertificate;
                this.signerCertificateBytes = signerCertificate.getEncoded();
                this.archiveData = archiveData;
                this.archiveId = archiveId;
            } catch (CertificateEncodingException ex) {
                throw new RuntimeException(ex);
            }
	}

	/**
	 * @return the request ID
	 */
	public int getRequestID() {
		return requestID;
	}


	/**
	 * @see org.signserver.common.ProcessResponse#getCertificate()
	 */
	public Certificate getSignerCertificate() {
            if (signerCertificate == null) {
                try {
                    signerCertificate = CertTools.getCertfromByteArray(
                            signerCertificateBytes);
                } catch (CertificateException ex) {
                    throw new RuntimeException(ex);
                }
            }
            return signerCertificate;
	}

	/**
	 * @see org.signserver.common.ProcessResponse#getArchiveData()
	 */	
	public ArchiveData getArchiveData() {
		return archiveData;
	}
	
	/**
	 * @see org.signserver.common.ProcessResponse#getArchiveId()
	 */	
	public String getArchiveId() {
		return archiveId;
	}



	/**
	 * @return the processedData
	 */
	public byte[] getProcessedData() {
		return processedData;
	}

	public void parse(DataInput in) throws IOException {
		in.readInt();
		this.requestID = in.readInt();
		
		int certSize = in.readInt();
		if(certSize != 0){
			byte[] certData = new byte[certSize];
			in.readFully(certData);
			try {
				this.signerCertificate = CertTools.getCertfromByteArray(certData);
			} catch (CertificateException e) {
				try {
					throw new IOException(e.getMessage()).initCause(e);
				} catch (Throwable e1) {
					throw new IOException(e.getMessage());
				}
			}
		}
		int dataSize = in.readInt();
		processedData = new byte[dataSize];
		in.readFully(processedData);
	}

	public void serialize(DataOutput out) throws IOException {
		out.writeInt(tag);
		out.writeInt(this.requestID);
		if(signerCertificate != null){
			try {
				byte[] certData = this.signerCertificate.getEncoded();
				out.writeInt(certData.length);
				out.write(certData);
			} catch (CertificateEncodingException e) {
				try {
					throw new IOException(e.getMessage()).initCause(e);
				} catch (Throwable e1) {
					throw new IOException(e.getMessage());
				}
			}
		}else{
			out.writeInt(0);
		}
        out.writeInt(processedData.length);
		out.write(processedData);
	}



}
