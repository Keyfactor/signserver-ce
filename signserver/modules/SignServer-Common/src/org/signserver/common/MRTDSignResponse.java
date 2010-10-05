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
import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;

import org.ejbca.util.CertTools;

/**
 * Class used for the response of the signSession.signData method and contain information
 * specific to MRTD signing.
 * 
 * 
 * @author Philip Vendil
 * $Id$
 */

public class MRTDSignResponse extends ProcessResponse {
	
	private static final long serialVersionUID = 1L;
	
	private int requestID = 0;
	private ArrayList<byte[]> signedData = null;
	private Certificate signerCertificate = null;

    /**
     * Default constructor used during serialization
     */
	public MRTDSignResponse(){}
	
	/**
	 * Main Constuctor
	 */
	public MRTDSignResponse(int requestID, ArrayList<byte[]> signedData, Certificate signerCertificate){
	  this.requestID = requestID;
	  this.signedData = signedData;
	  this.signerCertificate = signerCertificate;
	}
	
	/**
	 * 
	 * @see org.signserver.common.ProcessResponse#getRequestID()
	 */
	public int getRequestID() {
		return requestID;
	}

	/**
	 * Returns the signed data in an ArrayList class.
	 * 
	 * @return ArrayList of signed Hashes in byte[] format
	 */
	public Serializable getProcessedData() {
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


	public void parse(DataInput in) throws IOException {
		in.readInt();
		this.requestID = in.readInt();
		int arraySize = in.readInt();
		this.signedData = new ArrayList<byte[]>();
		for(int i = 0;i<arraySize;i++){
			int dataSize = in.readInt();
			byte[] data = new byte[dataSize];
			in.readFully(data);
			signedData.add(data);
		}
		int certSize = in.readInt();
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

	public void serialize(DataOutput out) throws IOException {
		out.writeInt(RequestAndResponseManager.RESPONSETYPE_MRTDSIGNRESPONSE);
		out.writeInt(this.requestID);
		out.writeInt(this.signedData.size());
		for(byte[] data : signedData){
			out.writeInt(data.length);
			out.write(data);
		}
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
	}


}
