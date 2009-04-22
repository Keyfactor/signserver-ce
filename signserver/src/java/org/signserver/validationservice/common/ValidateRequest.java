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
package org.signserver.validationservice.common;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestAndResponseManager;
import org.signserver.validationservice.server.ICertificateManager;

/**
 * ValidateRequest is a process request sent to a validation service in order to 
 * validate a certificate.
 * 
 * @author Philip Vendil
 * $Id$
 */
public class ValidateRequest extends ProcessRequest {

	private transient Logger log = Logger.getLogger(this.getClass());

	private static final long serialVersionUID = 1L;
	// Not really used in this case.	
	private transient ICertificate certificate;
	private byte[] certificateData;
	private String certPurposes;

    /**
     * Default constructor used during serialization
     */
	public ValidateRequest(){}
	
	/**
	 * Default constructor performing a full validation, verifying the complete chain
	 * returning the complete chain of the certificates
	 * @throws CertificateEncodingException 
	 */
	public ValidateRequest(ICertificate certificate, String certPurposes) throws CertificateEncodingException {
		super();
		this.certificate = certificate;
		this.certificateData = certificate.getEncoded();
		this.certPurposes = certPurposes;

	}
	


	/**
	 * @return the certificate
	 */
	public ICertificate getCertificate() {
		if(certificate == null){
			try {
				certificate = ICertificateManager.genICertificate(CertTools.getCertfromByteArray(certificateData));
			} catch (CertificateException e) {
				log.error(e);
			}
		}
		return certificate;
	}



	/**
	 * @return the certPurposes the client want's to check that the certificate can be used for a list that is splitted by ","
	 */
	public String[] getCertPurposes() {
		
		String[] retval = null;
		if(certPurposes != null && !certPurposes.trim().equals("")){
			retval = certPurposes.split(",");

			for(String purpose : retval){
				purpose = purpose.trim();
			}
		}
		
		return retval;
	}



	public void parse(DataInput in) throws IOException {
		in.readInt();
		int dataSize = in.readInt();
		certificateData = new byte[dataSize];
		in.readFully(certificateData);
		int stringLen = in.readInt();
		if(stringLen > 0){
		  byte[] stringData = new byte[stringLen];
		  in.readFully(stringData);
		  this.certPurposes = new String(stringData,"UTF-8");
		}
	}

	public void serialize(DataOutput out) throws IOException {
		out.writeInt(RequestAndResponseManager.RESPONSETYPE_VALIDATE);
		out.writeInt(certificateData.length);
		out.write(certificateData);
		if(certPurposes != null){
		  byte[] stringData = certPurposes.getBytes("UTF-8");
		  out.writeInt(stringData.length);
		  out.write(stringData);
		}else{
		  out.writeInt(0);
		}
	}





}
