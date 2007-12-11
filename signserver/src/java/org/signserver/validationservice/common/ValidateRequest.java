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

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.signserver.common.IProcessRequest;
import org.signserver.common.RequestAndResponseManager;
import org.signserver.validationservice.common.ValidationServiceConstants.CertType;
import org.signserver.validationservice.server.ICertificateManager;

/**
 * ValidateRequest is a process request sent to a validation service in order to 
 * validate a certificate.
 * 
 * @author Philip Vendil
 * $Id: ValidateRequest.java,v 1.2 2007-12-11 05:37:52 herrvendil Exp $
 */
public class ValidateRequest implements IProcessRequest {

	private transient Logger log = Logger.getLogger(this.getClass());

	private static final long serialVersionUID = 1L;
	// Not really used in this case.	
	private transient ICertificate certificate;
	private byte[] certificateData;
	private ValidationServiceConstants.CertType certType;

    /**
     * Default constructor used during serialization
     */
	public ValidateRequest(){}
	
	/**
	 * Default constructor performing a full validation, verifying the complete chain
	 * returning the complete chain of the certificates
	 * @throws CertificateEncodingException 
	 */
	public ValidateRequest(ICertificate certificate, ValidationServiceConstants.CertType certType) throws CertificateEncodingException {
		super();
		this.certificate = certificate;
		this.certificateData = certificate.getEncoded();
		this.certType = certType;

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
	 * @return the certType the client want's to check that the certificate can be used for.
	 */
	public ValidationServiceConstants.CertType getCertType() {
		return certType;
	}





	public void readExternal(ObjectInput in) throws IOException,
			ClassNotFoundException {
		in.readInt();
		int dataSize = in.readInt();
		certificateData = new byte[dataSize];
		in.readFully(certificateData);
		int stringLen = in.readInt();
		byte[] stringData = new byte[stringLen];
		in.readFully(stringData);
		this.certType = CertType.valueOf(new String(stringData,"UTF-8"));
	    
	}



	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(RequestAndResponseManager.RESPONSETYPE_VALIDATE);
		out.writeInt(certificateData.length);
		out.write(certificateData);
		byte[] stringData = certType.name().getBytes("UTF-8");
		out.writeInt(stringData.length);
		out.write(stringData);
	}





}
