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

import java.io.ByteArrayInputStream;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.ejbca.util.Base64;

/**
 * Class representing a certificate sent through WebService in
 * Base64 format.
 * 
 * 
 * @author Philip Vendil 29 okt 2007
 *
 * @version $Id: Certificate.java,v 1.1 2007-11-27 06:05:07 herrvendil Exp $
 */

public class Certificate {

	
	
	private String certificateBase64;
	private transient static String defaultCertType = "X.509"; // Default certificate type
	private transient static String defaultProvider = "BC";// Default provider
	
	public Certificate(){
		
	}
	
	/**
	 * Constructor containing the regular certificate
	 * @param cert
	 * @throws CertificateEncodingException 
	 */
	public Certificate(java.security.cert.Certificate cert) throws CertificateEncodingException{
		setCertificate(cert);
	}
	
	/**
	 * Constructor from  generated object
	 * @param cert
	 * @throws CertificateEncodingException 
	 *//*
	public Certificate(org.signserver.protocol.ws.gen.Certificate cert){
		setCertificateBase64(cert.getCertificateBase64());
	}*/
	
	/**
	 * 
	 * @return the certificate in Base64 format.
	 */
	public String getCertificateBase64() {
		return certificateBase64;
	}
	
	/**
	 * 
	 * @param certificateBase64   certificate in Base64 format.
	 */
	public void setCertificateBase64(String certificateBase64) {
		this.certificateBase64 = certificateBase64;
	}
	
	/**
	 * Help method used to retrieve the signerCertificate in Certificate format
	 * instead of String
	 * 
	 * @return the signer certificate or null if no signer certificate was set in the call.
	 * @throws CertificateException 
	 * @throws NoSuchProviderException 
	 */
	public java.security.cert.Certificate getSignerCertificate() throws CertificateException, NoSuchProviderException{

		return getCertificate(defaultCertType, defaultProvider);
	}
		
	public java.security.cert.Certificate getCertificate(String certType, String provider) throws CertificateException, NoSuchProviderException{
		if(certificateBase64 == null){
			return null;
		}

		CertificateFactory cf =  CertificateFactory.getInstance(certType, provider);
		return cf.generateCertificate(new ByteArrayInputStream(Base64.decode(certificateBase64.getBytes())));

	}
	
	/**
	 * Help method used to set the certificate in java.security.cert.Certificate from
	 * @param certificate the certificate to set.
	 * @throws CertificateEncodingException
	 */
	public void setCertificate(java.security.cert.Certificate certificate) throws CertificateEncodingException{
		if(certificate != null){
		  certificateBase64 = new String(Base64.encode(certificate.getEncoded()));
		}
	}
	
	
	
}
