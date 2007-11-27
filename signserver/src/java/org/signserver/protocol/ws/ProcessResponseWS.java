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

import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import javax.xml.bind.annotation.XmlTransient;

import org.ejbca.util.Base64;

/**
 * WebService representation of a signature response, corresponding
 * the the existing GeneralSignatureRespose class.
 * 
 * 
 * @author Philip Vendil 28 okt 2007
 *
 * @version $Id: ProcessResponseWS.java,v 1.1 2007-11-27 06:05:07 herrvendil Exp $
 */

public class ProcessResponseWS {
	
	private int requestID;
	private String processedDataBase64;
	private Certificate signerCertificate;
	private Collection<Certificate> signerCertificateChain;
	
	/**
	 * Default constructor
	 */
	public ProcessResponseWS(){}
	
	/**
	 * Constructor using non-WS objects.
	 * @throws CertificateEncodingException 
	 */
	public ProcessResponseWS(int requestID, byte[] processedData, java.security.cert.Certificate signerCertificate,
  			Collection<java.security.cert.Certificate> signerCertificateChain) throws CertificateEncodingException{
		this.requestID = requestID;
		setProcessedData(processedData);
		setSignerCertificate(new Certificate(signerCertificate));
		
		ArrayList<Certificate> certs = new ArrayList<Certificate>();
		if(signerCertificateChain != null){
		  for (Iterator<java.security.cert.Certificate> iterator = signerCertificateChain.iterator(); iterator.hasNext();) {
			certs.add(new Certificate(iterator.next()));			
		  }
		}
	}
	
	/*
	public SignResponseWS(org.signserver.protocol.ws.gen.SignResponseWS signResponseWS){
		setRequestID(signResponseWS.getRequestID());
		setSignedData(signResponseWS.getSignedData());
		setSignerCertificate(new Certificate(signResponseWS.getSignerCertificate()));
		
		ArrayList<Certificate> certs = new ArrayList<Certificate>();
		for (Iterator<org.signserver.protocol.ws.gen.Certificate> iterator = signResponseWS.getSignerCertificateChain().iterator(); iterator.hasNext();) {
			certs.add(new Certificate(iterator.next()));			
		}		
	}*/
	
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
	 * @return the processed data in base64 encoding.
	 */
	public String getProcessedDataBase64() {
		return processedDataBase64;
	}
	
	/**
	 * @param prociessedDataBase64 the processed data in base64 encoding.
	 */
	public void setProcessedDataBase64(String processedDataBase64) {
		this.processedDataBase64 = processedDataBase64;
	}
		

	/**
	 * 
	 * @return the entire  signer certificate chain in WS format.
	 */
	public Collection<Certificate> getSignerCertificateChain() {
		return signerCertificateChain;
	}
	

	/**
	 * 
	 * @return the signer certificate  in WS format.
	 */
	public Certificate getSignerCertificate() {
		return signerCertificate;
	}

	/**
	 * 
	 * @param signerCertificate the signer certificate  in WS format.
	 */
	public void setSignerCertificate(Certificate signerCertificate) {
		this.signerCertificate = signerCertificate;
	}

	/**
	 * 
	 * @param signerCertificateChain the entire  signer certificate chain in WS format.
	 */
	public void setSignerCertificateChain(
			Collection<Certificate> signerCertificateChain) {
		this.signerCertificateChain = signerCertificateChain;
	}
	/**
	 * Help method used to set the processed data from binary form. 
	 * @param signedData the data to base64 encode
	 */
	@XmlTransient
	public void setProcessedData(byte[] processedData){
		if(processedData != null){
		  this.processedDataBase64 = new String(Base64.encode(processedData));
		}
	}
	
	/**
	 * Help method returning the processed data in bytearray form. 
	 * @param processedData the actual data
	 */
	public byte[] getProcessedData(){
		if(processedDataBase64 == null){
			return null;
		}
		return Base64.decode(processedDataBase64.getBytes());
	}

}
