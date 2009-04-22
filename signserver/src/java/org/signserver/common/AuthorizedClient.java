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

import org.ejbca.util.CertTools;



/**
 * Class representing an authorized client containing the  serial number and issuerDN of trusted client certs.
 * @author Philip Vendil
 * 
 * $Id$
 *
 */
public class AuthorizedClient implements Comparable<Object>, Serializable{
	
	private static final long serialVersionUID = 1L;
	String certSN = null;
	String issuerDN = null;
	
	public AuthorizedClient(){}
	
	public void setCertSN(String certSN) {
		this.certSN = certSN;
	}

	public void setIssuerDN(String issuerDN) {
		this.issuerDN = CertTools.stringToBCDNString(issuerDN);
	}

	public AuthorizedClient(String certSN, String issuerDN){
      this.certSN = certSN;
      setIssuerDN(issuerDN);      
	}

	/**
	 * Sort by Cert SN
	 * @param arg0 must be a AuthorizedClient
	 */
	public int compareTo(Object arg0) {
		if(arg0 instanceof AuthorizedClient){
			return certSN.compareTo(((AuthorizedClient) arg0).getCertSN()); 
		}
		return 0;
	}

	public String getCertSN() {
		return certSN;
	}

	public String getIssuerDN() {
		return issuerDN;
	}

	public int hashCode() {		
		return certSN.hashCode() + issuerDN.hashCode();
	}

	public boolean equals(Object obj) {		
		return certSN.equals(((AuthorizedClient) obj).getCertSN()) && issuerDN.equals(((AuthorizedClient) obj).getIssuerDN()); 
	}
}