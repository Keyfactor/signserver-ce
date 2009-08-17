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
 
package org.signserver.module.wsra.ca;

import java.security.PublicKey;

import javax.xml.bind.annotation.XmlTransient;


/**
 * Plain certificate request data used for data import
 * and for server generated key stores.
 * 
 * It contains no public key.
 * 
 * 
 * @author Philip Vendil 24 okt 2008
 *
 * @version $Id$
 */

public class UserCertRequestData implements ICertRequestData {
	
	private String name;
	private String certificateProfile;
	private String subjectAltName;
	private String subjectDN;
	private String issuerDN;
	private String keyAlg;
	private String keySpec;
	private PublicKey publicKey;

	/**
	 * Main constructor with specification on server generated keys.
	 * 
	 * @param name of request, can be used for alias in soft tokens or similar.
	 * @param certificateProfile The certificate profile that should be used.
	 * @param subjectAltName The subject alternative name used.
	 * @param subjectDN The subject distinguished name used.
	 * @param issuerDN The issuer distinguished name used.
	 * @param keyAlg key algorithm on generated keys
	 * @param keySpec specification of keyon generated keys
	 */
	public UserCertRequestData(String name, String certificateProfile,
			String subjectAltName, String subjectDN, String issuerDN, String keyAlg, String keySpec) {
		super();
		this.name = name;
		this.certificateProfile = certificateProfile;
		this.subjectAltName = subjectAltName;
		this.subjectDN = subjectDN;
		this.issuerDN = issuerDN;
		this.keyAlg = keyAlg;
		this.keySpec = keySpec;
	}
	
	
	/**
	 * Main constructor
	 * 
	 * @param name of request, can be used for alias in soft tokens or similar.
	 * @param certificateProfile The certificate profile that should be used.
	 * @param subjectAltName The subject alternative name used.
	 * @param subjectDN The subject distinguished name used.
	 * @param issuerDN The issuer distinguished name used.
	 */
	public UserCertRequestData(String name, String certificateProfile,
			String subjectAltName, String subjectDN, String issuerDN) {
		this(name, certificateProfile, subjectAltName, subjectDN, issuerDN, null, null);
		
	}

	public UserCertRequestData(){}
	
	
	/**
	 * The certificate profile that should be used.
	 */
	public String getCertificateProfile() {
		return certificateProfile;
	}
	
	/**
	 * The certificate profile that should be used.
	 */
	public void setCertificateProfile(String certificateProfile) {
		this.certificateProfile = certificateProfile;
	}

	/**
	 * public key, set separately
	 */
	@XmlTransient
	public PublicKey getPublicKey() {
		return publicKey;
	}
	
	/**
	 * public key, set separately
	 */
	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	/**
	 * The subject alternative name used.
	 */
	public String getSubjectAltName() {
		return subjectAltName;
	}

	/**
	 * The subjct alternative name used.
	 */
	public void setSubjectAltName(String subjectAltName) {
		this.subjectAltName = subjectAltName;
	}

	/**
	 * The subject distinguished name used.
	 */
	public String getSubjectDN() {
		return subjectDN;
	}

	/**
	 * The subject distinguished name used.
	 */
	public void setSubjectDN(String subjectDN) {
		this.subjectDN = subjectDN;
	}

	/**
	 * The issuer distinguished name used.
	 */
	public String getIssuerDN() {
		return issuerDN;
	}
	
	/**
	 * The issuer distinguished name used.
	 */
	public void setIssuerDN(String issuerDN) {
		this.issuerDN = issuerDN;
	}

	/**
	 * 
	 * @return name of request, can be used for alias in soft tokens or similar.
	 */
	public String getName() {
		return name;
	}

	/**
	 * 
	 * @param name name of request, can be used for alias in soft tokens or similar.
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * Used for server generated keys
	 * @return the keyAlg
	 */
	public String getKeyAlg() {
		return keyAlg;
	}

	/**
	 * Used for server generated keys
	 * @param keyAlg the keyAlg to set
	 */
	public void setKeyAlg(String keyAlg) {
		this.keyAlg = keyAlg;
	}

	/**
	 * Used for server generated keys
	 * @return the keySpec
	 */
	public String getKeySpec() {
		return keySpec;
	}

	/**
	 * Used for server generated keys
	 * @param keySpec the keySpec to set
	 */
	public void setKeySpec(String keySpec) {
		this.keySpec = keySpec;
	}




}
