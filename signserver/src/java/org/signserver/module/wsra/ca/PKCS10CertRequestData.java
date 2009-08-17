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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import javax.xml.bind.annotation.XmlTransient;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.ejbca.util.CertTools;

/**
 * A Value object of ICertRequest data that
 * contains a PKCS10 request.
 * 
 * Important the certificate profile and 
 * subject alternative names data isn't
 * stored inside the pkcs10 data.s
 * 
 * 
 * @author Philip Vendil 19 okt 2008
 *
 * @version $Id$
 */

public class PKCS10CertRequestData implements ICertRequestData{
	

	private transient Logger log = Logger.getLogger(this.getClass());
	
	private String certificateProfile;
	private String subjectAltName;
	private String issuerDN;
	private String subjectDN;
	private byte[] pkcs10Data;
	
	/**
	 * Constructor used to create a new PKCS10 with the request data.
	 * 
	 * Important the subject alternative names and certificate profile is not
	 * stored inside the pkcs10 but in separate fields, these
	 * have to manually be managed by the CA connector.
	 * @throws SignatureException 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public PKCS10CertRequestData(String certificateProfile, String subjectAltName,
			                     String signatureAlgorithm, String subject, String issuer,
			                     ASN1Set attributes,
			                     PublicKey pubKey, PrivateKey privKey,
			                     String provider) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException{
		this.certificateProfile = certificateProfile;
		this.subjectAltName = subjectAltName;
		this.issuerDN = issuer;
		PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest(signatureAlgorithm,
				                                                           CertTools.stringToBcX509Name(subject),
				                                                           pubKey,
				                                                           attributes,
				                                                           privKey,
				                                                           provider);
		pkcs10Data = pkcs10.getEncoded();
	}
	
	/**
	 * Construct a PKCS10CertificateRequestData from a already
	 * existing pkcs10 data.
	 * 
	 * @param certificateProfile the certificate profile that should be used.
	 * @param subjectAltName the subject alternative name used in certificate.
	 * @param pkcs10Data DER encoded byte array.
	 * @param issuerDN the issuer that should certify
	 */
	public PKCS10CertRequestData(String certificateProfile, String subjectAltName,byte[] pkcs10Data, String issuerDN){
		this.certificateProfile = certificateProfile;
		this.issuerDN = issuerDN;
		this.subjectAltName = subjectAltName;
		this.pkcs10Data = pkcs10Data;
	}
	
	/**
	 * Empty constructor
	 */
	public PKCS10CertRequestData(){
		
	}

	/**
	 * 
	 * @see org.signserver.module.wsra.ca.ICertRequestData#getCertificateProfile()
	 */
	public String getCertificateProfile() {		
		return certificateProfile;
	}
	
	/**
	 * Manually sets the certificate profile/template
	 * @param certificateProfile the profile that should be used
	 * with this certificate.
	 */
	public void setCertificateProfile(String certificateProfile){
		this.certificateProfile = certificateProfile;
	}

	/**
	 * 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @see org.signserver.module.wsra.ca.ICertRequestData#getPublicKey()
	 */
	@XmlTransient
	public PublicKey getPublicKey() {
		if(pkcs10Data != null){
			try{
			  return getPKCS10CertificationRequest().getPublicKey();
			}catch(NoSuchAlgorithmException e){
				log.error("Error constructing public key from request : " + e.getMessage(),e);
			}catch(NoSuchProviderException e){
				log.error("Error constructing public key from request : " + e.getMessage(),e);
			}catch(InvalidKeyException e){
				log.error("Error constructing public key from request : " + e.getMessage(),e);
			}
		}
		return null;		
	}

	/**
	 * 
	 * @see org.signserver.module.wsra.ca.ICertRequestData#getSubjectAltName()
	 */
	public String getSubjectAltName() {		
		return subjectAltName;
	}
	
	/**
	 * Manually sets the subject alternative name used.
	 * 
	 * @param subjectAltName the subject alternative name.
	 */
	public void setSubjectAltName(String subjectAltName){
		this.subjectAltName = subjectAltName;
	}

	/**
	 * Returns the Subject DN, either from the manually set 
	 * subjectDN property or from the PKCS10.
	 * 
	 * @see org.signserver.module.wsra.ca.ICertRequestData#getSubjectDN()
	 */	
	public String getSubjectDN() {
		if(subjectDN != null){
			return subjectDN;
		}
		if(pkcs10Data != null){
			return getPKCS10CertificationRequest().getCertificationRequestInfo().getSubject().toString();
		}
		return null;
	}
	
	
	@XmlTransient
	public PKCS10CertificationRequest getPKCS10CertificationRequest(){
		if(pkcs10 == null){
			if(pkcs10Data != null){
			  pkcs10 = new PKCS10CertificationRequest(pkcs10Data);
			}
		}
		return pkcs10;
	}
	
	private PKCS10CertificationRequest pkcs10 = null;

	/**
	 * 
	 * @return the DER encoded pkcs10 data.
	 */
	public byte[] getPkcs10Data() {
		return pkcs10Data;
	}

	/**
	 * 
	 * @param pkcs10Data the DER encoded pkcs10 data.
	 */
	public void setPkcs10Data(byte[] pkcs10Data) {
		this.pkcs10Data = pkcs10Data;
	}

	/**
	 * 
	 * @return DN of the issuer that should certify the request
	 */
	public String getIssuerDN() {
		return CertTools.stringToBCDNString(issuerDN);
	}

	/**
	 * 
	 * @param issuerDN  of the issuer that should certify the request
	 */
	public void setIssuerDN(String issuerDN) {
		this.issuerDN = issuerDN;
	}

	/**
	 * It is possible to override the DN specified in PKCS10
	 * by setting the subject DN manually.
	 * @param subjectDN the subjectDN to set
	 */
	public void setSubjectDN(String subjectDN) {
		this.subjectDN = subjectDN;
	}
	
	

}
