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
 

package org.signserver.module.wsra.beans;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlTransient;

import org.apache.log4j.Logger;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.signserver.module.wsra.common.WSRAConstants;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.X509Certificate;




/**
 * Entity Bean used for storing main user data used in queries.
 * other data may be in the the DataBank.
 * 
 * Information stored:
 * <pre>
 * id                        : (PrimaryKey, int) (Not Null)
 * fingerprint               : String (Not Null) (unique)
 * organizationId            : int link to OrganizationDataBean
 * tokenId                   : int link to TokenDataBean
 * type                      : String (Not Null)
 * profile                   : String (Not Null)
 * issuerDN                  : String (Not Null)
 * subjectDN                 : String (Not Null)
 * status                    : int (Not Null)
 * expireDate                : long (Not Null)
 * certificateData           : byte[] LOB  (Not Null)
 * comment                   : String 
 * </pre>
 *
 * @author Philip Vendil
 *
 */
@Entity
@Table(name="WSRACertificates")
@NamedQueries(
		{@NamedQuery(name="CertificateDataBean.findByFingerprint",query="SELECT a from CertificateDataBean a WHERE a.fingerprint=?1 "),
		 @NamedQuery(name="CertificateDataBean.findByIssuerAndSubject",query="SELECT a from CertificateDataBean a WHERE a.issuerDN=?1 AND a.subjectDN=?2"),
		 @NamedQuery(name="CertificateDataBean.findByIssuerAndSerial",query="SELECT a from CertificateDataBean a WHERE a.issuerDN=?1 AND a.serialNumber=?2")
		})
public class CertificateDataBean {

	
   @Transient
   private Logger log = Logger.getLogger(this.getClass());

   @Id
   @GeneratedValue
   @Column(nullable=false)   
   private int id;
   @Column(nullable=false)
   private String fingerprint;
   @Column(nullable=false)
   private int tokenId;
   @Column(nullable=false)
   private int type;
   @Column(nullable=false)
   private String profile;
   @Column(nullable=false)
   private String issuerDN;
   @Column(nullable=false)
   private String subjectDN;
   @Column(nullable=false)
   private String serialNumber;
   @Column(nullable=false)
   private long expireDate;
   @Lob
   @Column(length=64000)
   private byte[] certificateData;
   @Column(length=64000)
   private String comment;   
   @Column(nullable=false)
   private int status;   
   
   /**
    * Empty Constructor
    */
   public CertificateDataBean() {
	   
   }
  
   /**
    * Constructor used when creating a new certificate data.
    * 
    * @param certificate the certificate to store.
    * @param tokenId which token that owns this certificate
    * @param profile What profile of certificate, this is a string value that can be 
    * custom defined to later generate reports, could be
    * "VPNCERT", "SIGNCERT" etc.
    * @param organizationId  which organization that owns this certificate
    * @throws CertificateEncodingException if parsing of certificate failed.
    */   
   public CertificateDataBean(ICertificate certificate, int tokenId, String profile) throws CertificateEncodingException {
	   super();
	   if(certificate instanceof X509Certificate){		   
		   X509Certificate cert = (X509Certificate) certificate;
		   setFingerprint(CertTools.getFingerprintAsString(cert));
		   setIssuerDN(cert.getIssuerDN().toString());
		   setSubjectDN(cert.getSubjectDN().toString());
		   setSerialNumber(cert.getSerialNumber().toString());
		   setExpireDate(cert.getNotAfter());
		   setCertificateData(cert.getEncoded());
           setStatus(WSRAConstants.CERTSTATUS_ACTIVE);		 
           setType(WSRAConstants.CERTTYPE_X509);
	   }else{
		   log.error("Error storing certificate data, certificate structure isn't supported : " + certificate.getClass().getName());
	   }
	   
	   this.tokenId = tokenId;
	   this.profile = profile;
   }
   
   /**
    * Constructor used when creating a new certificate data manually 
    * using jaxb
    * 
    * @param certificate the certificate to store.
    * @param profile What profile of certificate, this is a string value that can be 
    * custom defined to later generate reports, could be
    * "VPNCERT", "SIGNCERT" etc.
    * @param organizationId  which organization that owns this certificate
    * @throws CertificateEncodingException if parsing of certificate failed.
    */   
   public CertificateDataBean(java.security.cert.Certificate certificate, String profile) throws CertificateEncodingException {
	   super();
	   if(certificate instanceof java.security.cert.X509Certificate){		   
		   java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) certificate;
		   setFingerprint(CertTools.getFingerprintAsString(cert));
		   setIssuerDN(cert.getIssuerDN().toString());
		   setSubjectDN(cert.getSubjectDN().toString());
		   setSerialNumber(cert.getSerialNumber().toString());
		   setExpireDate(cert.getNotAfter());
		   setCertificateData(cert.getEncoded());
           setStatus(WSRAConstants.CERTSTATUS_ACTIVE);		 
           setType(WSRAConstants.CERTTYPE_X509);
	   }else{
		   log.error("Error storing certificate data, certificate structure isn't supported : " + certificate.getClass().getName());
	   }
	   
	   this.profile = profile;
   }
   
   /**
    * Help method used to fetch the actual certificate 
    * from the store byte array.
    * @return the certificate, never null.
    * @throws CertificateException if certificate couldn't be decoded properly.
    * @throws IOException if certificate couldn't be decoded properly.
    */
   @XmlTransient
   public ICertificate getCertificate() throws CertificateException, IOException{
	   ICertificate retval = null;
	   if(getType() == WSRAConstants.CERTTYPE_X509){
		   retval = X509Certificate.getInstance((java.security.cert.X509Certificate) CertTools.getCertfromByteArray(getCertificateData()));
	   }
	   
	   if(retval == null){
		   throw new CertificateException("Error decoding certificate, doesn't seem to be a supported certificate structure.");
	   }
	   
	   return retval;
   }
   

	/**
	 * @return the unique id of the user.
	 */	
    @XmlTransient
    public  int getId(){
    	return id;
    }

	/**
	 * @param id the unique id of the user.
	 */
	public void setId(int id) {
		this.id = id;
	}



	/**
	 * @return The comment on this user data entry
	 */
	public String getComment() {
		return comment;
	}


	/**
	 * @param comment The comment on this user data entry
	 */
	public void setComment(String comment) {
		this.comment = comment;
	}

    /**
     * DN of issuer of certificate
     *
     * @return issuer dn
     */
	@XmlElement(required=true)
    public String getIssuerDN(){
    	return issuerDN;
    }

    /**
     * DN of issuer of certificate
     *
     * @param issuerDN issuer dn
     */
    public void setIssuerDN(String issuerDN){
    	this.issuerDN = CertTools.stringToBCDNString(issuerDN);
    }

    /**
     * Subject DN of owner of certificate
     *
     * @return subject dn
     */
    @XmlElement(required=true)
    public String getSubjectDN(){
    	return subjectDN;
    }

    /**
     * Subject DN of owner of certificate
     *
     * @param subject issuer dn
     */
    public void setSubjectDN(String subjectDN){
    	this.subjectDN = CertTools.stringToBCDNString(subjectDN);
    }

    /**    
     * @return Fingerprint of certificate
     */
    @XmlElement(required=true)
    public String getFingerprint(){
    	return fingerprint;
    }

    /**
     *
     * @param fingerprint Fingerprint of certificate
     */
    public void setFingerprint(String fingerprint){
    	this.fingerprint = fingerprint;
    }


    /**
     * @return status of certificate, ex CertificateDataBean.CERT_ACTIVE
     * 
     */
    @XmlElement(required=true)
    public int getStatus(){
    	return status;
    }

    /**
     * @param status status of certificate, ex CertificateDataBean.CERT_ACTIVE
     */
    public void setStatus(int status){
    	this.status = status;
    }

    /**
     * What profile of certificate, this is a string value that can be 
     * custom defined to later generate reports, could be
     * "VPNCERT", "SIGNCERT" etc.
     *
     * @return profile of certificate
     */
    @XmlElement(required=true)
    public String getProfile(){
    	return profile;
    }

    /**
     * What profile of certificate, this is a string value that can be 
     * custom defined to later generate reports, could be
     * "VPNCERT", "SIGNCERT" etc.
     * 
     * @param profile of certificate
     */
    public void setProfile(String profile){
    	this.profile = profile;
    }

    /**
     * Serial number of certificate formated as BigInteger.toString()
     *
     * @return serial number of certificate
     */
    @XmlElement(required=true)
    public String getSerialNumber(){
    	return serialNumber;
    }

    /**
     * Serial number formated as BigInteger.toString()
     *
     * @param serialNumber serial number of certificate
     */
    public void setSerialNumber(String serialNumber){
    	this.serialNumber = serialNumber;
    }

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     *
     * @return expire date of certificate
     */
    @XmlElement(required=true)
    public Date getExpireDate(){
    	return new Date(expireDate);
    }

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     *
     * @param expireDate expire date of certificate
     */
    public void setExpireDate(Date expireDate){
    	this.expireDate = expireDate.getTime();
    }

    /**
     * certificate in binary encoding. (Stored in Base64)
     *
     * @return binary certificate data
     */
    @XmlElement(required=true)
    public byte[] getCertificateData(){
    	return Base64.decode(certificateData);
    }

    /**
     * certificate in binary encoding. (Stored in Base64)
     *
     * @param certificateData binary value of certificate data
     */
    public void setCertificateData(byte[] certificateData){
    	this.certificateData = Base64.encode(certificateData);
    }

	/**
	 * @return the tokenId this certificate belongs to.
	 * 
	 */
    @XmlTransient
	public int getTokenId() {
		return tokenId;
	}

	/**
	 * @param tokenId this certificate belongs to. 0 means no token.
	 */
	public void setTokenId(int tokenId) {
		this.tokenId = tokenId;
	}

	/**
	 * @return the type of certificate (X509 ...) of of CertificateDataBean.TYPE_ constants.
	 */
	@XmlElement(required=true)
	public int getType() {
		return type;
	}

	/**
	 * @param type the type of certificate (X509 ...) of of CertificateDataBean.TYPE_ constants.
	 */
	public void setType(int type) {
		this.type = type;
	}
}
