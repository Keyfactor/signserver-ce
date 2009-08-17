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

import java.util.Collection;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlTransient;

/**
 * Entity Bean used for data about a token (soft or hard).
 * 
 * Information stored:
 * <pre>
 * id                        : (PrimaryKey, int) (Not Null)
 * serialNumber              : String
 * organizationId            : int relation to organization using organizationId
 * profile                   : unique identifier of type of token. 
 * userId                    : int relation to userId
 * certificates              : Collection<CertificateDataBean> relation to certificate data table.
 * sensitiveData             : byte[] (BLOB)
 * copyOf                    : int another TokenDataBean.id used for key recovery.
 * comment                   : String 
 * </pre>
 *
 * @author Philip Vendil
 *
 */
@Entity
@Table(name="WSRATokens")
@NamedQueries(
		{@NamedQuery(name="TokenDataBean.findBySerialNumber",query="SELECT a from TokenDataBean a WHERE a.organizationId=?1 AND a.serialNumber=?2"),
		 @NamedQuery(name="TokenDataBean.findCopies",query="SELECT a from TokenDataBean a WHERE a.copyOf=?1")
		})
public class TokenDataBean {

   @Id
   @GeneratedValue
   @Column(nullable=false)
   private int id;
   @Column(nullable=false)
   private int organizationId;
   @Column(nullable=false)
   private int userId;
   @Column
   private int copyOf;
   @Column(nullable=false)
   private String profile;
   @Column(nullable=false)
   private String serialNumber;
   @Lob
   @Column(length=64000)
   private byte[] sensitiveData;
   @Column(length=64000)
   private String comment;
   
   
   @OneToMany(mappedBy="tokenId")
   private Collection<CertificateDataBean> certificates;
   
   /**
    * Empty Constructor
    */
   public TokenDataBean() {
	   
   }
   
    /**
     * Constructor used when creating a new TokenData bean.
     * 
     * @param organizationId the organization owning this token
     * @param userId the user owning this token
     * @param profile profile a class path to a class that implements
	 * the ITokenProfile interface.
     * @param serialNumber of the token
     */  
   public TokenDataBean(int organizationId, int userId, String profile,
		   String serialNumber) {
	   super();
	   this.organizationId = organizationId;
	   this.userId = userId;
	   this.profile = profile;
	   this.serialNumber = serialNumber;
   }
   
   /**
    * Constructor used when creating a new TokenData bean
    * manually through jaxb
    * 
    * @param profile profile a class path to a class that implements
	 * the ITokenProfile interface.
    * @param serialNumber of the token
    */  
  public TokenDataBean(String profile,
		   String serialNumber) {
	   super();
	   this.profile = profile;
	   this.serialNumber = serialNumber;
  }

	/**
	 * @return the unique id of the token.
	 */	
    @XmlTransient
    public  int getId(){
    	return id;
    }

	/**
	 * @param id the unique id of the token.
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
	 * @return the organizationId of the organization owning this token.
	 */
	@XmlTransient
	public int getOrganizationId() {
		return organizationId;
	}

	/**
	 * @param organizationId of the organization owning this token.
	 */
	public void setOrganizationId(int organizationId) {
		this.organizationId = organizationId;
	}

	/**
	 * @return the id of the user owning this token.
	 */
	@XmlTransient
	public int getUserId() {
		return userId;
	}

	/**
	 * @param userId the id of the user owning this token.
	 */
	public void setUserId(int userId) {
		this.userId = userId;
	}

	/**
	 * @return the copyOf the id of token this token is a copy of
	 * (set after a key recovery action have been performed).
	 */
	@XmlTransient
	public int getCopyOf() {
		return copyOf;
	}

	/**
	 * @param copyOf the id of token this token is a copy of
	 * (set after a key recovery action have been performed).
	 */
	public void setCopyOf(int copyOf) {
		this.copyOf = copyOf;
	}

	/**
	 * @return a class path to a class that implements
	 * the ITokenProfile interface.
	 */
	@XmlElement(required=true)
	public String getProfile() {
		return profile;
	}

	/**
	 * @param profile a class path to a class that implements
	 * the ITokenProfile interface.
	 * TODO
	 */
	public void setProfile(String profile) {
		this.profile = profile;
	}

	/**
	 * @return the serialNumber of the token, should
	 * be unique together with organizationId.
	 */
	@XmlElement(required=true)
	public String getSerialNumber() {
		return serialNumber;
	}

	/**
	 * @param serialNumber the serialNumber of the token, should
	 * be unique together with organizationId.
	 */
	public void setSerialNumber(String serialNumber) {
		this.serialNumber = serialNumber;
	}

	/**
	 * The data returned in this call is only readable if
	 * the token data was read through the TokenManager#getToken(int, String,boolean)
	 * with include sensitive data set to true.
	 * 
	 * @return the sensitiveData this data
	 * might be encrypted
	 */
	public byte[] getSensitiveData() {
		return sensitiveData;
	}

	/**
	 * @param sensitiveData the sensitiveData to set, this data
	 * might be encrypted
	 */
	public void setSensitiveData(byte[] sensitiveData) {
		this.sensitiveData = sensitiveData;
	}

	/**
	 * @return the certificates belonging to this token.
	 */
	@XmlElementWrapper(name="certificates")	
	@XmlElements({@XmlElement(name="certificate")})
	public Collection<CertificateDataBean> getCertificates() {
		return certificates;
	}

	/**
	 * @param certificates the certificates belonging to this token.
	 */
	public void setCertificates(Collection<CertificateDataBean> certificates) {
		this.certificates = certificates;
	}

}
