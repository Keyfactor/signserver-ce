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

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlTransient;




/**
 * Entity Bean used for storing authorization data and
 * connecting that data to a user.
 * 
 * Information stored: (authType and authValue should be unique)
 * <pre>
 * id                        : (PrimaryKey, int) (Not Null)
 * authType                  : int (Not Null)  
 * authValue                 : String (Not Null)
 * userId                    : id (Not Null) link to UserDataBean 
 * comment                   : String 
 * </pre>
 *
 * @author Philip Vendil
 *
 */
@Entity
@Table(name="WSRAAuthData")
@NamedQueries(
		{@NamedQuery(name="AuthDataBean.findByAuthData",query="SELECT a from AuthDataBean a WHERE a.authType=?1 AND a.authValue=?2"),
		 @NamedQuery(name="AuthDataBean.findByUserId",query="SELECT a from AuthDataBean a WHERE a.userId LIKE ?1")
		})
public class AuthDataBean {

   @Id
   @GeneratedValue
   @Column(nullable=false)
   private int id;
   @Column(nullable=false)
   private int authType;
   @Column(length=64000,nullable=false)
   private String authValue;
   @Column(nullable=false)
   private int userId;
   @Column(length=64000)
   private String comment;
   
   /**
    * Empty Constructor
    */
   public AuthDataBean() {
	   
   }
   
   /**
    * Constructor when creating a new AuthType
    * 
    * @param authType one of the AUTHTYPE_ constants specifying 
	* the type of authentication. 
    * @param authValue the data used to check the authentication.
    * @param userId of the user this authentication data relates to.
    */
   public AuthDataBean(int authType, String authData, int userId) {
	   super();
	   this.authType = authType;
	   this.authValue = authData;
	   this.userId = userId;
   }
   
   /**
    * Constructor when creating a new AuthType manually using
    * Jaxb.
    * 
    * @param authType one of the AUTHTYPE_ constants specifying 
	* the type of authentication. 
    * @param authValue the data used to check the authentication.
    */
   public AuthDataBean(int authType, String authData) {
	   super();
	   this.authType = authType;
	   this.authValue = authData;
   }

	/**
	 * @return the unique id of the authorization data.
	 */	
    @XmlTransient
    public  int getId(){
    	return id;
    }

	/**
	 * @param id the unique id of authorization data.
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
	 * @return one of the  specifying 
	 * the type of authentication. 
	 */
	@XmlElement(required=true)
	public int getAuthType() {
		return authType;
	}

	/**
	 * @param authType  specifying 
	 * the type of authentication. 
	 */
	public void setAuthType(int authType) {
		this.authType = authType;
	}

	/**
	 * @return the value used to check the authentication.
	 */
	@XmlElement(required=true)
	public String getAuthValue() {
		return authValue;
	}

	/**
	 * @param authValue the data used to check the authentication.
	 */
	public void setAuthValue(String authValue) {
		this.authValue = authValue;
	}

	/**
	 * @return the userId this authorization data is connected to.
	 * @see org.signserver.module.wsra.beans.UserDataBean
	 */
	@XmlTransient
	public int getUserId() {
		return userId;
	}

	/**
	 * @param userId the userId this authorization data is connected to.
	 * @see org.signserver.module.wsra.beans.UserDataBean
	 */
	public void setUserId(int userId) {
		this.userId = userId;
	}



}
