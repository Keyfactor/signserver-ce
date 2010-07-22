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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlTransient;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.module.wsra.common.WSRAConstants.UserStatus;




/**
 * Entity Bean used for storing main user data used in queries.
 * other data may be in the the DataBank.
 * 
 * Information stored:
 * <pre>
 * id                        : (PrimaryKey, int) (Not Null)
 * userName                  : String (Not Null)
 * displayName               : String (Not Null)  
 * roles                     : String (Not Null) 
 * status                    : int (Not Null)
 * comment                   : String 
 * organizatinId             : int related the OrganizationDataBean
 * authdata                  : Collection<AuthDataBean> related to authData
 * tokens                    : Collection<TokenDataBean>
 * aliases                   : Collection<UserAliasDataBean>  
 * </pre>
 *
 * @author Philip Vendil
 *
 */
@Entity
@Table(name="WSRAUsers")
@NamedQueries(
		{@NamedQuery(name="UserDataBean.findByUserName",query="SELECT a from UserDataBean a WHERE a.userName=?1 AND a.organizationId=?2"),		
		 @NamedQuery(name="UserDataBean.findByRole",query="SELECT a from UserDataBean a WHERE a.rolesData LIKE ?1"),
		 @NamedQuery(name="UserDataBean.findByRoleAndOrg",query="SELECT a from UserDataBean a WHERE a.rolesData LIKE ?1 and a.organizationId=?2"),
		 @NamedQuery(name="UserDataBean.findByOrg",query="SELECT a from UserDataBean a WHERE a.organizationId=?1")
		})
public class UserDataBean {
	
	private static Logger log = Logger.getLogger(UserDataBean.class);
	
	private static final String HASH_PREFIX = "HASH:";
	private static final String CLEAR_PREFIX = "CLEAR:";
	

   @Id
   @GeneratedValue
   @Column(nullable=false)
   private int id;
   @Column(nullable=false)
   private String userName;
   @Column(nullable=false)
   private boolean clearPassword = true;
   @Column
   private String password ;
   @Column(nullable=false)
   private String displayName;
   @Column(length=64000,nullable=false)
   private String rolesData;
   @Column(length=64000)
   private String comment;
   
   @Column(nullable=false)
   private int status;
   
   @OneToMany(mappedBy="userId")
   private Collection<AuthDataBean> authData;
   
   @OneToMany(mappedBy="userId")
   private Collection<TokenDataBean> tokens;
   
   @OneToMany(mappedBy="userId")
   private Collection<UserAliasDataBean> aliases;
   
   @Column(nullable=false)
   private int organizationId;
   
   @Transient
   private Set<String> roles;

  /**
   * Default constructor when creating a new user.
   * 
   * @param userName the unique name of the user.
   * @param displayName a human readable name of the user.
   * @param roles the user is authorized to
   * @param organizationId the user belong to.
   */

   public UserDataBean(String userName, String displayName, Set<String> roles, int organizationId) {
	   super();
	   this.userName = userName;
	   this.displayName = displayName;
	   this.clearPassword = true;
	   setRoles(roles);
	   this.organizationId = organizationId;
	   setStatus(UserStatus.READYFORGENERATION);
   }
   
   /**
    * Default constructor when creating a manually
    * 
    * @param userName the unique name of the user.
    * @param displayName a human readable name of the user.
    * @param roles the user is authorized to
    */

    public UserDataBean(String userName, String displayName, Set<String> roles) {
 	   super();
 	   this.userName = userName;
 	   this.displayName = displayName;
 	   this.clearPassword = true;
 	   setRoles(roles); 	   
 	   setStatus(UserStatus.READYFORGENERATION);
    }

   /**
    * Empty Constructor
    */
   public UserDataBean() {
	   
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
	 * @return the displayName a human readable name of the user.
	 */
	@XmlElement(required=true)
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * @param displayName a human readable name of the user.
	 */
	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}
	
	

	/**
	 * @return the roles the user is authorized to, never null
	 * @see org.signserver.module.wsra.common.Roles 
	 */
	@XmlElementWrapper(name="roles",required=true)
	@XmlElements({@XmlElement(name="role")})
	public Set<String> getRoles() {		
		if(roles == null && rolesData != null){
			roles = new HashSet<String>();
			String[] allRoles = rolesData.split(",");			
			for(String role : allRoles){
				if(role.length() >0){
					roles.add(role);
				}
			}
		}
		return roles;
	}

	/**
	 * @param roles the roles to set, cannot be null
	 * @see org.signserver.module.wsra.common.Roles 
	 */
	public void setRoles(Set<String> roles) {
		String allRoles = "";
		for(String role : roles){
			allRoles += role + ",";
		}
		this.rolesData = allRoles;
		this.roles = roles;
	}

	/**
	 * @return the related authorization data connected with this user.
	 * @see org.signserver.module.wsra.beans.AuthDataBean
	 */
	@XmlElementWrapper(name="authDatas")	
	@XmlElements({@XmlElement(name="authData")})
	public Collection<AuthDataBean> getAuthData() {
		return authData;
	}

	/**
	 * @param authData the related authorization data connected with this user.
	 * @see org.signserver.module.wsra.beans.AuthDataBean
	 */
	public void setAuthData(Collection<AuthDataBean> authData) {
		this.authData = authData;
	}

	/**
	 * @return the organizationId the Id of the organization
	 */
    @XmlTransient
	public int getOrganizationId() {
		return organizationId;
	}

	/**
	 * @param organizationId the Id of the organization
	 */
	public void setOrganizationId(int organizationId) {
		this.organizationId = organizationId;
	}

	/**
	 * @return the status of the user, one of the UserStatus constants.
	 */
	@XmlTransient
	public UserStatus getStatus() {
		return UserStatus.findByIntValue(status);
	}

	/**
	 * @param status of the user, one of the UserStatus constants.
	 */
	public void setStatus(UserStatus status) {
		this.status = status.getIntValue();
	}
	
	/**
	 * @return the status of the user, one of the UserStatus constants.
	 */
	@XmlElement(name="status",required=true)
	public String getStatusText() {
		return UserStatus.findByIntValue(status).toString();
	}

	/**
	 * @param status of the user, one of the UserStatus constants.
	 */
	public void setStatusText(String statusText) {
		this.status = UserStatus.valueOf(statusText).getIntValue();
	}

	/**
	 * @return the tokens belonging to this user
	 */
	@XmlElementWrapper(name="tokens")	
	@XmlElements({@XmlElement(name="token")})
	public Collection<TokenDataBean> getTokens() {
		return tokens;
	}

	/**
	 * @param tokens belonging to this user.
	 */
	public void setTokens(Collection<TokenDataBean> tokens) {
		this.tokens = tokens;
	}

	/**
	 * @return the unique userName of the user in the organization.
	 */
	@XmlElement(required=true)
	public String getUserName() {
		return userName;
	}

	/**
	 * @param userName the unique userName of the user in the organization.
	 */
	public void setUserName(String userName) {
		this.userName = userName;
	}

	/**
	 * 
	 * @return all aliases of the user.
	 */
	@XmlElementWrapper(name="aliases")	
	@XmlElements({@XmlElement(name="alias")})
	public Collection<UserAliasDataBean> getAliases() {
		return aliases;
	}

	/**
	 * 
	 * @param aliases all aliases of the user.
	 */
	public void setAliases(Collection<UserAliasDataBean> aliases) {
		this.aliases = aliases;
	}

	/**
	 * If the password should be stored in clear text in hashFormat
	 * @return If the password should be stored in clear text in hashFormat
	 */
	@XmlElement(defaultValue="true")
	public boolean isClearPassword() {
		return clearPassword;
	}

	/**
	 * If the password should be stored in clear text in hashFormat
	 * @param clearPassword if the password should be stored in clear text in hashFormat
	 */
	public void setClearPassword(boolean clearPassword) {
		this.clearPassword = clearPassword;
	}

	/**
	 * 
	 * @return the password in either hash or clear text format
	 */
	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		if(password == null){
			this.password = null;
		}else{
			if(clearPassword){
				if(password.startsWith(CLEAR_PREFIX)){
					this.password = password;
				}else{
					this.password = CLEAR_PREFIX +password;
				}
				
			}else{
				if(password.startsWith(HASH_PREFIX)){
					this.password = password;
				}else{
					this.password = HASH_PREFIX +hash(password);
				}
			}
		}
	}
	
	public boolean checkPassword(String password){
		if(this.password.startsWith("HASH:")){
			return this.password.equals(HASH_PREFIX + hash(password));
		}else{
			return this.password.equals(CLEAR_PREFIX + password);
		}
		
	}

	private String hash(String password) {
        if (password == null) {
            return null;
        }

        String ret = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            byte[] pwdhash = md.digest(password.trim().getBytes());
            ret = new String(Hex.encode(pwdhash));
        } catch (NoSuchAlgorithmException nsae) {
            log.error("SHA1 algorithm not supported.", nsae);
        }
		return ret;
	}

}
