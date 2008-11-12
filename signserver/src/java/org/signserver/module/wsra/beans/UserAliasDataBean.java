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
 * Entity Bean used for storing alias data used user searches.
 * 
 * An alias doesn't have to be unique.
 * 
 * Information stored:
 * <pre>
 * id                        : (PrimaryKey, int) (Not Null)
 * userId                    : int (Not Null)
 * alias                     : String (Not Null)  
 * comment                   : String 
 * </pre>
 *
 * @author Philip Vendil
 *
 */
@Entity
@Table(name="WSRAAliases")
@NamedQueries(
		{@NamedQuery(name="UserAliasDataBean.findByUserAlias",query="SELECT a FROM UserAliasDataBean a WHERE a.userId=?1 AND a.type=?2 AND a.alias=?3"),
		 @NamedQuery(name="UserAliasDataBean.findUserByAlias",query="SELECT u FROM UserDataBean u JOIN u.aliases a WHERE u.organizationId=?1 AND a.type=?2 AND a.alias=?3"),
		 @NamedQuery(name="UserAliasDataBean.findUserLikeAlias",query="SELECT u FROM UserDataBean u JOIN u.aliases a WHERE u.organizationId=?1 AND a.type=?2 AND a.alias LIKE ?3")
		})
public class UserAliasDataBean {
	

   @Id
   @GeneratedValue
   @Column(nullable=false)
   private int id;
   @Column(nullable=false)
   private int userId;
   @Column(nullable=false)
   private String type;
   @Column(nullable=false)
   private String alias;
   @Column(length=64000)
   private String comment;   

  /**
   * Default constructor when creating a new user.
   * 
   * @param type of alias
   * @param the alias of user.
   */

   public UserAliasDataBean(String type, String alias) {
	   super();
	   this.type = type;
	   this.alias = alias;
   }
   
   

   /**
    * Empty Constructor
    */
   public UserAliasDataBean() {
	   
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
	 * @return the alias of the user.
	 */
	@XmlElement(name="aliasValue", required=true)
	public String getAlias() {
		return alias;
	}

	/**
	 * @param userName the unique userName of the user in the organization.
	 */
	public void setAlias(String alias) {
		this.alias = alias;
	}
	
	/**
	 * 
	 * @return the type of alias the value is custom defined.
	 */
	@XmlElement(name="aliasType",required=true)
	public String getType() {
		return type;
	}

	/**
	 * 
	 * @param type of alias the value is custom defined.
	 */
	public void setType(String type) {
		this.type = type;
	}

	/**
	 * 
	 * @return the user id of the user.
	 */
	@XmlTransient
	public int getUserId() {
		return userId;
	}

	/**
	 * 
	 * @param userId user id of the user.
	 */
	public void setUserId(int userId) {
		this.userId = userId;
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



}
