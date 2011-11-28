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
 * Entity Bean used for storing different kinds of data, this
 * could be configuration or statistics, or other data related
 * to the different areas of the WSRA, it is used to avoid 
 * table restrictions and for data that doesn't need any
 * speedy queries (such as invoce address, etc)
 * 
 * Information stored:
 * <pre>
 * id                        : (PrimaryKey, int) (Not Null)
 * type                      : int (not null)  
 * relatedId                 : related id of foreign object, could be organizationId or other depending on type
 * theKey                       : String (not null)
 * theValue                     : String
 * theComment                   : String
 * </pre>
 *
 * @author Philip Vendil
 *
 */
@Entity
@Table(name="WSRADataBank")
@NamedQueries(
		{@NamedQuery(name="DataBankDataBean.findByKey",query="SELECT a from DataBankDataBean a WHERE a.type=?1 AND a.theKey=?2"),
		 @NamedQuery(name="DataBankDataBean.findByType",query="SELECT a from DataBankDataBean a WHERE a.type=?1 "),
		 @NamedQuery(name="DataBankDataBean.findByTypeAndRelatedId",query="SELECT a from DataBankDataBean a WHERE a.type=?1 AND a.relatedId=?2"),
		 @NamedQuery(name="DataBankDataBean.findByTypeAndRelatedIdAndKey",query="SELECT a from DataBankDataBean a WHERE a.type=?1 AND a.relatedId=?2 AND a.theKey=?3"),
		 @NamedQuery(name="DataBankDataBean.findAll",query="SELECT a from DataBankDataBean a")
		})
public class DataBankDataBean {
	


   @Id
   @GeneratedValue
   @Column(nullable=false)   
   private int id;
   @Column(nullable=false)
   private int type;
   @Column(nullable=false)
   private int relatedId;
   @Column(nullable=false)
   private String theKey;
   @Column(length=64000)
   private String theValue;
   @Column(length=64000)
   private String theComment;
   
   /**
    * Empty Constructor
    */
   public DataBankDataBean() {
	   
   }
   
   /**
    * Constructor used when creating a new DataBankDataBean.
    * @param type one of the DataBankDataBean.TYPE_ parameters 
    * @param key the key of the current data, can be custom specified.
    * @param value the value of this data
    */
   public DataBankDataBean(int type, String key, String value) {
	   super();
	   this.type = type;
	   this.relatedId = 0;
	   this.theKey = key;
	   this.theValue = value;
   }
   
   /**
    * Constructor used when creating a new DataBankDataBean.
    * @param type one of the DataBankDataBean.TYPE_ parameters
    * @param relatedId id of foreign object, could be organizationId depending on type.
    * @param key the key of the current data, can be custom specified.
    * @param value the value of this data
    */
   public DataBankDataBean(int type, int relatedId, String key, String value) {
	   super();
	   this.type = type;
	   this.relatedId = relatedId;
	   this.theKey = key;
	   this.theValue = value;
   }
   
   /**
    * Constructor used when creating a new DataBankDataBean
    * manually through Jaxb.
    * 
    * @param key the key of the current data, can be custom specified.
    * @param value the value of this data
    */
   public DataBankDataBean(String key, String value) {
	   super();
	   this.theKey = key;
	   this.theValue = value;
   }

	/**
	 * @return the unique id of this key-data relation.
	 */	
    @XmlTransient
    public  int getId(){
    	return id;
    }

	/**
	 * @param id the unique id of this key-data relation.
	 */
	public void setId(int id) {
		this.id = id;
	}

	/**
	 * @return the type one of the DataBankDataBean.TYPE_ parameters
	 */
	@XmlElement(required=true)
	public int getType() {
		return type;
	}

	/**
	 * @param type one of the DataBankDataBean.TYPE_ parameters 
	 */
	public void setType(int type) {
		this.type = type;
	}

	/**
	 * @return the key of the current data, can be custom specified.
	 */
	@XmlElement(required=true)
	public String getKey() {
		return theKey;
	}

	/**
	 * @param key the key to set, can be custom specified.
	 */
	public void setKey(String key) {
		this.theKey = key;
	}

	/**
	 * @return the value of this data
	 */
	@XmlElement(required=true)
	public String getValue() {
		return theValue;
	}

	/**
	 * @param value the value to set
	 */
	public void setValue(String value) {
		this.theValue = value;
	}

	/**
	 * @return The comment on this user data entry
	 */
	public String getComment() {
		return theComment;
	}


	/**
	 * @param comment The comment on this user data entry
	 */
	public void setComment(String comment) {
		this.theComment = comment;
	}

	/**
	 * 
	 * @return id of foreign object, could be organizationId depending on type.
	 */
	@XmlTransient
	public int getRelatedId() {
		return relatedId;
	}

	/**
	 * 
	 * @param relatedId id of foreign object, could be organizationId depending on type.
	 */
	public void setRelatedId(int relatedId) {
		this.relatedId = relatedId;
	}

}
