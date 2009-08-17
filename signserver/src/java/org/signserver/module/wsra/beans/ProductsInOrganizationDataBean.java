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
 * Entity Bean used for the relation be between an 
 * organization and product and the price class it
 * have in that organization
 * 
 * Information stored:
 * <pre>
 * id                        : (PrimaryKey, int) (Not Null)
 * organizationId            : int (Not Null)
 * priceId                   : int (Not Null)
 * productId                 : int (Not Null)
 * currency                  : String (Not Null)
 * comment                   : String  
 * </pre>
 *
 * @author Philip Vendil
 *
 */
@Entity
@Table(name="WSRAProdInOrg")
@NamedQueries(
		{@NamedQuery(name="ProductsInOrganizationDataBean.findByOrganizationAndProduct",query="SELECT a from ProductsInOrganizationDataBean a WHERE a.organizationId=?1 AND productId=?2"),
		 @NamedQuery(name="ProductsInOrganizationDataBean.findByOrganization",query="SELECT a from ProductsInOrganizationDataBean a WHERE a.organizationId=?1")
		})
public class ProductsInOrganizationDataBean {
	

   @Id
   @GeneratedValue
   @Column(nullable=false)
   private int id;
   @Column(nullable=false)
   private int organizationId;
   @Column(nullable=false)
   private int priceId;
   @Column(nullable=false)
   private int productId;
   @Column(nullable=false)
   private String currency;
   @Column(length=64000)
   private String comment;
   
   private String productNumber;
   private String priceClass;
   
   /**
    * 
    * @param organizationId of the organization 
    * @param productId of the product
    * @param priceId of the price class
    * @param currency can be one one of PricingDataBean.CURRENCY_ constants
    */
   public ProductsInOrganizationDataBean(int organizationId, int productId, int priceId, String currency) {
	   super();
	   this.organizationId = organizationId;
	   this.priceId = priceId;
	   this.productId = productId;
	   this.currency = currency;
   }
   
   /**
    * Constructor used to create product in organization relation
    * manually 
    * @param productNumber of the product
    * @param priceClass of the price class
    * @param currency can be one one of PricingDataBean.CURRENCY_ constants
    */
   public ProductsInOrganizationDataBean(String productNumber, String priceClass, String currency) {
	   super();
	   this.productNumber = productNumber;
	   this.priceClass = priceClass;
	   this.currency = currency;
   }
   /**
    * Empty Constructor
    */
   public ProductsInOrganizationDataBean() {
	   
   }

	/**
	 * @return the unique id of the product.
	 */	
   @XmlTransient
    public  int getId(){
    	return id;
    }

	/**
	 * @param id the unique id of the product.
	 */
	public void setId(int id) {
		this.id = id;
	}



	/**
	 * @return The comment on this product data entry
	 */
	public String getComment() {
		return comment;
	}


	/**
	 * @param comment The comment on this product data entry
	 */
	public void setComment(String comment) {
		this.comment = comment;
	}


	/**
	 * @return the currency that is used in this price, 
	 * can be one of PricingDataBean.CURRENCY_ constants. 
	 */
	@XmlElement(required=true)
	public String getCurrency() {
		return currency;
	}

	/**
	 * @param currency the currency that is used in this price, 
	 * can be one of PricingDataBean.CURRENCY_ constants.
	 */
	public void setCurrency(String currency) {
		this.currency = currency;
	}

	/**
	 * @return the organizationId
	 */
	@XmlTransient
	public int getOrganizationId() {
		return organizationId;
	}

	/**
	 * @param organizationId the organizationId to set
	 */
	public void setOrganizationId(int organizationId) {
		this.organizationId = organizationId;
	}

	/**
	 * @return the priceId
	 */
	@XmlTransient
	public int getPriceId() {
		return priceId;
	}

	/**
	 * @param priceId the priceId to set
	 */
	public void setPriceId(int priceId) {
		this.priceId = priceId;
	}

	/**
	 * @return the productId
	 */
	@XmlTransient
	public int getProductId() {
		return productId;
	}

	/**
	 * @param productId the productId to set
	 */
	public void setProductId(int productId) {
		this.productId = productId;
	}

	/**
	 * Not stored in database
	 * @return the productNumber
	 */
	@XmlElement(required=true)
	public String getProductNumber() {
		return productNumber;
	}

	/**
	 * Not stored in database
	 * @param productNumber the productName to set
	 */
	public void setProductNumber(String productNumber) {
		this.productNumber = productNumber;
	}

	/**
	 * Not stored in database
	 * @return the priceClass
	 */
	@XmlElement(required=true)
	public String getPriceClass() {
		return priceClass;
	}

	/**
	 * Not stored in database
	 * @param priceClass the priceClass to set
	 */
	public void setPriceClass(String priceClass) {
		this.priceClass = priceClass;
	}



}
