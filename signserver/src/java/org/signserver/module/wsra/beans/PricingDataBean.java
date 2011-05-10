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

import org.signserver.module.wsra.common.WSRAConstants.PricingStatus;




/**
 * Entity Bean used for storing information about a pricing of a product.
 * One product may have different price classes depending on deal
 * with organization.
 * other data may be in the the DataBank.
 * 
 * Information stored:
 * <pre>
 * id                        : (PrimaryKey, int) (Not Null)
 * priceClass                : String (Not Null)
 * displayName               : String (Not Null)
 * price                     : float (Not Null)
 * currency                  : String (Not Null) 
 * status                    : int (Not Null)
 * comment                   : String  
 * </pre>
 *
 * @author Philip Vendil
 *
 */
@Entity
@Table(name="WSRAPricing")
@NamedQueries(
		{@NamedQuery(name="PricingDataBean.findByPriceClass",query="SELECT a from PricingDataBean a WHERE a.priceClass=?1"),		
		 @NamedQuery(name="PricingDataBean.findByStatus",query="SELECT a from PricingDataBean a WHERE a.status=?1"),
		 @NamedQuery(name="PricingDataBean.findAll",query="SELECT a from PricingDataBean a")
		})
public class PricingDataBean {
	
	public static final String CURRENCY_NOK = "NOK";
	public static final String CURRENCY_SEK = "SEK";
	

   @Id
   @GeneratedValue
   @Column(nullable=false)   
   private int id;
   @Column(nullable=false)
   private String priceClass;
   @Column(nullable=false)
   private String displayName;
   @Column(nullable=false, precision=8, scale=2)
   private float price;
   @Column(nullable=false)
   private String currency;
   @Column(length=64000)
   private String comment;
   
   @Column(nullable=false)
   private int status;
   
   

  /**
   * Default constructor when creating a new product.
   * 
   * @param priceClass the unique number/name of this kind of price.
   * @param displayName a human readable name of the product.
   * @param price the actual price of the product.
   * @param currency the currency used for the price.
   */

   public PricingDataBean(String priceClass, String displayName, float price, String currency) {
	   super();
	   this.priceClass = priceClass;
	   this.displayName = displayName;
	   this.price = price;
	   this.currency = currency;
	   setStatus(PricingStatus.ACTIVE);
   }

   /**
    * Empty Constructor
    */
   public PricingDataBean() {
	   
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
	 * @return the displayName a human readable name of the product.
	 */
	@XmlElement(required=true)
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * @param displayName a human readable name of the product.
	 */
	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}


	/**
	 * @return the status of the product, one of the PricingStatus constants.
	 */
	@XmlTransient
	public PricingStatus getStatus() {
		return PricingStatus.findByIntValue(status);
	}

	/**
	 * @param status of the product, one of the PricingStatus constants
	 */
	public void setStatus(PricingStatus status) {
		this.status = status.getIntValue();
	}
	
	/**
	 * @return the status of the product, one of the PricingStatus constants.
	 */
	@XmlElement(name="status", required=true)
	public String getStatusText() {
		return PricingStatus.findByIntValue(status).toString();
	}

	/**
	 * @param status of the product, one of the PricingStatus constants
	 */
	public void setStatusText(String statusText) {
		this.status = PricingStatus.valueOf(statusText).getIntValue();
	}



	/**
	 * @return the unique price class of this kind of price of the product.
	 */
	@XmlElement(required=true)
	public String getPriceClass() {
		return priceClass;
	}

	/**
	 * @param priceClass the unique price class of this kind of price of the product.
	 */
	public void setPriceClass(String priceClass) {
		this.priceClass = priceClass;
	}

	/**
	 * @return the actual price for this price class.
	 */
	@XmlElement(required=true)
	public float getPrice() {
		return price;
	}

	/**
	 * @param price the actual price for this price class.
	 */
	public void setPrice(float price) {
		this.price = price;
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





}
