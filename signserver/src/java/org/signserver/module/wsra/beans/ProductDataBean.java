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

import org.signserver.module.wsra.common.WSRAConstants.ProductStatus;




/**
 * Entity Bean used for storing information about a product.
 * other data may be in the the DataBank.
 * 
 * Information stored:
 * <pre>
 * id                        : (PrimaryKey, int) (Not Null)
 * productNumber             : String (Not Null)
 * displayName               : String (Not Null)
 * description               : String (Not Null)  
 * status                    : int (Not Null)
 * comment                   : String  
 * </pre>
 *
 * @author Philip Vendil
 *
 */
@Entity
@Table(name="WSRAProduct")
@NamedQueries(
		{@NamedQuery(name="ProductDataBean.findByProductNumber",query="SELECT a from ProductDataBean a WHERE a.productNumber=?1"),		
		 @NamedQuery(name="ProductDataBean.findByStatus",query="SELECT a from ProductDataBean a WHERE a.status=?1"),
		 @NamedQuery(name="ProductDataBean.findAll",query="SELECT a from ProductDataBean a")
		})
public class ProductDataBean {
	


   @Id
   @GeneratedValue
   @Column(nullable=false)
   private int id;
   @Column(nullable=false)
   private String productNumber;
   @Column(nullable=false)
   private String displayName;
   @Column(length=64000,nullable=false)
   private String description;
   @Column(length=64000)
   private String comment;
   
   @Column(nullable=false)
   private int status;
   
   

  /**
   * Default constructor when creating a new product.
   * 
   * @param productNumber the unique number/name of the product.
   * @param displayName a human readable name of the product.
   * @param description of the product
   */

   public ProductDataBean(String productNumber, String displayName, String description) {
	   super();
	   this.productNumber = productNumber;
	   this.displayName = displayName;
	   this.description = description;
	   setStatus(ProductStatus.SOLD);
   }

   /**
    * Empty Constructor
    */
   public ProductDataBean() {
	   
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
	 * @return the status of the product, one of the ProductStatus constants.
	 */
	@XmlTransient
	public ProductStatus getStatus() {
		return ProductStatus.findByIntValue(status);
	}

	/**
	 * @param status of the product, one of the ProductStatus constants.
	 */
	public void setStatus(ProductStatus status) {
		this.status = status.getIntValue();
	}
	
	/**
	 * @return the status of the product, one of the ProductStatus constants.
	 */
	@XmlElement(name="status", required=true)
	public String getStatusText() {
		return ProductStatus.findByIntValue(status).toString();
	}

	/**
	 * @param status of the product, one of the ProductStatus constants.
	 */
	public void setStatusText(String statusText) {
		this.status = ProductStatus.valueOf(statusText).getIntValue();
	}



	/**
	 * @return the unique productNumber of the product.
	 */
	@XmlElement(required=true)
	public String getProductNumber() {
		return productNumber;
	}

	/**
	 * @param productNumber the unique productNumber of the product.
	 */
	public void setProductNumber(String productNumber) {
		this.productNumber = productNumber;
	}

	/**
	 * @return the description of the product.
	 */
	@XmlElement(defaultValue="")
	public String getDescription() {
		return description;
	}

	/**
	 * @param description of the product.
	 */
	public void setDescription(String description) {
		this.description = description;
	}



}
