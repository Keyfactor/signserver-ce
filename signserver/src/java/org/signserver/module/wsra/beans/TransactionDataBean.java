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

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlTransient;

import org.signserver.module.wsra.common.WSRAConstants;


/**
 * Entity Bean used for specify the data used in one
 * transaction (this could be an organization buying a
 * set of products).
 * 
 * Information stored:
 * <pre>
 * id                        : (PrimaryKey, int) (Not Null)
 * organizationId            : int (Not Null)
 * productId                 : int (Not Null)
 * units                     : int (Not Null)
 * transactionDate           : long (Not Null)
 * expectedLifeDate          : long (Not Null)
 * status                    : int (Not Null)
 * nodeId                    : int (Not Null) should be '0' if not belonging to any node
 * comment                   : String  
 * </pre>
 *
 * @author Philip Vendil
 *
 */
@Entity
@Table(name="WSRATrans")
@NamedQueries(
		{@NamedQuery(name="TransactionDataBean.findTransactionByTime",query="SELECT a from TransactionDataBean a WHERE a.transactionDate>=?1 AND a.transactionDate<=?2 ORDER BY a.organizationId"),		
		 @NamedQuery(name="TransactionDataBean.findActiveTransaction",query="SELECT a from TransactionDataBean a WHERE a.transactionDate<=?1 AND a.expectedLifeDate>=?1"),
		 @NamedQuery(name="TransactionDataBean.findTransactionByTimeAndStatus",query="SELECT a from TransactionDataBean a WHERE a.transactionDate>=?1 AND a.transactionDate<=?2 AND a.status=?3 ORDER BY a.organizationId"),		
		 @NamedQuery(name="TransactionDataBean.findActiveTransactionAndStatus",query="SELECT a from TransactionDataBean a WHERE a.transactionDate<=?1 AND a.expectedLifeDate>=?1 AND a.status=?2"),
		 @NamedQuery(name="TransactionDataBean.findByNodeAndStatus",query="SELECT a from TransactionDataBean a WHERE a.nodeId=?1 AND a.transactionDate>=?2 AND a.transactionDate<=?3 AND a.status=?4 ORDER BY a.organizationId"),
		 @NamedQuery(name="TransactionDataBean.updateByStatus",query="UPDATE TransactionDataBean a SET a.nodeId=?1 , a.status=?2 WHERE a.transactionDate>=?3 AND a.transactionDate<=?4 AND a.status=?5"),
		 @NamedQuery(name="TransactionDataBean.updateByStatusAndNode",query="UPDATE TransactionDataBean a SET a.nodeId=?1 , a.status=?2 WHERE a.nodeId=?3 AND a.transactionDate>=?4 AND a.transactionDate<=?5 AND a.status=?6"),
		 @NamedQuery(name="TransactionDataBean.deleteByTime",query="DELETE FROM TransactionDataBean a WHERE a.transactionDate>=?1 AND a.transactionDate<=?2")
		})
public class TransactionDataBean {
	
	
   @Id
   @GeneratedValue
   @Column(nullable=false)
   private int id;
   @Column(nullable=false)
   private int organizationId;
   @Column(nullable=false)
   private int productId;
   @Column(nullable=false)
   private int units;
   @Column(nullable=false)
   private long transactionDate;
   @Column(nullable=false)
   private long expectedLifeDate;
   @Column(length=64000)
   private String comment;
   @Column(nullable=false)
   private int status;
   @Column(nullable=false)
   private int nodeId;
   
   /**
    * 
    * @param organizationId of the organization 
    * @param productId of the product
    * @param units number of units involved in transaction
    * @param transactionDate date this transaction occurred.
    * @param expectedLifeDate date when this transaction will be considered as ended, this
    * could be used for subscriptions etc. 
    */
   public TransactionDataBean(int organizationId, int productId, int units, Date transactionDate, Date expectedLifeDate) {
	   super();
	   this.organizationId = organizationId;
	   this.productId = productId;
	   this.units = units;
	   this.transactionDate = transactionDate.getTime();
	   this.expectedLifeDate = expectedLifeDate.getTime();
	   this.status = WSRAConstants.TRANSACTIONSTATUS_UNPROCESSED;
	   this.nodeId = 0;
   }

   /**
    * Empty Constructor
    */
   public TransactionDataBean() {
	   
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
	 * @return the organizationId
	 */
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
	 * @return the productId
	 */
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
	 * @return number of units involved in transaction
	 */
	public int getUnits() {
		return units;
	}

	/**
	 * @param units number of units involved in transaction
	 */
	public void setUnits(int units) {
		this.units = units;
	}

	/**
	 * @return date this transaction occurred.
	 */
	public Date getTransactionDate() {
		return new Date(transactionDate);
	}

	/**
	 * @param transactionDate date this transaction occurred.
	 */
	public void setTransactionDate(Date transactionDate) {
		this.transactionDate = transactionDate.getTime();
	}

	/**
	 * @return date when this transaction will be considered as ended, this
     * could be used for subscriptions etc.
	 */
	@XmlElement(required=true)
	public Date getExpectedLifeDate() {
		return new Date(expectedLifeDate);
	}

	/**
	 * @param expectedLifeDate date when this transaction will be considered as ended, this
     * could be used for subscriptions etc.
	 */
	public void setExpectedLifeDate(Date expectedLifeDate) {
		this.expectedLifeDate = expectedLifeDate.getTime();
	}

	/**
	 * @return the status of transaction, one of TransactionDataBean.STATUS_ constants.
	 */
	public int getStatus() {
		return status;
	}

	/**
	 * @param status the status of transaction, one of TransactionDataBean.STATUS_ constants.
	 */
	public void setStatus(int status) {
		this.status = status;
	}

	/**
	 * @return the nodeId usually a hash of NodeId of current node, used
	 * to avoid two nodes processing the same transaction at once.
	 */
	public int getNodeId() {
		return nodeId;
	}

	/**
	 * @param nodeId  usually a hash of NodeId of current node, used
	 * to avoid two nodes processing the same transaction at once.
	 */
	public void setNodeId(int nodeId) {
		this.nodeId = nodeId;
	}

}
