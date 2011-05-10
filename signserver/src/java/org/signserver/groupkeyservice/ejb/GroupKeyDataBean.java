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


package org.signserver.groupkeyservice.ejb;

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;



/**
 * Entity Bean storing data about a group key 
 * Information stored:
 * <pre>
 * id (PrimaryKey, long)
 * documentID (unique, String)
 * encryptedData (byte[])
 * creationDate (Date)
 * firstUsedDate (Date)
 * lastFetchedDate (Date)
 * encKeyRef (String)
 * </pre>
 *
 * @author Philip Vendil
 * @version $Id$
 * 
 */
@Entity
@Table(name="groupkeydata")
@NamedQueries(
		{@NamedQuery(name="GroupKeyDataBean.findByDocumentId",query="SELECT a from GroupKeyDataBean a WHERE a.workerId=?1 AND a.documentID=?2 "),
		 @NamedQuery(name="GroupKeyDataBean.findUnassignedKey",query="SELECT DISTINCT a from GroupKeyDataBean a WHERE a.workerId=?1 AND a.documentID IS NULL"),
		 @NamedQuery(name="GroupKeyDataBean.findByCreationDate",query="SELECT a from GroupKeyDataBean a WHERE a.workerId=?1 AND a.creationDate>=?2 AND a.creationDate<=?3"),
		 @NamedQuery(name="GroupKeyDataBean.findByFirstUsedDate",query="SELECT a from GroupKeyDataBean a WHERE a.workerId=?1 AND a.firstUsedDate>=?2 AND a.firstUsedDate<=?3"),
		 @NamedQuery(name="GroupKeyDataBean.findByLastFetchedDate",query="SELECT a from GroupKeyDataBean a WHERE a.workerId=?1 AND a.lastFetchedDate>=?2 AND a.lastFetchedDate<=?3"),
		 @NamedQuery(name="GroupKeyDataBean.numberOfUnassignedKeys",query="SELECT count(a) from GroupKeyDataBean a WHERE a.workerId=?1 AND a.creationDate>=?2 AND a.creationDate<=?3 AND a.documentID IS NULL"),
		 @NamedQuery(name="GroupKeyDataBean.numberOfAssignedKeys",query="SELECT count(a) from GroupKeyDataBean a WHERE a.workerId=?1 AND a.creationDate>=?2 AND a.creationDate<=?3 AND a.documentID IS NOT NULL"),
		 @NamedQuery(name="GroupKeyDataBean.totalNumberOfKeys",query="SELECT count(a) from GroupKeyDataBean a WHERE a.workerId=?1 AND a.creationDate>=?2 AND a.creationDate<=?3")
		})
public class GroupKeyDataBean  {
	
	@Id()
	@GeneratedValue
	private long id;
	
	@Column(length=255)
	private String documentID;
		
	private int workerId;
	
	@Lob
	private byte[] encryptedData;
	
	private transient byte[] decryptedData;
	
	@Temporal(TemporalType.TIMESTAMP)
	private Date creationDate;
	@Temporal(TemporalType.TIMESTAMP)
	private Date firstUsedDate;	
	@Temporal(TemporalType.TIMESTAMP)
	private Date lastFetchedDate;	
	private String encKeyRef;
	
	
	/**
	 * @return Primary key set by the database
	 */
	public long getId() {
		return id;
	}
	
	/**
	 * @param id primary key set by the database
	 */
	public void setId(long id) {
		this.id = id;
	}
	
	/**
	 * @return unique id of the document associated with this key.
	 */
	public String getDocumentID() {
		return documentID;
	}
	
	/**
	 * 
	 * @param documentID unique id of the document associated with this key.
	 * This could be the full id of a hash of the full id in order to save space.
	 */
	public void setDocumentID(String documentID) {
		this.documentID = documentID;
	}
	
	/**
	 * 
	 * @return the key data encrypted 
	 */
	public byte[] getEncryptedData() {
		return encryptedData;
	}
	
	/**
	 * 
	 * @param encryptedData the key data encrypted 
	 */
	public void setEncryptedData(byte[] encryptedData) {
		this.encryptedData = encryptedData;
	}
	
	/**
	 * 
	 * @return cached decrypted data used by the service bean. 
	 * Transient value never stored to the database.
	 */
	public byte[] getDecryptedData() {
		return decryptedData;
	}
	
	/**
	 * 
	 * @param decryptedData cached decrypted data used by the service bean. 
	 * Transient value never stored to the database.
	 */
	public void setDecryptedData(byte[] decryptedData) {
		this.decryptedData = decryptedData;
	}
	
	/**
	 * 
	 * @return the time this group key was first created
	 */
	public Date getCreationDate() {
		return creationDate;
	}
	
	/**
	 * 
	 * @param creationDate the time this group key was generated
	 */
	public void setCreationDate(Date creationDate) {
		this.creationDate = creationDate;
	}
	
	/**
	 * 
	 * @return The date this group key used the first time and
	 * associated with a document Id
	 */
	public Date getFirstUsedDate() {
		return firstUsedDate;
	}
	
	/**
	 * 
	 * @param firstUsedDate the date this group key used the first time and
	 * associated with a document Id
	 */
	public void setFirstUsedDate(Date firstUsedDate) {
		this.firstUsedDate = firstUsedDate;
	}
	
	/**
	 * 
	 * @return the date the group key was last fetched.
	 */
	public Date getLastFetchedDate() {
		return lastFetchedDate;
	}
	
	/**
	 * 
	 * @param lastFetchedDate the date the group key was last fetched.
	 */
	public void setLastFetchedDate(Date lastFetchedDate) {
		this.lastFetchedDate = lastFetchedDate;
	}
	
	/**
	 * 
	 * @return reference to the encryption key used to encrypt the data.
	 */
	public String getEncKeyRef() {
		return encKeyRef;
	}
	
	/**
	 * @param encKeyRef reference to the encryption key used to encrypt the data.
	 */
	public void setEncKeyRef(String encKeyRef) {
		this.encKeyRef = encKeyRef;
	}

	/**
	 * @return the workerId
	 */
	public int getWorkerId() {
		return workerId;
	}

	/**
	 * @param workerId the workerId to set
	 */
	public void setWorkerId(int workerId) {
		this.workerId = workerId;
	}

}
