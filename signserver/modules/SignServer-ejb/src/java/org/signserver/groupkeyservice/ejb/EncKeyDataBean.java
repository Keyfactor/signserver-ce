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

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

/**
 * Entity Bean storing data about a encryption key used to store
 * group keys.
 * Information stored:
 * <pre>
 * id (PrimaryKey, long)
 * workerId (int)
 * encKeyRef (unique, String)
 * usageStarted (Date)
 * usageEnded (Date)
 * numberOfEncryptions (long)
 * </pre>
 *
 * @author Philip Vendil
 * @version $Id$
 */
@Entity
@Table(name = "enckeydata")
@NamedQueries({
    @NamedQuery(name = "EncKeyDataBean.findByEncKeyRef", query = "SELECT a from EncKeyDataBean a WHERE a.workerId=?1 AND a.encKeyRef=?2 "),
    @NamedQuery(name = "EncKeyDataBean.findByUseFlag", query = "SELECT DISTINCT a from EncKeyDataBean a WHERE a.workerId=?1 AND a.inUse=TRUE")
})
public class EncKeyDataBean implements Serializable {

    @Id()
    @GeneratedValue
    private long id;
    
    private int workerId;
    
    @Column(length = 255)
    private String encKeyRef;
    
    private boolean inUse;
    
    @Temporal(TemporalType.TIMESTAMP)
    private Date usageStarted;
    
    @Temporal(TemporalType.TIMESTAMP)
    private Date usageEnded;
    
    private long numberOfEncryptions;

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
     * @return the encKeyRef
     */
    public String getEncKeyRef() {
        return encKeyRef;
    }

    /**
     * @param encKeyRef the encKeyRef to set
     */
    public void setEncKeyRef(String encKeyRef) {
        this.encKeyRef = encKeyRef;
    }

    /**
     * @return the usageStarted
     */
    public Date getUsageStarted() {
        return usageStarted;
    }

    /**
     * @param usageStarted the usageStarted to set
     */
    public void setUsageStarted(Date usageStarted) {
        this.usageStarted = usageStarted;
    }

    /**
     * @return the usageEnded
     */
    public Date getUsageEnded() {
        return usageEnded;
    }

    /**
     * @param usageEnded the usageEnded to set
     */
    public void setUsageEnded(Date usageEnded) {
        this.usageEnded = usageEnded;
    }

    /**
     * @return the numberOfEncryptions
     */
    public long getNumberOfEncryptions() {
        return numberOfEncryptions;
    }

    /**
     * @param numberOfEncryptions the numberOfEncryptions to set
     */
    public void setNumberOfEncryptions(long numberOfEncryptions) {
        this.numberOfEncryptions = numberOfEncryptions;
    }

    /**
     * @return the inUse
     */
    public boolean getInUse() {
        return inUse;
    }

    /**
     * @param isUse if the current key is in use.
     */
    public void setInUse(boolean inUse) {
        this.inUse = inUse;
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
