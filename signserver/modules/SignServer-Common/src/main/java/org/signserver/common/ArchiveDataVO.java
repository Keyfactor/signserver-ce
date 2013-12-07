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
package org.signserver.common;

import java.io.Serializable;
import java.util.Date;

/**
 * Envelope class containing the archive data along with
 * other data such as time of archival, requestorIP, type ...
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class ArchiveDataVO implements Serializable {

    private static final long serialVersionUID = 1L;
    
    /**
     * Archive type is response.
     */
    public static final int TYPE_RESPONSE = 0;
    
    /** Archive type is request. */
    public static final int TYPE_REQUEST = 1;
    
    private ArchiveData archiveData = null;
    private byte[] archivedBytes;
    private int type = 0;
    private Date time = null;
    private String archiveId = null;
    private String requestIssuerDN = null;
    private String requestSerialnumber = null;
    private String requestIP = null;
    private int signerId = 0;

    /**
     * @param type
     * @param time
     * @param requestIssuerDN
     * @param requestSerialnumber
     * @param requestIP
     * @param archiveData
     */
    public ArchiveDataVO(int type, int signerId, String archiveId, Date time, String requestIssuerDN, String requestSerialnumber, String requestIP, ArchiveData archiveData) {
        super();
        this.archiveData = archiveData;
        this.type = type;
        this.signerId = signerId;
        this.time = time;
        this.archiveId = archiveId;
        this.requestIssuerDN = requestIssuerDN;
        this.requestSerialnumber = requestSerialnumber;
        this.requestIP = requestIP;
    }
    
    public ArchiveDataVO(int type, int signerId, String archiveId, Date time, String requestIssuerDN, String requestSerialnumber, String requestIP, byte[] archivedBytes) {
        super();
        this.type = type;
        this.signerId = signerId;
        this.time = time;
        this.archiveId = archiveId;
        this.requestIssuerDN = requestIssuerDN;
        this.requestSerialnumber = requestSerialnumber;
        this.requestIP = requestIP;
        this.archivedBytes = archivedBytes;
    }

    /**
     * @return Returns the archiveData or null if not available.
     * @see #getArchivedBytes()
     */
    public ArchiveData getArchiveData() {
        return archiveData;
    }
    
    /**
     * @return The archived bytes independent on how they were stored.
     */
    public byte[] getArchivedBytes() {
        if (archiveData != null) {
            return archiveData.getData();
        } else {
            return archivedBytes;
        }
    }

    /**
     * @return Returns the archiveId.
     */
    public String getArchiveId() {
        return archiveId;
    }

    /**
     * @return Returns the requestIP.
     */
    public String getRequestIP() {
        return requestIP;
    }

    /**
     * @return Returns the requestIssuerDN.
     */
    public String getRequestIssuerDN() {
        return requestIssuerDN;
    }

    /**
     * @return Returns the requestSerialnumber.
     */
    public String getRequestSerialnumber() {
        return requestSerialnumber;
    }

    /**
     * @return Returns the time.
     */
    public Date getTime() {
        return time;
    }

    /**
     * @return Returns the type.
     */
    public int getType() {
        return type;
    }

    /**
     * @return Returns the signerId.
     */
    public int getSignerId() {
        return signerId;
    }
}
