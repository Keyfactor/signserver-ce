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
package org.signserver.adminws;

import org.signserver.common.ArchiveMetadata;

/**
 * Holder for archive entries.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class ArchiveEntry {
    private String uniqueId;
    private String archiveId;
    private String requestCertSerialNumber;
    private String requestIssuerDN;
    private String requestIP;
    private Integer signerId;
    private Long time;
    private Integer type;

    public ArchiveEntry() {
    }
    
    public ArchiveEntry(final String uniqueId, final String archiveId,
            final String requestCertSerialNumber,
            final String requestIssuerDN, final String requestIP, 
            final Integer signerId,
            final Long time, final Integer type) {
        this.uniqueId = uniqueId;
        this.archiveId = archiveId;
        this.requestCertSerialNumber = requestCertSerialNumber;
        this.requestIssuerDN = requestIssuerDN;
        this.requestIP = requestIP;
        this.signerId = signerId;
        this.time = time;
        this.type = type;
    }

    public static ArchiveEntry fromArchiveMetadata(final ArchiveMetadata src) {
        return new ArchiveEntry(src.getUniqueId(), src.getArchiveId(),
                src.getRequestCertSerialNumber(), src.getRequestIssuerDN(),
                src.getRequestIP(), src.getSignerId(),
                src.getTime().getTime(), src.getType());
    }
    
    public String getUniqueId() {
        return uniqueId;
    }
    
    public String getArchiveId() {
        return archiveId;
    }
    public String getRequestCertSerialNumber() {
        return requestCertSerialNumber;
    }
    public String getRequestIssuerDN() {
        return requestIssuerDN;
    }
    public String getRequestIP() {
        return requestIP;
    }
    public Integer getSignerId() {
        return signerId;
    }
    public Long getTime() {
        return time;
    }
    public Integer getType() {
        return type;
    }

    public void setUniqueId(final String uniqueId) {
        this.uniqueId = uniqueId;
    }
    
    public void setArchiveId(final String archiveId) {
        this.archiveId = archiveId;
    }

    public void setRequestCertSerialNumber(final String requestCertSerialNumber) {
        this.requestCertSerialNumber = requestCertSerialNumber;
    }

    public void setRequestIssuerDN(final String requestIssuerDN) {
        this.requestIssuerDN = requestIssuerDN;
    }

    public void setRequestIP(final String requestIP) {
        this.requestIP = requestIP;
    }

    public void setSignerId(final Integer signerId) {
        this.signerId = signerId;
    }

    public void setTime(final Long time) {
        this.time = time;
    }

    public void setType(final Integer type) {
        this.type = type;
    }

    
}
