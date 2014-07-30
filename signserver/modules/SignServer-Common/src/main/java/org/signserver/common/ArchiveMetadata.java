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
 * Class holding metadata of matched archive entries.
 * The rationale is to present collections of these objects as
 * a "preliminary" search result with the possibility of fetching
 * actual archive data on a per-row basis.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class ArchiveMetadata implements Serializable {
    private static final long serialVersionUID = 1L;

    private String archiveId;
    private String requestCertSerialNumber;
    private String requestIssuerDN;
    private String requestIP;
    private int signerId;
    private Date time;
    private int type;
    
    // field names
    public static String ARCHIVE_ID = "archiveid";
    public static String REQUEST_CERT_SERIAL_NUMBER = "requestCertSerialNumber";
    public static String REQUEST_ISSUER_DN = "requestIssuerDN";
    public static String REQUEST_IP = "requestIP";
    public static String SIGNER_ID = "signerid";
    public static String TIME = "time";
    public static String TYPE = "type";

    public ArchiveMetadata(int type, int signerid, String archiveid,
            Date date, String requestIssuerDN,
            String requestCertSerialnumber, String requestIP) {
        this.type = type;
        this.signerId = signerid;
        this.archiveId = archiveid;
        this.time = date;
        this.requestIssuerDN = requestIssuerDN;
        this.requestCertSerialNumber = requestCertSerialnumber;
        this.requestIP = requestIP;
    }
    
    public int getType() {
        return type;
    }
    
    public int getSignerId() {
        return signerId;
    }
    
    public String getArchiveId() {
        return archiveId;
    }
    
    public Date getTime() {
        return time;
    }
    
    public String getRequestIssuerDN() {
        return requestIssuerDN;
    }
    
    public String getRequestCertSerialNumber() {
        return requestCertSerialNumber;
    }
    
    public String getRequestIP() {
        return requestIP;
    }
}
