package org.signserver.common;

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
public class ArchiveMetadata {

    private String archiveId;
    private String requestCertSerialNumber;
    private String requestIssuerDN;
    private String requestIP;
    private int signerId;
    private Date time;
    private int type;
    
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
