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
import org.signserver.server.archive.Archivable;

/**
 * Class holding metadata of matched archive entries.
 * Can optionally hold the actual archived data assoiated with an entry.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class ArchiveMetadata implements Serializable {
    private static final long serialVersionUID = 1L;

    private String uniqueId;
    private String archiveId;
    private String requestCertSerialNumber;
    private String requestIssuerDN;
    private String requestIP;
    private int signerId;
    private Date time;
    private int type;
    private byte[] archiveData;
    
    // field names used for querying the archive
    public static String UNIQUE_ID = "uniqueId";
    public static String ARCHIVE_ID = "archiveid";
    public static String REQUEST_CERT_SERIAL_NUMBER = "requestCertSerialnumber";
    public static String REQUEST_ISSUER_DN = "requestIssuerDN";
    public static String REQUEST_IP = "requestIP";
    public static String SIGNER_ID = "signerid";
    public static String TIME = "time";
    public static String TYPE = "type";
    public static String ARCHIVE_DATA = "archiveData";

    /**
     * Construct an archive metadata entry.
     * The values are analogous to the corresponding database columns.
     * 
     * @param type Archive type
     * @param signerid Signer ID
     * @param uniqueId Unique ID in DB
     * @param archiveid Archive ID
     * @param time Time of operation
     * @param requestIssuerDN Issuer DN of client performing operation
     * @param requestCertSerialnumber Serial number of client cert performing operation
     * @param requestIP IP address of client performing operation
     */
    public ArchiveMetadata(final int type, final int signerid,
            final String uniqueId, final String archiveid,
            final Date time, final String requestIssuerDN,
            final String requestCertSerialnumber, final String requestIP) {
        this.type = type;
        this.signerId = signerid;
        this.uniqueId = uniqueId;
        this.archiveId = archiveid;
        this.time = time;
        this.requestIssuerDN = requestIssuerDN;
        this.requestCertSerialNumber = requestCertSerialnumber;
        this.requestIP = requestIP;
    }
    
    /**
     * Construct an archive metadata entry including archive data.
     * 
     * @param type Archive type
     * @param signerid Signer ID
     * @param uniqueId Unique ID in DB
     * @param archiveid Archive ID
     * @param time Time of operation
     * @param requestIssuerDN Issuer DN of client performing operation
     * @param requestCertSerialnumber Cert serial number of client performing operation
     * @param requestIP IP address of client performing operation
     * @param archiveData Archive data
     */
    public ArchiveMetadata(final int type, final int signerid,
            final String uniqueId, final String archiveid,
            final Date time, final String requestIssuerDN,
            final String requestCertSerialnumber, final String requestIP,
            final byte[] archiveData) {
        this.type = type;
        this.signerId = signerid;
        this.uniqueId = uniqueId;
        this.archiveId = archiveid;
        this.time = time;
        this.requestIssuerDN = requestIssuerDN;
        this.requestCertSerialNumber = requestCertSerialnumber;
        this.requestIP = requestIP;
        this.archiveData = archiveData;
    }
    
    public int getType() {
        return type;
    }
    
    public int getSignerId() {
        return signerId;
    }
    
    public String getUniqueId() {
        return uniqueId;
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
    
    public byte[] getArchiveData() {
        return archiveData;
    }
    
    /**
     * Get a suggested output file name for storing archive data.
     * The file name is based on the archiveId when extensions ".request" and ".response"
     * for the known archive types. For any unknown archive type, the resulting
     * file name is based on the archiveId and type separated by "." with an extension
     * of ".data".
     * 
     * @return The suggested file name
     */
    public String suggestedFilename() {
        if (type == ArchiveDataVO.TYPE_REQUEST) {
            return archiveId + ".request";
        } else if (type == ArchiveDataVO.TYPE_RESPONSE) {
            return archiveId + ".response";
        } else {
            // fall back to a generic pattern if the archive type is unknown
            return archiveId + "." + type + ".data";
        }
    }
    
    /**
     * Given a type value (DB column value), return string value
     * for representation (i.e. list output).
     * 
     * @param type
     * @return String representation, falls back to the string representation of
     *                the numeric value for unknown type values
     */
    public static String getTypeName(final int type) {
        if (type == ArchiveDataVO.TYPE_REQUEST) {
            return Archivable.TYPE_REQUEST;
        } else if (type == ArchiveDataVO.TYPE_RESPONSE) {
            return Archivable.TYPE_RESPONSE;
        } else {
            // if additional values would be possible in the future, add cases here
            return Integer.toString(type);
        }
    }

    /**
     * Type names.
     */
    public static String[] TYPE_NAMES = {Archivable.TYPE_REQUEST, Archivable.TYPE_RESPONSE};

    /**
     * Translate a type representation name to the corresponding DB value.
     * 
     * @param name Name as presented in i.e. the GUI list
     * @return The value store in the DB
     * @throws IllegalArgumentException If the name is unknown
     */
    public static int translateTypeName(final String name)
            throws IllegalArgumentException {
        if (Archivable.TYPE_REQUEST.equals(name)) {
            return ArchiveDataVO.TYPE_REQUEST;
        } else if (Archivable.TYPE_RESPONSE.equals(name)) {
            return ArchiveDataVO.TYPE_RESPONSE;
        } else {
            // if additional values would be possible in the future, add cases here
            throw new IllegalArgumentException("Unknown type name: " + name);
        }
    }
}
