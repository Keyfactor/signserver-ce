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
package org.signserver.clientws;

import java.util.List;

/**
 * Represents the response (result) of requesting some data to be processed.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class DataResponse {
   
    private int requestId;
    private byte[] data;
    private String archiveId;
    private byte[] signerCertificate;
    private List<Metadata> metadata;

    public DataResponse() {
    }

    /**
     * Constructs a new instance of DataResponse.
     * @param requestId Id of the worker that processed the request.
     * @param data The result (for instance signed document).
     * @param archiveId The ID assigned to the archivable item(s).
     * @param signerCertificate Certificate of the signer signing the data (if any).
     * @param metadata Response metadata.
     */
    public DataResponse(int requestId, byte[] data, String archiveId, byte[] signerCertificate, List<Metadata> metadata) {
        this.requestId = requestId;
        this.data = data;
        this.archiveId = archiveId;
        this.signerCertificate = signerCertificate;
        this.metadata = metadata;
    }

    /**
     * @return The archive id
     */
    public String getArchiveId() {
        return archiveId;
    }

    /**
     * @param archiveId The archive id
     */
    public void setArchiveId(String archiveId) {
        this.archiveId = archiveId;
    }

    /**
     * @return The signed data
     */
    public byte[] getData() {
        return data;
    }

    /**
     * @param data The signed data
     */
    public void setData(byte[] data) {
        this.data = data;
    }

    /**
     * @return The id of the request
     */
    public int getRequestId() {
        return requestId;
    }

    /**
     * @param requestId The id of the request
     */
    public void setRequestId(int requestId) {
        this.requestId = requestId;
    }

    /**
     * @return The signer certificate (if any)
     */
    public byte[] getSignerCertificate() {
        return signerCertificate;
    }

    /**
     * @param signerCertificate The signer certificate
     */
    public void setSignerCertificate(byte[] signerCertificate) {
        this.signerCertificate = signerCertificate;
    }

    /**
     * @return The response metadata (if any)
     */
    public List<Metadata> getMetadata() {
        return metadata;
    }

    /**
     * @param metadata The response metadata
     */
    public void setMetadata(List<Metadata> metadata) {
        this.metadata = metadata;
    }
    
}
