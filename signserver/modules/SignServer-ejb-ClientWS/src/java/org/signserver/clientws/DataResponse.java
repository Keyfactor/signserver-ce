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

    public DataResponse(int requestId, byte[] data, String archiveId, byte[] signerCertificate, List<Metadata> metadata) {
        this.requestId = requestId;
        this.data = data;
        this.archiveId = archiveId;
        this.signerCertificate = signerCertificate;
        this.metadata = metadata;
    }

    public String getArchiveId() {
        return archiveId;
    }

    public void setArchiveId(String archiveId) {
        this.archiveId = archiveId;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public int getRequestId() {
        return requestId;
    }

    public void setRequestId(int requestId) {
        this.requestId = requestId;
    }

    public byte[] getSignerCertificate() {
        return signerCertificate;
    }

    public void setSignerCertificate(byte[] signerCertificate) {
        this.signerCertificate = signerCertificate;
    }

    public List<Metadata> getMetadata() {
        return metadata;
    }

    public void setMetadata(List<Metadata> metadata) {
        this.metadata = metadata;
    }
    
}
