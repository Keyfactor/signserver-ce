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
package org.signserver.rest.api.io.response;

import java.util.Map;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 *
 * @author Markus Kilås
 */
@Schema(
    name = "ProcessResponse",
    description = "POJO that represents a process response."
)
public class ProcessResponse {

    @Schema(
        description = "The resulting data (i.e the signature) in Base64 encoding"
    )
    private String data;
    private String requestId;
    private String archiveId;
    private String signerCertificate;
    private Map<String, String> metaData;

    public ProcessResponse() {
    }

    public ProcessResponse(String archiveId, String data, String requestId, String signerCertificate) {
        this.archiveId = archiveId;
        this.data = data;
        this.requestId = requestId;
        this.signerCertificate = signerCertificate;
    }

    public ProcessResponse(String requestId, Map<String, String> metaData, String data) {
        this.requestId = requestId;
        this.metaData = metaData;
        this.data = data;

    }

    public ProcessResponse(String archiveId, String data, String requestId, String signerCertificate, Map<String, String> metadata) {
        this.archiveId = archiveId;
        this.data = data;
        this.requestId = requestId;
        this.signerCertificate = signerCertificate;
        this.metaData = metadata;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public Map<String, String> getMetaData() {
        return metaData;
    }

    public void setMetaData(Map<String, String> metaData) {
        this.metaData = metaData;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getArchiveId() {
        return archiveId;
    }

    public void setArchiveId(String archiveId) {
        this.archiveId = archiveId;
    }

    public String getSignerCertificate() {
        return signerCertificate;
    }

    public void setSignerCertificate(String signerCertificate) {
        this.signerCertificate = signerCertificate;
    }
}
