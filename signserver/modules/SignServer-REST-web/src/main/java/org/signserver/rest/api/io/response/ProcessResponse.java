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
        description = "The resulting data (i.e the signature) in Base64 encoding",
        example = "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"
    )
    private String data;
    @Schema(example = "457529920")
    private String requestId;
    @Schema(example= "61f5414b202a8c4006a1f9e7486af0181f73d710")
    private String archiveId;
    @Schema(example = "MIIDlzCCAn+gAwIBAgIIOdPbElQbJhcwDQYJKoZIhvcNAQELBQAwTDEWMBQGA1UEAwwNRFNTIFN1YiBDQSAxMTEQMA4GA1UECwwHVGVzdGluZzETMBEGA1UECgwKU2lnblNlcnZlcjELMAkGA1UEBhMCU0UwHhcNMTYwMzAzMDgyNTA0WhcNMzYwMjI3MDgyNTA0WjBKMRQwEgYDVQQDDAtzaWduZXIwMDAwMzEQMA4GA1UECwwHVGVzdGluZzETMBEGA1UECgwKU2lnblNlcnZlcjELMAkGA1UEBhMCU0UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCyFKqwwiHS2o4PO3zovqC+jGuIELnja1iAlg/hyrRp28mF6BOGVaKE6ZzbQIMmmICRz+EeqXN1W8gyCEh6T2qN3QvXTAF9mrrUI3hG4Xn/Davgsln8saRE0zt45yy47dPq5YofYJWWIdW/6qssiX+ApcPqthCQfkgraUSagS/Reqy0WT/A2lwKh147GB9+MxhheskQIPaKQasOpI7vGfzey+GnkHPsfU21irS2nC8uzv6hd0G6hNYUEmJtIh9/5WebMoMiGFq1sydTtZp7pJilfPyxrAkHXEwMUEEMcVlE/ISCoKMttnLMUT/F00cHesU4D2yNl6gcSjpMj4Q/iF+hAgMBAAGjfzB9MB0GA1UdDgQWBBQ2/WY3Ln7tdUmDrTyvtvSZwBg8YzAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFBxgQUremK3l1gOK6GaCqX6w8gKHMA4GA1UdDwEB/wQEAwIF4DAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwDQYJKoZIhvcNAQELBQADggEBAIUh6kkCMc0Fs6U+Sw6Ns0Yd28Fb5SM//nE6mq3mf1SD4lAyChVrFvlqMZJaqeJlkVeHc9E+KCE5bX1r2iGC8rnE9DuItI0pKMrgFt4cbSbDwgovnTrkiIhuqP2pjdhmrHtlLqZBR8e16c4xGSn6XWKJ8vPzx2AJl7MY3sY3Z4aPckBFNjG1lzH1inq5WM/+WaLghOQQngaXeU+SWpoAM7cUjB8Uyjf2Qr2GerI4AZZJMuC6BuvMdFMyXX78l7c9qmvK9Bre+SFKdtcMAgnglLzu0lyPHPwYL0R+pwc5dFOJipafxeqeHGpkZTXMsdMn6f1USRznlGbRWru68/XOOFU=")
    private String signerCertificate;
    @Schema(example = "{}")
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
