/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.validationservice.server;

import java.security.cert.X509Certificate;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;

/**
 * Holder for information returned from the OCSP responder as well as information
 * about return codes etc.
 *
 *
 * @version $Id: OCSPResponse.java 15282 2012-08-09 12:56:38Z netmackan $
 */
public class OCSPResponse {
    
    private Long responseTime;
    private int httpReturnCode;
    private Error error;
    private OCSPResp resp;
    private BasicOCSPResp responseObject;
    
    private X500Principal issuerDN;
    private X509Certificate signerCertificate;
    
    private List<String> failedResponses;
    private List<String> responsesFromOther;

    public Long getResponseTime() {
        return responseTime;
    }

    public void setResponseTime(Long responseTime) {
        this.responseTime = responseTime;
    }

    public void setHttpReturnCode(int httpReturnCode) {
        this.httpReturnCode = httpReturnCode;
    }

    public int getHttpReturnCode() {
        return httpReturnCode;
    }

    public Error getError() {
        return error;
    }

    public void setError(Error error) {
        this.error = error;
    }

    public OCSPResp getResp() {
        return resp;
    }

    public void setResp(OCSPResp resp) {
        this.resp = resp;
    }

    public X500Principal getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(X500Principal issuerDN) {
        this.issuerDN = issuerDN;
    }

    public BasicOCSPResp getResponseObject() {
        return responseObject;
    }

    public void setResponseObject(BasicOCSPResp responseObject) {
        this.responseObject = responseObject;
    }

    public X509Certificate getSignerCertificate() {
        return signerCertificate;
    }

    public void setSignerCertificate(X509Certificate signerCertificate) {
        this.signerCertificate = signerCertificate;
    }

    public void setFailedResponses(List<String> failedResponses) {
        this.failedResponses = failedResponses;
    }

    public List<String> getFailedResponses() {
        return failedResponses;
    }

    public void setResponsesFromOther(List<String> unexpectedResponses) {
        this.responsesFromOther = unexpectedResponses;
    }
    
    public List<String> getResponsesFromOther() {
        return responsesFromOther;
    }

    @Override
    public String toString() {
        return "OCSPResponse{" + "responseTime=" + responseTime + ", httpReturnCode=" + httpReturnCode + ", error=" + error + ", resp=" + resp + ", responseObject=" + responseObject + ", issuerDN=" + issuerDN + ", signerCertificate=" + signerCertificate + ", failedResponses=" + failedResponses + ", responsesFromOther=" + responsesFromOther + '}';
    }
    
    /**
     * Error code as returned from the server contacted.
     */
    public enum Error {
        httpUnauthorized,
        unknown,
        noResponse,
        invalidSignerId, 
        inconsistentSignature,
        
        responseSuccess,
        responseMalformedRequest,
        responseInternalError,
        responseTryLater,
        responseSigRequired,
        responseUnauthorized,
        responseOther;
        
        public static Error fromBCOCSPResponseStatus(int status) {
            final Error result;
            switch (status) {
                case OCSPResponseStatus.SUCCESSFUL: result = responseSuccess; break;
                case OCSPResponseStatus.MALFORMED_REQUEST: result = responseMalformedRequest; break;
                case OCSPResponseStatus.INTERNAL_ERROR: result = responseInternalError; break;
                case OCSPResponseStatus.TRY_LATER: result = responseTryLater; break;
                case OCSPResponseStatus.SIG_REQUIRED: result = responseSigRequired; break;
                case OCSPResponseStatus.UNAUTHORIZED: result = responseUnauthorized; break;
                default: result = responseOther;
            }
            return result;
        }
    }
}
