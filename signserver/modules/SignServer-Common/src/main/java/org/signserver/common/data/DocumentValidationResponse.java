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
package org.signserver.common.data;

/**
 * Data holder for a document validation response.
 *
 * @version $Id$
 */
public class DocumentValidationResponse extends Response {

    private final int requestID;
    private final boolean valid;
    private final CertificateValidationResponse certificateValidationResponse;

    public DocumentValidationResponse(int requestID, boolean valid, CertificateValidationResponse certificateValidationResponse) {
        this.requestID = requestID;
        this.valid = valid;
        this.certificateValidationResponse = certificateValidationResponse;
    }

    public DocumentValidationResponse(int requestId, boolean b) {
        this(requestId, b, null);
    }

    public int getRequestID() {
        return requestID;
    }

    public boolean isValid() {
        return valid;
    }

    public CertificateValidationResponse getCertificateValidationResponse() {
        return certificateValidationResponse;
    }
    
}
