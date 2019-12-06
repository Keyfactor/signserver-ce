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

import java.security.cert.Certificate;
import java.util.Collection;
import org.signserver.common.IArchivableProcessResponse;
import org.signserver.server.archive.Archivable;

/**
 * Data holder for a generic process response.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SignatureResponse extends Response implements IArchivableProcessResponse {

    private final int requestID;
    private final WritableData responseData;
    private final Certificate signerCertificate;
    private final String archiveId;
    private final String contentType;
    private final Collection<? extends Archivable> archivables;
    
    /**
     * Creates a GenericWorkResponse, works as a simple VO.
     * 
     * @param requestID
     * @param responseData
     * @param signerCertificate
     * @param archiveId
     * @param archivables
     * @param contentType
     * @see org.signserver.common.ProcessRequest
     */
    public SignatureResponse(int requestID, WritableData responseData,
            Certificate signerCertificate,
            String archiveId, Collection<? extends Archivable> archivables,
            String contentType) {
        this.requestID = requestID;
        this.responseData = responseData;
        this.signerCertificate = signerCertificate;
        this.archiveId = archiveId;
        this.archivables = archivables;
        this.contentType = contentType;
    }

    public int getRequestID() {
        return requestID;
    }

    public WritableData getResponseData() {
        return responseData;
    }

    public Certificate getSignerCertificate() {
        return signerCertificate;
    }

    public String getArchiveId() {
        return archiveId;
    }

    public String getContentType() {
        return contentType;
    }

    public Collection<? extends Archivable> getArchivables() {
        return archivables;
    }

}
