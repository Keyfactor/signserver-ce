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

import java.io.IOException;
import java.security.cert.Certificate;
import java.util.Collection;
import org.signserver.common.GenericServletResponse;
import org.signserver.server.archive.Archivable;

/**
 * 
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TBNServletResponse extends GenericServletResponse {

    private final WritableData responseData;
    
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
    public TBNServletResponse(int requestID, WritableData responseData,
            Certificate signerCertificate,
            String archiveId, Collection<? extends Archivable> archivables,
            String contentType) {
        super(requestID, new byte[0], signerCertificate, archiveId, archivables, contentType); // TODO
        this.responseData = responseData;
    }

    public WritableData getResponseData() {
        return responseData;
    }

    @Override
    public byte[] getProcessedData() {
        try {
            return responseData.toReadableData().getAsByteArray();
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to obtain data", ex);
        }
    }
    
    

}
