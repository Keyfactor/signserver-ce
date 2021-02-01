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
 * The response data returned by the processSOD operation.
 *
 * @author Markus Kilås
 * @version $Id$
 * @see ClientWS#processSOD(java.lang.String, java.util.List, org.signserver.clientws.SODRequest) 
 */
public class SODResponse extends DataResponse {

    public SODResponse() {
    }
    
    /**
     * Constructs a new instance of SODResponse.
     * @param requestId Id of the worker that processed the request.
     * @param data The result (for instance signed document).
     * @param archiveId The ID assigned to the archivable item(s).
     * @param signerCertificate Certificate of the signer signing the data (if any).
     * @param metadata Response metadata.
     */
    public SODResponse(int requestId, byte[] data, String archiveId, byte[] signerCertificate, List<Metadata> metadata) {
        super(requestId, data, archiveId, signerCertificate, metadata);
    }
    
}
