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
public class SODResponse extends DataResponse {

    public SODResponse() {
    }
    
    public SODResponse(int requestId, byte[] data, String archiveId, byte[] signerCertificate, List<Metadata> metadata) {
        super(requestId, data, archiveId, signerCertificate, metadata);
    }
    
}
