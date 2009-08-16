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
package org.signserver.common;

import java.security.cert.Certificate;


/** Response used for a signed SO(d) from the MRTD SOD Signer. Used for ePassports.
 * This is not located in the mrtdsod module package because it has to be available at startup to map urls.
 *
 * @author Markus Kilas
 * $Id$
 */
public class SODSignResponse extends GenericSignResponse {

    private static final long serialVersionUID = 1L;

    /**
     * Default constructor used during serialization
     */
    public SODSignResponse() {
        this.tag = RequestAndResponseManager.RESPONSETYPE_SODSIGNRESPONSE;
    }

    /**
     * Creates a SODSignResponse, works as a simple VO.
     *
     * @see org.signserver.common.ProcessRequest
     */
    public SODSignResponse(int requestID, byte[] processedData,
            Certificate signerCertificate,
            String archiveId, ArchiveData archiveData) {
        super(requestID, processedData, signerCertificate, archiveId, archiveData);
        this.tag = RequestAndResponseManager.RESPONSETYPE_SODSIGNRESPONSE;
    }
}
