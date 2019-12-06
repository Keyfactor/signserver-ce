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
import org.signserver.server.archive.Archivable;

/**
 * Data holder for a MRTD SOD signing response.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SODResponse extends SignatureResponse {

    public SODResponse(int requestID, WritableData responseData, Certificate signerCertificate, String archiveId, Collection<? extends Archivable> archivables, String contentType) {
        super(requestID, responseData, signerCertificate, archiveId, archivables, contentType);
    }

}
