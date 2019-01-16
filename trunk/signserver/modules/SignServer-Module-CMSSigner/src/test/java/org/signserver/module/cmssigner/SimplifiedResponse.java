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
package org.signserver.module.cmssigner;

import java.security.cert.Certificate;

/**
 * Holder for the response data and certificate to simplify migration of the
 * unit tests that was designed for the old API.
 *
 * @author Markus Kilås
 * @version $Id$
 */
class SimplifiedResponse {
    
    private final byte[] processedData;
    private final Certificate signerCertificate;

    public SimplifiedResponse(byte[] processedData, Certificate signerCertificate) {
        this.processedData = processedData;
        this.signerCertificate = signerCertificate;
    }

    public byte[] getProcessedData() {
        return processedData;
    }

    public Certificate getSignerCertificate() {
        return signerCertificate;
    }
    
}
