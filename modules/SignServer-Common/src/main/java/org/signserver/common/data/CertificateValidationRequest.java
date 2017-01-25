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

/**
 * Data holder for a certificate validation request.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CertificateValidationRequest extends Request {

    private final Certificate certificate;
    private final String certPurposes;

    public CertificateValidationRequest(Certificate cert, String certPurposes) {
        this.certificate = cert;
        this.certPurposes = certPurposes;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    /**
     * @return the certPurposes the client want's to check that the certificate can be used for a list that is splitted by ","
     */
    public String[] getCertPurposes() {

        String[] retval = null;
        if (certPurposes != null && !certPurposes.trim().equals("")) {
            retval = certPurposes.split(",");

            for (String purpose : retval) {
                purpose = purpose.trim();
            }
        }

        return retval;
    }

}
