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

package org.signserver.server.log;

import java.security.cert.X509Certificate;

/**
 * Class holding administrator logging information.
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class AdminInfo {
    private final String subject;
    private final String issuer;
    private final String serialNumber;

    public AdminInfo(final X509Certificate clientCert) {
        subject = clientCert.getSubjectDN().getName();
        issuer = clientCert.getIssuerDN().getName();
        serialNumber = clientCert.getSerialNumber().toString(16);
    }

    public AdminInfo(final String subjectDN, final String issuerDN, final String certSerialNumber) {
        this.subject = subjectDN;
        this.issuer = issuerDN;
        this.serialNumber = certSerialNumber;
    }
    public AdminInfo(final String subject, final String issuer, final String preferredUsername, final String nothing) {
        this.subject = preferredUsername;
        this.issuer = issuer;
        this.serialNumber = subject;
    }
    public String getSubject() {
        return subject;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

}
