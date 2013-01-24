/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import java.math.BigInteger;
import java.security.cert.X509Certificate;

/**
 * Class holding administrator logging information.
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class AdminInfo {
    private final String subjectDN;
    private final String issuerDN;
    private final BigInteger certSerialNumber;

    public AdminInfo(final X509Certificate clientCert) {
        subjectDN = clientCert.getSubjectDN().getName();
        issuerDN = clientCert.getIssuerDN().getName();
        certSerialNumber = clientCert.getSerialNumber();
    }
    
    public AdminInfo(final String subjectDN, final String issuerDN, final BigInteger certSerialNumber) {
        this.subjectDN = subjectDN;
        this.issuerDN = issuerDN;
        this.certSerialNumber = certSerialNumber;
    }
    
    public String getSubjectDN() {
        return subjectDN;
    }
    
    public String getIssuerDN() {
        return issuerDN;
    }
    
    public BigInteger getCertSerialNumber() {
        return certSerialNumber;
    }
}
