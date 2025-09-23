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
package org.signserver.admin.web.auth;

import java.security.cert.X509Certificate;
import org.cesecore.util.CertTools;

/**
 * Representation of an X.509 certificate for display on login page etc.
 */
public class ClientCert {
    private static final int HEX_RADIX = 16;
    private final String serialNumber;
    private final String subjectCN;

    public ClientCert(X509Certificate cert) {
        if (cert == null) {
            serialNumber = "";
            subjectCN = "";
        } else {
            subjectCN = CertTools.getPartFromDN(cert.getSubjectX500Principal().getName(), "CN");
            serialNumber = cert.getSerialNumber().toString(HEX_RADIX);
        }
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public String getSubjectCN() {
        return subjectCN;
    }

}
