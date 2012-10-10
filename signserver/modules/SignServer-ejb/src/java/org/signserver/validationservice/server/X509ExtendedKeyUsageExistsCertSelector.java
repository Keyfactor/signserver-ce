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
package org.signserver.validationservice.server;

import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import org.bouncycastle.util.Selector;

/**
 * CertSelector used to match specific extended key usage existence in the 
 * certificate passed.
 *
 * @author rayback2
 * @version $Id$
 */
public class X509ExtendedKeyUsageExistsCertSelector implements CertSelector, Selector {

    private String oIDToCheck; // extended key usage OID to check for existence

    public X509ExtendedKeyUsageExistsCertSelector(String oIDToCheck) {
        this.oIDToCheck = oIDToCheck;
    }

    @Override
    public boolean match(Certificate cert) {

        //match certificate containing specified extended key usage
        if (!(cert instanceof X509Certificate)) {
            return false;
        }
        X509Certificate xcert = (X509Certificate) cert;
        try {
            if (xcert.getExtendedKeyUsage() != null) {

                for (String ext : xcert.getExtendedKeyUsage()) {
                    if (ext.equals(oIDToCheck)) {
                        return true;
                    }
                }
            }
        } catch (CertificateParsingException e) {
            return false;
        }

        return false;
    }

    @Override
    public X509ExtendedKeyUsageExistsCertSelector clone() {
        return new X509ExtendedKeyUsageExistsCertSelector(oIDToCheck);
    }

    @Override
    public boolean match(final Object o) {
        boolean result = false;
        if (o instanceof Certificate) {
            result = match ((Certificate) o);
        }
        return result;
    }
}