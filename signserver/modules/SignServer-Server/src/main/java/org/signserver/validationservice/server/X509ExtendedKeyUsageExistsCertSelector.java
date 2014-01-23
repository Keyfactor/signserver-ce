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
package org.signserver.validationservice.server;

import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.util.Selector;

/**
 * CertSelector used to match specific extended key usage existence in the
 * certificate passed.
 *
 * @author rayback2
 * @version $Id: X509ExtendedKeyUsageExistsCertSelector.java 3419 2013-04-07
 * 14:55:41Z netmackan $
 */
public class X509ExtendedKeyUsageExistsCertSelector implements CertSelector, Selector {

    private final String oIDToCheck; // extended key usage OID to check for existence

    public X509ExtendedKeyUsageExistsCertSelector(ASN1ObjectIdentifier oid) {
        this(oid.getId());
    }

    public X509ExtendedKeyUsageExistsCertSelector(String oIDToCheck) {
        this.oIDToCheck = oIDToCheck;
    }

    @Override
    public boolean match(Certificate cert) {
        return match((Object) cert);
    }

    @Override
    public X509ExtendedKeyUsageExistsCertSelector clone() {
        return new X509ExtendedKeyUsageExistsCertSelector(oIDToCheck);
    }

    @Override
    public boolean match(final Object o) {
        //match certificate containing specified extended key usage
        X509Certificate xcert;
        if (o instanceof X509Certificate) {
            xcert = (X509Certificate) o;
        } else if (o instanceof X509CertificateHolder) {
            try {
                xcert = new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) o);
            } catch (CertificateException ex) {
                return false;
            }
        } else {
            return false;
        }

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
}
