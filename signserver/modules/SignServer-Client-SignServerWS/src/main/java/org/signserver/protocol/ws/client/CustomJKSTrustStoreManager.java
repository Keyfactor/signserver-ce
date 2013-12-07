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
package org.signserver.protocol.ws.client;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * Custom trust store that reads all CA certs from
 * a JKS file.
 *
 * @author Philip Vendil 15 sep 2008
 * @version $Id$
 */
class CustomJKSTrustStoreManager implements X509TrustManager {

    KeyStore trustStore = null;

    CustomJKSTrustStoreManager(String trustStorePath, String trustStorePwd) throws Exception {
        trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream(trustStorePath), trustStorePwd.toCharArray());

    }

    public void checkClientTrusted(X509Certificate[] arg0, String arg1)
            throws CertificateException {
        // Not Implemented
    }

    public void checkServerTrusted(X509Certificate[] certs, String authType)
            throws CertificateException {
        for (X509Certificate cert : certs) {
            if (cert.getBasicConstraints() != -1) {
                try {
                    if (trustStore.getCertificateAlias(cert) == null) {
                        throw new CertificateException("Error, CA certificate with DN " + cert.getSubjectDN().toString() + " not found in trust store.");
                    }
                } catch (KeyStoreException e) {
                    throw new CertificateException("Error retrieving certificate with DN " + cert.getSubjectDN().toString() + " from trust store.");
                }
            }
        }

    }

    public X509Certificate[] getAcceptedIssuers() {
        //Not supported
        return null;
    }
}
