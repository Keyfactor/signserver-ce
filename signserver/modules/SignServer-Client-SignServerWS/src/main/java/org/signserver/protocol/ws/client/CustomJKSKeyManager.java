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
import java.net.Socket;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

import javax.net.ssl.X509KeyManager;

import org.apache.log4j.Logger;

/**
 * TODO: Document me!
 *
 * @author Philip Vendil 15 sep 2008
 * @version $Id$
 */
class CustomJKSKeyManager implements X509KeyManager {

    private static final Logger log = Logger.getLogger(CustomJKSKeyManager.class);
    KeyStore ks = null;
    char[] password = null;

    CustomJKSKeyManager(String keyStorePath, String keyStorePwd) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        password = keyStorePwd.toCharArray();
        trustStore.load(new FileInputStream(keyStorePath), password);

    }

    public String chooseClientAlias(String[] keyType, Principal[] issuers,
            Socket socket) {
        return chooseAlias(issuers);
    }

    public String chooseServerAlias(String keyType, Principal[] issuers,
            Socket socket) {
        return chooseAlias(issuers);
    }

    private String chooseAlias(Principal[] issuers) {
        String retval = null;
        try {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                if (cert.getBasicConstraints() == -1) {
                    Principal certIssuer = cert.getIssuerDN();
                    for (Principal issuer : issuers) {
                        if (issuer.equals(certIssuer)) {
                            retval = alias;
                            break;
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error fetchin alias from client key store", e);
        }

        return retval;
    }

    public X509Certificate[] getCertificateChain(String alias) {
        try {
            return (X509Certificate[]) ks.getCertificateChain(alias);
        } catch (Exception e) {
            log.error("Error fetching certificate chain for the logon certificate : " + e.getMessage(), e);
            return null;
        }
    }

    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return getAliases(issuers);

    }

    private String[] getAliases(Principal[] issuers) {
        ArrayList<String> retval = null;
        try {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                if (cert.getBasicConstraints() == -1) {
                    Principal certIssuer = cert.getIssuerDN();
                    for (Principal issuer : issuers) {
                        if (issuer.equals(certIssuer)) {
                            retval.add(alias);
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error fetchin alias from client key store", e);
        }

        return retval.toArray(new String[retval.size()]);
    }

    public PrivateKey getPrivateKey(String alias) {
        try {
            return (PrivateKey) ks.getKey(alias, password);
        } catch (Exception e) {
            log.error("Error fetching private key for the logon certificate : " + e.getMessage(), e);
            return null;
        }
    }

    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return getAliases(issuers);
    }
}
