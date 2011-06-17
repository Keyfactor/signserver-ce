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
package org.signserver.client.cli;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509KeyManager;

/**
 * KeyManager choosing the specified alias.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class AliasKeyManager implements X509KeyManager {

    private final X509KeyManager base;
    private final String alias;

    public AliasKeyManager(final X509KeyManager base, final String alias) {
        this.base = base;
        this.alias = alias;
    }

    @Override
    public String[] getClientAliases(String string, Principal[] prncpls) {
        return base.getClientAliases(string, prncpls);
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers,
            Socket socket) {
        return alias;
    }

    @Override
    public String[] getServerAliases(String string, Principal[] prncpls) {
        return base.getClientAliases(string, prncpls);
    }

    @Override
    public String chooseServerAlias(String string, Principal[] prncpls,
            Socket socket) {
        return base.chooseServerAlias(string, prncpls, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String string) {
        return base.getCertificateChain(string);
    }

    @Override
    public PrivateKey getPrivateKey(String string) {
        return base.getPrivateKey(string);
    }
}
