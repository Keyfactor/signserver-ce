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
package org.signserver.admin.common.auth;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import org.cesecore.util.CertTools;
import org.signserver.server.log.AdminInfo;

/**
 * Administrator info and roles for this client certificate authenticated and authorized
 * user.
 */
public class ClientCertAdminPrincipal implements AdminPrincipal {

    private static final int HEX_RADIX = 16;
    private final X509Certificate clientCert;
    private final List<String> roles;
    private AdminInfo adminInfo;

    public ClientCertAdminPrincipal(X509Certificate clientCert, List<String> roles) {
        this.clientCert = clientCert;
        this.roles = roles;
    }

    @Override
    public String getName() {
        String result;
        String cn = CertTools.getPartFromDN(clientCert.getSubjectX500Principal().getName(), "CN");
        if (cn == null || cn.isEmpty()) {
            result = clientCert.getSerialNumber().toString(HEX_RADIX);
        } else {
            result = cn;
        }
        return result;
    }

    @Override
    public List<String> getRoles() {
        return Collections.unmodifiableList(roles);
    }

    @Override
    public AdminInfo getAdminInfo() {
        if (adminInfo == null) {
            adminInfo = new AdminInfo(clientCert.getSubjectDN().getName(),
                    clientCert.getIssuerDN().getName(), clientCert.getSerialNumber().toString(HEX_RADIX));
        }
        return adminInfo;
    }

    public X509Certificate getClientCert() {
        return clientCert;
    }

    @Override
    public String toString() {
        return "ClientCertAdminPrincipal{" + "name: " + getName() + ", roles: " + roles + '}';
    }

}
