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

import java.util.List;
import org.signserver.server.log.AdminInfo;

/**
 * Administrator info and roles for this OIDC authenticated and authorized user.
 */
public class OidcAdminPrincipal implements AdminPrincipal {
    
    private final String name;
    private final List<String> roles;
    private final AdminInfo adminInfo;

    public OidcAdminPrincipal(String name, List<String> roles, AdminInfo adminInfo) {
        this.name = name;
        this.roles = roles;
        this.adminInfo = adminInfo;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public List<String> getRoles() {
        return roles;
    }

    @Override
    public AdminInfo getAdminInfo() {
        return adminInfo;
    }

    @Override
    public String toString() {
        return "OidcAdminPrincipal{" + "name: " + name + ", roles: " + roles + '}';
    }

}
