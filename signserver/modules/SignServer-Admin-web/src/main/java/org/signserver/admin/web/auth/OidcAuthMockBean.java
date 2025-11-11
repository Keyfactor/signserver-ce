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

import jakarta.enterprise.inject.Alternative;
import org.signserver.admin.common.auth.AdminPrincipal;

/**
 * Alternative implementation when OIDC is not enabled.
 */
@Alternative
public class OidcAuthMockBean implements OidcAuth {

    @Override
    public OidcTokens getClientTokens() {
        return null;
    }

    @Override
    public boolean isAudienceValidOrNotUsed() {
        return false;
    }

    @Override
    public boolean isOidcAuthenticated() {
        return false;
    }

    @Override
    public String getOidcLogoutRedirect() {
        return "";
    }

    @Override
    public String getOidcLoginLink() {
        return "";
    }

    @Override
    public String getOidcProviderLogoutUri() {
        return "";
    }

    @Override
    public String getOidcProviderUri() {
        return "";
    }

    @Override
    public AdminPrincipal getAdminPrincipal() {
        return null;
    }
}
