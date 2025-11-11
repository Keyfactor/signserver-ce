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

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Named;
import jakarta.inject.Inject;
import jakarta.security.enterprise.SecurityContext;
import jakarta.security.enterprise.identitystore.openid.OpenIdContext;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import org.signserver.admin.common.auth.AdminPrincipal;
import org.signserver.admin.common.auth.OidcAdminPrincipal;
import org.signserver.admin.common.config.OidcConfig;
import org.signserver.server.log.AdminInfo;

/**
 * Supports OIDC.
 */
@Named(value = "oidcAuthBean")
@RequestScoped
public class OidcAuthBean implements OidcAuth {
    
    private OidcTokens tokens;
    
    @Inject
    private OpenIdContext context;
    
    @Inject
    private SecurityContext securityContext;

    @Inject
    OidcConfig oidcConfig;

    public OidcTokens getClientTokens() {
        if (tokens == null) {
            tokens = new OidcTokens(context);
        }
        return tokens;
    }

    public boolean isAudienceValidOrNotUsed() {
        boolean result = true;
        if (oidcConfig.getAudience() != null && !oidcConfig.getAudience().isEmpty()) {
            result = context.getIdentityToken().getJwtClaims().getAudience().contains(oidcConfig.getAudience());
        }
        return result;
    }

    public boolean isOidcAuthenticated() {
        return context != null && context.getIdentityToken() != null;
    }
    
    public String getOidcLoginLink() {
        return oidcConfig.getLoginUri();
    }

    public String getOidcProviderUri() {
        return oidcConfig.getProviderUri();
    }

    public String getOidcLogoutRedirect() {
        //boolean passIdToken = false; // With id_token_hint the user might not need to be prompted
        /*if (passIdToken) {
            //TODO is this used in Auth0? id_token_hint
            logoutLink += "&id_token_hint=" + idToken;
        }*/

        String logoutLink = oidcConfig.getProviderLogOutUri();
        //TODO maybe it is good to rename LogoutUri to returnToUri in oidcConfig?
        String encodedReturnToUri = URLEncoder.encode(oidcConfig.getLogoutUri(), StandardCharsets.UTF_8);
        logoutLink += "?client_id=" + oidcConfig.getClientId() + "&returnTo=" + encodedReturnToUri;
        return logoutLink;
    }

    public AdminPrincipal getAdminPrincipal() {
        final OidcTokens clientTokens = getClientTokens();
        final ArrayList<String> roles = new ArrayList<>(3);
        if (securityContext.isCallerInRole("admin")) {
            roles.add("admin");
        }
        if (securityContext.isCallerInRole("auditor")) {
            roles.add("auditor");
        }
        if (securityContext.isCallerInRole("archive_auditor")) {
            roles.add("archive_auditor");
        }
        
        final AdminInfo adminInfo = new AdminInfo(clientTokens.getSubject(),
                    clientTokens.getIssuer(), clientTokens.getPreferredUsername(), "Nothing");
        
        return new OidcAdminPrincipal(clientTokens.getSubject(), roles, adminInfo);
    }

    public void setContext(OpenIdContext context) {
        this.context = context;
    }

    public void setOidcConfig(OidcConfig oidcConfig) {
        this.oidcConfig = oidcConfig;
    }

    public String getOidcProviderLogoutUri() {
        return oidcConfig.getProviderLogOutUri();
    }
}
