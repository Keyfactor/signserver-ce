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

import jakarta.security.enterprise.identitystore.openid.OpenIdContext;

/**
 * Representation of OIDC tokens for display on login page etc.
 */
public class OidcTokens {
    
    private final String subject;
    private final String issuer;
    private final String preferredUsername;
    
    public OidcTokens(OpenIdContext context) {
        if (context == null || context.getIdentityToken() == null) {
            this.subject = "";
            this.issuer = "";
            this.preferredUsername = "";
        } else {
            this.subject = context.getSubject();
            this.issuer = context.getIdentityToken().getJwtClaims().getIssuer().orElse("");
            this.preferredUsername = context.getClaims().getPreferredUsername().orElse("");
        }
    }

    public String getSubject() {
        return subject;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getPreferredUsername() {
        return preferredUsername;
    }

}
