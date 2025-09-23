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

import jakarta.security.enterprise.identitystore.openid.IdentityToken;
import jakarta.security.enterprise.identitystore.openid.JwtClaims;

import java.util.Map;

/**
 * Mocked version of the IdentityToken used for unit tests.
 */
public class MockIdentityToken implements IdentityToken {

    private final String token;
    private final JwtClaims jwtClaims;
    private final boolean expired;
    private final Map<String, Object> claims;

    public MockIdentityToken(String token, JwtClaims jwtClaims, boolean expired, Map<String, Object> claims) {
        this.token = token;
        this.jwtClaims = jwtClaims;
        this.expired = expired;
        this.claims = claims;
    }

    @Override
    public String getToken() {
        return token;
    }

    @Override
    public JwtClaims getJwtClaims() {
        return jwtClaims;
    }

    @Override
    public boolean isExpired() {
        return expired;
    }

    @Override
    public Map<String, Object> getClaims() {
        return claims;
    }
}

