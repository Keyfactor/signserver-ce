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

import jakarta.json.JsonObject;
import jakarta.security.enterprise.identitystore.openid.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Optional;

/**
 * Mocked version of the OpenIdContext used for unit tests.
 */
public class MockOpenIdContext implements OpenIdContext {
    private IdentityToken identityToken;

    public MockOpenIdContext(IdentityToken identityToken) {
        this.identityToken = identityToken;
    }

    @Override
    public String getSubject() {
        return "";
    }

    @Override
    public String getTokenType() {
        return "";
    }

    @Override
    public AccessToken getAccessToken() {
        return null;
    }

    @Override
    public IdentityToken getIdentityToken() {
        return identityToken;
    }

    @Override
    public Optional<RefreshToken> getRefreshToken() {
        return Optional.empty();
    }

    @Override
    public Optional<Long> getExpiresIn() {
        return Optional.empty();
    }

    @Override
    public JsonObject getClaimsJson() {
        return null;
    }

    @Override
    public OpenIdClaims getClaims() {
        return null;
    }

    @Override
    public JsonObject getProviderMetadata() {
        return null;
    }

    @Override
    public <T> Optional<T> getStoredValue(HttpServletRequest request, HttpServletResponse response, String key) {
        return Optional.empty();
    }
}
