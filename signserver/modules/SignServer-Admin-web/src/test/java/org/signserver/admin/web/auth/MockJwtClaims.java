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

import jakarta.security.enterprise.identitystore.openid.Claims;
import jakarta.security.enterprise.identitystore.openid.JwtClaims;

import java.time.Instant;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;
import java.util.List;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.OptionalDouble;

/**
 * Mocked version of the JwtClaims used for unit tests.
 */
public class MockJwtClaims implements JwtClaims {
    private final Map<String, Object> claimMap;

    public MockJwtClaims(Map<String, Object> claimMap) {
        this.claimMap = new HashMap<>(claimMap);
    }

    public Object getClaim(String name) {
        return claimMap.get(name);
    }

    public Map<String, Object> getAllClaims() {
        return claimMap;
    }

    @Override
    public Optional<String> getStringClaim(String name) {
        return Optional.empty();
    }

    @Override
    public Optional<Instant> getNumericDateClaim(String name) {
        return Optional.empty();
    }

    @Override
    public List<String> getArrayStringClaim(String name) {
        return List.of();
    }

    @Override
    public OptionalInt getIntClaim(String name) {
        return OptionalInt.empty();
    }

    @Override
    public OptionalLong getLongClaim(String name) {
        return OptionalLong.empty();
    }

    @Override
    public OptionalDouble getDoubleClaim(String name) {
        return OptionalDouble.empty();
    }

    @Override
    public Optional<Claims> getNested(String name) {
        return Optional.empty();
    }

    @Override
    public List<String> getAudience() {
        return (List<String>) claimMap.get("aud");
    }
}
