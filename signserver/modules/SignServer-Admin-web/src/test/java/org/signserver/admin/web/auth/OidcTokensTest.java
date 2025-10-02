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
import jakarta.security.enterprise.identitystore.openid.OpenIdClaims;
import jakarta.security.enterprise.identitystore.openid.OpenIdContext;
import jakarta.security.enterprise.identitystore.openid.JwtClaims;
import org.junit.Test;

import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Verifies extraction of a subject, issuer and preferred username
 * and handling of null/absent context or tokens.
 */
public class OidcTokensTest {

    /**
     * Ensures empty fields when context is null.
     */
    @Test
    public void testConstructorNullContextEmptyFields() {
        // Act
        OidcTokens tokens = new OidcTokens(null);
        // Assert
        assertEquals("", tokens.getSubject());
        assertEquals("", tokens.getIssuer());
        assertEquals("", tokens.getPreferredUsername());
    }

    /**
     * Ensures empty fields when an identity token is missing.
     */
    @Test
    public void testConstructorNoIdentityTokenEmptyFields() {
        // Mocks
        OpenIdContext ctx = mock(OpenIdContext.class);
        // When
        when(ctx.getIdentityToken()).thenReturn(null);
        // Act
        OidcTokens tokens = new OidcTokens(ctx);
        // Assert
        assertEquals("", tokens.getSubject());
        assertEquals("", tokens.getIssuer());
        assertEquals("", tokens.getPreferredUsername());
    }

    /**
     * Extracts subject, issuer and preferred username from context and claims.
     */
    @Test
    public void constructor_WithTokens_ExtractsFields() {
        // Mocks
        OpenIdContext openIdContext = mock(OpenIdContext.class);
        IdentityToken identityToken = mock(IdentityToken.class);
        JwtClaims jwtClaims = mock(JwtClaims.class);
        OpenIdClaims openIdClaims = mock(OpenIdClaims.class);
        // When
        when(openIdContext.getSubject()).thenReturn("sub-123");
        when(openIdContext.getIdentityToken()).thenReturn(identityToken);
        when(identityToken.getJwtClaims()).thenReturn(jwtClaims);
        when(jwtClaims.getIssuer()).thenReturn(Optional.of("https://issuer.example"));
        when(openIdContext.getClaims()).thenReturn(openIdClaims);
        when(openIdClaims.getPreferredUsername()).thenReturn(Optional.of("alice"));
        // Act
        OidcTokens tokens = new OidcTokens(openIdContext);
        // Assert
        assertEquals("sub-123", tokens.getSubject());
        assertEquals("https://issuer.example", tokens.getIssuer());
        assertEquals("alice", tokens.getPreferredUsername());
    }

    /**
     * Falls back to empty strings when optional values are absent.
     */
    @Test
    public void testConstructorWithMissingOptionalClaimUsesEmptyDefaults() {
        // Mocks
        OpenIdContext openIdContext = mock(OpenIdContext.class);
        IdentityToken identityToken = mock(IdentityToken.class);
        JwtClaims jwtClaims = mock(JwtClaims.class);
        OpenIdClaims openIdClaims = mock(OpenIdClaims.class);
        // When
        when(openIdContext.getSubject()).thenReturn("sub-xyz");
        when(openIdContext.getIdentityToken()).thenReturn(identityToken);
        when(identityToken.getJwtClaims()).thenReturn(jwtClaims);
        when(jwtClaims.getIssuer()).thenReturn(Optional.empty());
        when(openIdContext.getClaims()).thenReturn(openIdClaims);
        when(openIdClaims.getPreferredUsername()).thenReturn(Optional.empty());
        // Act
        OidcTokens tokens = new OidcTokens(openIdContext);
        // Assert
        assertEquals("sub-xyz", tokens.getSubject());
        assertEquals("", tokens.getIssuer());
        assertEquals("", tokens.getPreferredUsername());
    }
}
