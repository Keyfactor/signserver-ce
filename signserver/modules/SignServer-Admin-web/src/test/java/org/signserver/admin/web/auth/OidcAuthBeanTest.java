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

import jakarta.security.enterprise.SecurityContext;
import jakarta.security.enterprise.identitystore.openid.IdentityToken;
import jakarta.security.enterprise.identitystore.openid.JwtClaims;
import jakarta.security.enterprise.identitystore.openid.OpenIdClaims;
import jakarta.security.enterprise.identitystore.openid.OpenIdContext;
import org.junit.Test;
import org.signserver.admin.common.auth.AdminPrincipal;
import org.signserver.admin.common.auth.OidcAdminPrincipal;
import org.signserver.admin.common.config.OidcConfig;
import org.signserver.server.log.AdminInfo;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


/**
 * Verifies authentication checks, audience validation, token exposure,
 * logout redirect building, provider URIs, and admin principal construction.
 */
public class OidcAuthBeanTest {
    
    /**
     * isOidcAuthenticated is true only when context and identity token exist.
     */
    @Test
    public void testIsOidcAuthenticated() {
        OidcAuthBean oidcAuthBean = new OidcAuthBean();

        // No context
        oidcAuthBean.setContext(null);
        assertFalse(oidcAuthBean.isOidcAuthenticated());

        // Context without token
        OpenIdContext ctx = mock(OpenIdContext.class);
        when(ctx.getIdentityToken()).thenReturn(null);
        oidcAuthBean.setContext(ctx);
        assertFalse(oidcAuthBean.isOidcAuthenticated());

        // Context with token
        when(ctx.getIdentityToken()).thenReturn(mock(IdentityToken.class));
        assertTrue(oidcAuthBean.isOidcAuthenticated());
    }

    /**
     * Audience validation returns true if audience unset, or contained in token claims.
     */
    @Test
    public void testIsAudienceValidOrNotUsed() {
        OidcAuthBean oidcAuthBean = new OidcAuthBean();

        // Config with no audience set => always true
        OidcConfig cfg = new OidcConfig();
        cfg.setAudience("");
        oidcAuthBean.setOidcConfig(cfg);
        oidcAuthBean.setContext(null);
        assertTrue(oidcAuthBean.isAudienceValidOrNotUsed());

        // Config with audience set and present in token
        cfg.setAudience("aud");
        IdentityToken id = mock(IdentityToken.class);
        JwtClaims jwt = mock(JwtClaims.class);
        when(jwt.getAudience()).thenReturn(List.of("aud", "aud"));
        when(id.getJwtClaims()).thenReturn(jwt);
        OpenIdContext ctx = mock(OpenIdContext.class);
        when(ctx.getIdentityToken()).thenReturn(id);
        oidcAuthBean.setContext(ctx);
        assertTrue(oidcAuthBean.isAudienceValidOrNotUsed());

        // Audience not present
        when(jwt.getAudience()).thenReturn(List.of("other"));
        assertFalse(oidcAuthBean.isAudienceValidOrNotUsed());
    }

    /**
     * getClientTokens returns tokens built from context.
     */
    @Test
    public void testGetClientTokens() {
        OidcAuthBean oidcAuthBean = new OidcAuthBean();
        OpenIdContext ctx = mock(OpenIdContext.class);
        IdentityToken id = mock(IdentityToken.class);
        JwtClaims jwt = mock(JwtClaims.class);
        OpenIdClaims claims = mock(OpenIdClaims.class);

        when(ctx.getSubject()).thenReturn("sub");
        when(ctx.getIdentityToken()).thenReturn(id);
        when(id.getJwtClaims()).thenReturn(jwt);
        when(jwt.getIssuer()).thenReturn(Optional.of("iss"));
        when(ctx.getClaims()).thenReturn(claims);
        when(claims.getPreferredUsername()).thenReturn(Optional.of("user"));

        oidcAuthBean.setContext(ctx);

        OidcTokens t1 = oidcAuthBean.getClientTokens();
        OidcTokens t2 = oidcAuthBean.getClientTokens();
        assertSame(t1, t2);
        assertEquals("sub", t1.getSubject());
        assertEquals("iss", t1.getIssuer());
        assertEquals("user", t1.getPreferredUsername());
    }

     /**
     * Logout redirect is constructed using provider logout URI, client_id and encoded returnTo.
     * Uses a mocked OidcConfig to avoid null injections.
     */
    @Test
    public void testGetOidcLogoutRedirect() {
        OidcAuthBean oidcAuthBean = new OidcAuthBean();

        OidcConfig cfg = mock(OidcConfig.class);
        when(cfg.getProviderLogOutUri()).thenReturn("https://idp/logout");
        when(cfg.getLogoutUri()).thenReturn("https://signserver");
        when(cfg.getClientId()).thenReturn("client-123");
        oidcAuthBean.setOidcConfig(cfg);

        String expected = "https://idp/logout"
                + "?client_id=client-123"
                + "&returnTo=" + URLEncoder.encode("https://signserver", StandardCharsets.UTF_8);
        assertEquals(expected, oidcAuthBean.getOidcLogoutRedirect());
    }


    /**
     * Simple test fo getters for configured URIs.
     */
    @Test
    public void testProviderAndLoginUris() {
        OidcAuthBean oidcAuthBean = new OidcAuthBean();
        OidcConfig cfg = new OidcConfig();
        cfg.setLoginUri("https://signserver/adminweb/callback");
        cfg.setProviderUri("https://idp");
        cfg.setProviderLogOutUri("https://idp/logout");
        oidcAuthBean.setOidcConfig(cfg);

        assertEquals("https://signserver/adminweb/callback", oidcAuthBean.getOidcLoginLink());
        assertEquals("https://idp", oidcAuthBean.getOidcProviderUri());
        assertEquals("https://idp/logout", oidcAuthBean.getOidcProviderLogoutUri());
    }

    /**
     * getAdminPrincipal maps SecurityContext roles to AdminPrincipal with AdminInfo from tokens.
     */
    @Test
    public void testGetAdminPrincipalUsesRolesAndTokens() {
        OidcAuthBean oidcAuthBean = new OidcAuthBean();

        // Mock context and tokens
        OpenIdContext openIdContext = mock(OpenIdContext.class);
        IdentityToken identityToken = mock(IdentityToken.class);
        JwtClaims jwtClaims = mock(JwtClaims.class);
        OpenIdClaims claims = mock(OpenIdClaims.class);
        when(openIdContext.getSubject()).thenReturn("sub"); // check mapped TODO
        when(openIdContext.getIdentityToken()).thenReturn(identityToken);
        when(identityToken.getJwtClaims()).thenReturn(jwtClaims);
        when(jwtClaims.getIssuer()).thenReturn(Optional.of("iss"));
        when(openIdContext.getClaims()).thenReturn(claims);
        when(claims.getPreferredUsername()).thenReturn(Optional.of("serial"));  // check mapped TODO
        oidcAuthBean.setContext(openIdContext);

        // Mock security roles
        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.isCallerInRole("admin")).thenReturn(true);
        when(securityContext.isCallerInRole("auditor")).thenReturn(false);
        when(securityContext.isCallerInRole("archive_auditor")).thenReturn(true);
        // inject via reflection since a field is @Inject and package-private
        try {
            var field = OidcAuthBean.class.getDeclaredField("securityContext");
            field.setAccessible(true);
            field.set(oidcAuthBean, securityContext);
        } catch (Exception e) {
            fail("Failed to inject SecurityContext: " + e.getMessage());
        }

        // Also need to add OidcConfig heree
        OidcConfig oidcConfig = new OidcConfig();
        oidcAuthBean.setOidcConfig(oidcConfig);

        AdminPrincipal principal = oidcAuthBean.getAdminPrincipal();
        assertTrue(principal instanceof OidcAdminPrincipal);

        // Roles should contain admin and archive_auditor
        var roles = principal.getRoles();
        assertTrue(roles.contains("admin"));
        assertFalse(roles.contains("auditor"));
        assertTrue(roles.contains("archive_auditor"));

        // AdminInfo should reflect tokens
        AdminInfo info = principal.getAdminInfo();
        assertEquals("serial", info.getSubject()); // check mapped TODO
        assertEquals("iss", info.getIssuer());
        assertEquals("sub", info.getSerialNumber()); // check mapped TODO
    }
}
