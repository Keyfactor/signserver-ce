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

import org.junit.Before;
import org.junit.Test;
import org.signserver.common.GlobalConfiguration;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.server.log.AdminInfo;

import javax.security.auth.Subject;
import java.util.List;

import org.apache.log4j.Logger;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.mockito.Mockito;

/**
 * Unit tests for AdminAuthHelper.requireAdminAuthorization.
 */
public class AdminAuthHelperTest {
    private static final Logger LOG = Logger.getLogger(AdminAuthHelperTest.class);

    private GlobalConfigurationSessionLocal globalSession;
    private GlobalConfiguration globalConfig;
    private AdminAuthHelper helper;

    @Before
    public void setUp() {
        globalSession = mock(GlobalConfigurationSessionLocal.class);
        globalConfig = mock(GlobalConfiguration.class);
        when(globalSession.getGlobalConfiguration()).thenReturn(globalConfig);
        helper = new AdminAuthHelper(globalSession);
    }

    /**
     * Test that null principal throws an exception with a message indicating a client cert is required.
     */
    @Test
    public void testNullPrincipalThrowsNotAuthorizedWithClientCertMessage() {
        LOG.info("testNullPrincipalThrowsNotAuthorizedWithClientCertMessage");
        AdminNotAuthorizedException ex = assertThrows(
                AdminNotAuthorizedException.class,
                () -> helper.requireAdminAuthorization(null, "test", "a", "b")
        );
        assertTrue(ex.getMessage().contains("Client certificate authentication required"));
    }

    /**
     * Test that an unsupported principal type throws an exception with a message indicating an unsupported principal type.
     */
    @Test
    public void testUnsupportedPrincipalTypeThrowsNotAuthorized() throws AdminNotAuthorizedException {
        LOG.info("testUnsupportedPrincipalTypeThrowsNotAuthorized");
        // Create an AdminPrincipal that is not ClientCertAdminPrincipal nor OidcAdminPrincipal
        AdminPrincipal unsupported = new AdminPrincipal() {
            @Override
            public String getName() {
                return "";
            }

            @Override
            public boolean implies(Subject subject) {
                return AdminPrincipal.super.implies(subject);
            }

            @Override
            public List<String> getRoles() {
                return List.of("admin");
            }

            @Override
            public AdminInfo getAdminInfo() {
                return new AdminInfo("subject", "issuer", "123");
            }
        };
        AdminNotAuthorizedException ex = assertThrows(AdminNotAuthorizedException.class,
                () -> helper.requireAdminAuthorization(unsupported, "testOperation"));
        assertTrue(ex.getMessage().startsWith("Unsupported principal"));
    }

    /**
     * Test that an admin principal returns the admin info.
     *
     * @throws Exception
     */
    @Test
    public void testAdminRoleReturnsAdminInfo() throws Exception {
        LOG.info("testAdminRoleReturnsAdminInfo");
        AdminInfo info = new AdminInfo("subjectA", "issuerA", "snA");
        AdminPrincipal principal = mock(AdminPrincipal.class);
        when(principal.getRoles()).thenReturn(List.of("user", "admin"));
        when(principal.getAdminInfo()).thenReturn(info);

        OidcAdminPrincipal oidc = Mockito.mock(OidcAdminPrincipal.class);
        when(oidc.getRoles()).thenReturn(List.of("user", "admin"));
        when(oidc.getAdminInfo()).thenReturn(info);

        AdminInfo result = helper.requireAdminAuthorization(oidc, "performAction", "arg1");
        assertSame(info, result);
    }

    /**
     * Test that a non-admin principal throws an exception.
     */
    @Test
    public void testNonAdminRoleThrowsNotAuthorized() {
        LOG.info("testNonAdminRoleThrowsNotAuthorized");
        AdminInfo info = new AdminInfo("subjectB", "issuerB", "snB");
        OidcAdminPrincipal oidc = mock(OidcAdminPrincipal.class);
        when(oidc.getRoles()).thenReturn(List.of("auditor")); // no "admin"
        when(oidc.getAdminInfo()).thenReturn(info);

        AdminNotAuthorizedException ex = assertThrows(
                AdminNotAuthorizedException.class,
                () -> helper.requireAdminAuthorization(oidc, "Test operation")
        );
        assertTrue(ex.getMessage().contains("Administrator not authorized"));
    }
}
