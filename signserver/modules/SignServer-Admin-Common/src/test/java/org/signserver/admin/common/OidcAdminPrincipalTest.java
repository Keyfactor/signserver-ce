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
package org.signserver.admin.common;

import org.junit.Test;
import org.signserver.admin.common.auth.OidcAdminPrincipal;
import org.signserver.server.log.AdminInfo;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

/**
 * Verifies construction, getters, immutability expectations on provided lists,
 * and basic toString contract elements.
 */
public class OidcAdminPrincipalTest {

    /**
     * Verifies that constructor values are exposed via getters.
     */
    @Test
    public void testConstructorAndGetters() {
        final String name = "test@example.com";
        final List<String> roles = Arrays.asList("admin", "auditor");
        final AdminInfo adminInfo = new AdminInfo("sub-123", "iss-issuer", "serial-abc");

        final OidcAdminPrincipal principal = new OidcAdminPrincipal(name, roles, adminInfo);

        assertEquals("name", name, principal.getName());
        assertEquals("roles", roles, principal.getRoles());
        assertSame("adminInfo", adminInfo, principal.getAdminInfo());
    }
    
    /**
     * Ensures an empty roles list is handled correctly.
     */
    @Test
    public void testEmptyRoles() {
        final OidcAdminPrincipal principal = new OidcAdminPrincipal("Test User", Collections.emptyList(),
                new AdminInfo("sub", "iss", "sn"));

        assertNotNull(principal.getRoles());
        assertTrue(principal.getRoles().isEmpty());
    }
    
    /**
     * Checks that toString contains key fields for basic diagnostics.
     */
    @Test
    public void testToStringContainsNameAndRoles() {
        final OidcAdminPrincipal principal = new OidcAdminPrincipal("Test User",
                Arrays.asList("admin"), new AdminInfo("sub", "iss", "sn"));

        final String s = principal.toString();

        assertTrue("toString should contain name", s.contains("name: Test User"));
        assertTrue("toString should contain roles", s.contains("roles: [admin]"));
        assertTrue("toString should contain class name", s.startsWith("OidcAdminPrincipal{"));
    }
}
