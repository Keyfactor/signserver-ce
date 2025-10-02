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

package org.signserver.admin.roles;

import org.junit.Test;
import org.signserver.admin.common.roles.AdminEntry;
import org.signserver.admin.common.roles.AdminsUtil;
import org.signserver.common.ClientEntry;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


/**
 * Verifies parsing of admin role strings and serialization of role maps.
 */
public class AdminsUtilTest {

    /**
     * Ensures that parseAdmins creates entries for all role categories.
     */
    @Test
    public void testParseAdminsAllRoles() {
        final String admins = "1a2b3c,ISSUER A;abcdef,ISSUER B;";
        final String auditors = "abcdef,ISSUER B;ff,ISSUER C;";
        final String archiveAuditors = "ff,ISSUER C;";
        final String peers = "1234,ISSUER D;";

        final LinkedHashMap<ClientEntry, AdminEntry> map =
                AdminsUtil.parseAdmins(admins, auditors, archiveAuditors, peers);

        assertEquals(4, map.size());

        final AdminEntry a = map.get(new ClientEntry(new BigInteger("1a2b3c", 16), "ISSUER A"));
        final AdminEntry b = map.get(new ClientEntry(new BigInteger("abcdef", 16), "ISSUER B"));
        final AdminEntry c = map.get(new ClientEntry(new BigInteger("ff", 16), "ISSUER C"));
        final AdminEntry d = map.get(new ClientEntry(new BigInteger("1234", 16), "ISSUER D"));

        assertNotNull(a);
        assertTrue(a.isAdmin());
        assertFalse(a.isAuditor());
        assertFalse(a.isArchiveAuditor());
        assertFalse(a.isPeerSystem());

        assertNotNull(b);
        assertTrue(b.isAdmin());
        assertTrue(b.isAuditor());
        assertFalse(b.isArchiveAuditor());
        assertFalse(b.isPeerSystem());

        assertNotNull(c);
        assertFalse(c.isAdmin());
        assertTrue(c.isAuditor());
        assertTrue(c.isArchiveAuditor());
        assertFalse(c.isPeerSystem());

        assertNotNull(d);
        assertFalse(d.isAdmin());
        assertFalse(d.isAuditor());
        assertFalse(d.isArchiveAuditor());
        assertTrue(d.isPeerSystem());
    }

    /**
     * Ensures serialize methods only include entries with the respective role and keep order.
     */
    @Test
    public void testSerializeByRole() {
        final LinkedHashMap<ClientEntry, AdminEntry> map = new LinkedHashMap<>();

        final ClientEntry c1 = new ClientEntry(new BigInteger("1a", 16), "ISSUER A");
        final ClientEntry c2 = new ClientEntry(new BigInteger("2b", 16), "ISSUER B");
        final ClientEntry c3 = new ClientEntry(new BigInteger("3c", 16), "ISSUER C");
        final ClientEntry c4 = new ClientEntry(new BigInteger("4d", 16), "ISSUER D");

        final AdminEntry e1 = new AdminEntry(c1);
        e1.setAdmin(true);
        final AdminEntry e2 = new AdminEntry(c2);
        e2.setAuditor(true);
        final AdminEntry e3 = new AdminEntry(c3);
        e3.setArchiveAuditor(true);
        final AdminEntry e4 = new AdminEntry(c4);
        e4.setPeerSystem(true);

        map.put(c1, e1);
        map.put(c2, e2);
        map.put(c3, e3);
        map.put(c4, e4);

        assertEquals("1a,ISSUER A;", AdminsUtil.serializeAdmins(map));
        assertEquals("2b,ISSUER B;", AdminsUtil.serializeAuditors(map));
        assertEquals("3c,ISSUER C;", AdminsUtil.serializeArchiveAuditors(map));
        assertEquals("4d,ISSUER D;", AdminsUtil.serializePeerSystems(map));
    }


    /**
     * Tests getRolesString with multiple roles.
     */
    @Test
    public void testGetRolesStringMultipleRoles() {
        final List<String> roles = Arrays.asList("admin", "auditor", "archive_auditor");
        final String result = AdminsUtil.getRolesString(roles);
        assertEquals("admin, auditor, archive_auditor", result);
    }

    /**
     * Tests getRolesString with a single role.
     */
    @Test
    public void testGetRolesStringSingleRole() {
        final List<String> roles = Arrays.asList("admin");
        final String result = AdminsUtil.getRolesString(roles);
        assertEquals("admin", result);
    }

    /**
     * Tests getRolesString with an empty list.
     */
    @Test
    public void testGetRolesStringEmptyList() {
        final List<String> roles = Arrays.asList();
        final String result = AdminsUtil.getRolesString(roles);
        assertEquals("", result);
    }
}
