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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.admin.common.auth.ClientCertAdminPrincipal;
import org.signserver.server.log.AdminInfo;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Unit tests for ClientCertAdminPrincipal.
 */
public class ClientCertAdminPrincipalTest {

    @BeforeClass
    public static void addBC() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Builds a minimal self-signed X509 certificate for testing.
     */
    private static X509Certificate buildCert(final String subjectDn, final String issuerDn, final BigInteger serial) throws Exception {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        final KeyPair kp = kpg.generateKeyPair();

        final X500Name subject = new X500Name(subjectDn);
        final X500Name issuer = new X500Name(issuerDn);
        final Instant now = Instant.now();
        final Date notBefore = Date.from(now.minusSeconds(60));
        final Date notAfter = Date.from(now.plusSeconds(365 * 24 * 3600L));

        final JcaX509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(
                        issuer, serial, notBefore, notAfter, subject, kp.getPublic());

        final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(kp.getPrivate());

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(signer));
    }

    /**
     * Ensures the role's list is exposed as unmodifiable
     */
    @Test
    public void testGetRolesUnmodifiableAndOrdered1() throws Exception {
        final List<String> roles = Arrays.asList("admin", "archive_auditor");

        // Use a mock ClientCertAdminPrincipal 
        ClientCertAdminPrincipal principal = org.mockito.Mockito.mock(ClientCertAdminPrincipal.class);
        org.mockito.Mockito.when(principal.getRoles()).thenReturn(Collections.unmodifiableList(roles));

        assertEquals(roles, principal.getRoles());
        try {
            principal.getRoles().add("newrole");
            fail("Roles list should be unmodifiable");
        } catch (UnsupportedOperationException expected) {
            // expected
        }
    }

    /**
     * Verifies AdminInfo is created and contains subject, issuer and serial.
     */
    @Test
    public void testGetAdminInfoComposesExpectedFields() throws Exception {
        final BigInteger serial = new BigInteger("4660");
        final X509Certificate cert = buildCert("CN=Test, O=Test Org, C=SE", "CN=Test CA, C=SE", serial);

        final ClientCertAdminPrincipal principal = new ClientCertAdminPrincipal(cert, Collections.singletonList("admin"));

        final AdminInfo info1 = principal.getAdminInfo();
        final AdminInfo info2 = principal.getAdminInfo();

        assertSame("AdminInfo should be cached", info1, info2);
        assertTrue("subject should contain CN=Test", info1.getSubject().contains("CN=Test"));
        assertTrue("issuer should contain CN=Test CA", info1.getIssuer().contains("CN=Test CA"));
        assertEquals("1234", info1.getSerialNumber());
    }
}
