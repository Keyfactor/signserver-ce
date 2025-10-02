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

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;

/**
 * Unit tests for ClientCert.
 */
public class ClientCertTest {
    private static final Logger LOG = Logger.getLogger(String.valueOf(ClientCertTest.class));

    @BeforeClass
    public static void setupProvider() {
        LOG.info("setupProvider");
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Verifies ClientCert class handles null input. Test constructing a ClientCert with a null X509Certificate.
     */
    @Test
    public void testConstructorNullCertEmptyFields() {
        LOG.info("testConstructorNullCertEmptyFields");
        final ClientCert clientCert = new ClientCert(null);

        assertEquals("", clientCert.getSerialNumber());
        assertEquals("", clientCert.getSubjectCN());
    }

}
