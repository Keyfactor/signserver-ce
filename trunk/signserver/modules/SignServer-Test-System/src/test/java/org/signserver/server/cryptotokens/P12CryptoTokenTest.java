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
package org.signserver.server.cryptotokens;

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;
import java.util.Collections;
import java.util.Properties;

import junit.framework.TestCase;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.signserver.common.RequestContext;
import org.signserver.common.util.PathUtil;
import org.signserver.test.utils.mock.MockedServicesImpl;

/**
 * TODO: Document me!
 * 
 * TODO: This is a unit test consider moving from SignServer Test-System to SignServer-Server project.
 * 
 * @version $Id$
 */
public class P12CryptoTokenTest extends TestCase {

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        // Install BC Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    /*
     * Test method for 'org.signserver.server.HardCodedSignToken.getPrivateKey(int)'
     * 
     * Makes sure that the private key verifies with the public key in the certificate.
     */
    public void testGetPrivateKey() throws Exception {
        Signature sig = null;
        String signatureAlgorithm = "SHA256WITHRSAANDMGF1";

        P12CryptoToken signToken = new P12CryptoToken();
        Properties props = new Properties();
        final String signserverhome = PathUtil.getAppHome().getAbsolutePath();
        assertNotNull(signserverhome);
        props.setProperty("KEYSTOREPATH", signserverhome + "/res/test/timestamp1.p12");
        signToken.init(1, props, new MockedServicesImpl());

        signToken.activate("foo123", null);

        try {
            sig = Signature.getInstance(signatureAlgorithm, "BC");
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException("exception creating signature: " + e.toString());
        }

        RequestContext context = new RequestContext(true);
        ICryptoInstance crypto = null;
        try {
            crypto = signToken.acquireCryptoInstance("timestamptest", Collections.<String, Object>emptyMap(), context);
            sig.initSign(crypto.getPrivateKey());

            try {
                sig.update("Hello World".getBytes());
            } catch (Exception e) {
                throw new SecurityException("Error updating with string " + e);
            }

            byte[] result = sig.sign();

            sig.initVerify(crypto.getPublicKey());
            sig.update("Hello World".getBytes());
            assertTrue(sig.verify(result));

            assertTrue(signToken.deactivate(null));
        } finally {
            signToken.releaseCryptoInstance(crypto, context);
        }
    }
}
