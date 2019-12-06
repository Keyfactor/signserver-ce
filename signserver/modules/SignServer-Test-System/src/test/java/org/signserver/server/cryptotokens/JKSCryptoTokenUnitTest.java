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

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Collections;
import java.util.Properties;

import junit.framework.TestCase;
import static junit.framework.TestCase.assertTrue;
import org.signserver.common.RequestContext;
import org.signserver.common.util.PathUtil;
import org.signserver.test.utils.mock.MockedServicesImpl;

/**
 * Tests for a crypto token that uses a Java Keystore (JKS) file.
 * 
 * TODO: This is a unit test consider moving from SignServer Test-System to SignServer-Server project.
 *
 * @version $Id$
 */
public class JKSCryptoTokenUnitTest extends TestCase {

    /** Project base directory. */
    private File homeDir;

    @Override
    protected void setUp() throws Exception {
        homeDir = PathUtil.getAppHome();
        assertTrue("SIGNSERVER_HOME nonexisting directory", homeDir.exists());
    }

    /**
     * Makes sure that the private key verifies with the public key in the
     * certificate.
     * @throws Exception
     */
    public final void testGetPrivateKeyWithRSA() throws Exception {
        signTester("SHA256WITHRSA", "/res/test/xmlsigner2.jks", "xmlsigner2aalias");
    }

    /**
     * Makes sure that the private key verifies with the public key in the
     * certificate.
     * @throws Exception
     */
    public final void testGetPrivateKeyWithDSA() throws Exception {
        signTester("SHA1WITHDSA", "/res/test/xmlsigner4.jks", "xmlsigner4");
    }

    public final void signTester(final String signatureAlgorithm, final String file, final String alias)
            throws Exception {
        Signature sig = null;

        // Create crypto token
        final JKSCryptoToken signToken = new JKSCryptoToken();
        final Properties props = new Properties();

        props.setProperty("KEYSTOREPATH",
                new File(homeDir, file).getAbsolutePath());
        signToken.init(1, props, new MockedServicesImpl());

        // Activate
        signToken.activate("foo123", null);
        
        try {
            sig = Signature.getInstance(signatureAlgorithm, "BC");
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException("exception creating signature: " + e.toString());
        }

        RequestContext context = new RequestContext(true);
        ICryptoInstance crypto = null;
        try {
            crypto = signToken.acquireCryptoInstance(alias, Collections.<String, Object>emptyMap(), context);
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
