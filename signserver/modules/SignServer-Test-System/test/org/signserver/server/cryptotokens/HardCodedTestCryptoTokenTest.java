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
import java.security.Signature;

import junit.framework.TestCase;

import org.signserver.common.SignServerUtil;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class HardCodedTestCryptoTokenTest extends TestCase {

    protected void setUp() throws Exception {
        super.setUp();

        // Install BC Provider
        SignServerUtil.installBCProvider();
    }

    /*
     * Test method for 'org.signserver.server.HardCodedSignToken.getPrivateKey(int)'
     * 
     * Makes sure that the private key verifies with the public key in the certificate.
     */
    public void testGetPrivateKey() throws Exception {
        Signature sig = null;
        String signatureAlgorithm = "SHA256WITHRSAANDMGF1";

        HardCodedCryptoToken signToken = new HardCodedCryptoToken();
        signToken.init(0, null);

        try {
            sig = Signature.getInstance(signatureAlgorithm, "BC");
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException("exception creating signature: " + e.toString());
        }


        sig.initSign(signToken.getPrivateKey(ICryptoToken.PURPOSE_SIGN));

        try {
            sig.update("Hello World".getBytes());
        } catch (Exception e) {
            throw new SecurityException("Error updating with string " + e);
        }

        byte[] result = sig.sign();

        sig.initVerify(signToken.getPublicKey(ICryptoToken.PURPOSE_SIGN));
        sig.update("Hello World".getBytes());
        assertTrue(sig.verify(result));
    }
}
