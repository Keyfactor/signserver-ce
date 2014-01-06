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

import java.security.KeyPair;
import java.security.Security;
import javax.crypto.Cipher;
import junit.framework.TestCase;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.util.Base64;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.common.IllegalRequestException;

/**
 * Tests for the ExtendedHardCodedCryptoToken.
 * 
 * @version $Id$
 */
public class ExtendedHardCodedCryptoTokenTest extends TestCase {

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        // Install BC Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Fails if for instance running Oracle JRE and the JCE strong encryption 
     * policy has not been installed. In that case the maximum key length for 
     * DES is as low as 64 or at least not Integer.MAX_VALUE.
     * @throws Exception in case of error
     */
    public void testStrongCryptoAvailable() throws Exception {
        assertEquals("JCE crypto policy was not installed as the key length was limited",
                Integer.MAX_VALUE, Cipher.getMaxAllowedKeyLength("DES"));
    }

    /*
     * Test method for 'org.signserver.server.HardCodedSignToken.getPrivateKey(int)'
     * 
     * Makes sure that the private key verifies with the public key in the certificate.
     */
    public void testEncryptDecryptData() throws Exception {
        ExtendedHardCodedCryptoToken ehct = new ExtendedHardCodedCryptoToken();
        String keyRefAES = ehct.genNonExportableKey("AES", "256");
        assertTrue(keyRefAES.startsWith(ExtendedHardCodedCryptoToken.KEYREF_AES256KEY));

        byte[] orgdata = "HELLO".getBytes();
        byte[] encdata = ehct.encryptData(keyRefAES, orgdata);
        assertFalse(new String(orgdata).equals(new String(encdata)));

        byte[] data = ehct.decryptData(keyRefAES, encdata);
        assertTrue(new String(data), new String(orgdata).equals(new String(data)));

        String keyRefRSA = ehct.genNonExportableKey("RSA", "1024");
        assertTrue(keyRefRSA.startsWith(ExtendedHardCodedCryptoToken.KEYREF_RSA1024KEY));
        byte[] orgdata2 = "HELLO2".getBytes();
        byte[] encdata2 = ehct.encryptData(keyRefRSA, orgdata2);
        assertFalse(new String(orgdata2).equals(new String(encdata2)));

        byte[] data2 = ehct.decryptData(keyRefRSA, encdata2);
        assertTrue(new String(data2), new String(orgdata2).equals(new String(data2)));
    }

    public void testGenExportableKey() throws Exception {
        ExtendedHardCodedCryptoToken ehct = new ExtendedHardCodedCryptoToken();
        SecretKey key = (SecretKey) ehct.genExportableKey("AES", "256");
        assertNotNull(key);
        KeyPair keys = (KeyPair) ehct.genExportableKey("RSA", "1024");
        KeyTools.testKey(keys.getPrivate(), keys.getPublic(), "BC");
        try {
            ehct.genExportableKey("ASE", "256");
            assertTrue(false);
        } catch (IllegalRequestException e) {
        }
    }
}
