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

import java.util.Properties;

import junit.framework.TestCase;

/**
 * Tests that the hard token properties are set correctly for PKCS11 crypto tokens.
 * 
 * TODO: This is a unit test consider moving from SignServer Test-System to SignServer-Server project.
 *
 * @version $Id$
 */
public class CryptoTokenHelperTest extends TestCase {

    @Override
    protected void setUp() throws Exception {
    }

    public final void testSlotProperties() throws Exception {
        PKCS11CryptoToken token = new PKCS11CryptoToken();
        Properties prop = new Properties();
        prop.put("SHAREDLIBRARY", "/opt/nfast/toolkits/pkcs11/libcknfast.so");
        prop.put("SLOT", "1");
        prop.put("DEFAULTKEY", "default");
        prop.put("PIN", "1234");
        Properties p = CryptoTokenHelper.fixP11Properties(prop);
        assertEquals("{PIN=1234, DEFAULTKEY=default, sharedLibrary=/opt/nfast/toolkits/pkcs11/libcknfast.so, pin=1234, SLOT=1, defaultKey=default, SHAREDLIBRARY=/opt/nfast/toolkits/pkcs11/libcknfast.so, slot=1}", p.toString());
    }

    public final void testSlotIndexProperties() throws Exception {
        // When using nCipher we have to use slotListIndex instead of slot property
        PKCS11CryptoToken token = new PKCS11CryptoToken();
        Properties prop = new Properties();
        prop.put("SHAREDLIBRARY", "/opt/nfast/toolkits/pkcs11/libcknfast.so");
        prop.put("SLOTLISTINDEX", "1");
        prop.put("DEFAULTKEY", "default");
        prop.put("PIN", "1234");
        Properties p = CryptoTokenHelper.fixP11Properties(prop);
        assertEquals("{PIN=1234, DEFAULTKEY=default, sharedLibrary=/opt/nfast/toolkits/pkcs11/libcknfast.so, pin=1234, SLOTLISTINDEX=1, defaultKey=default, SHAREDLIBRARY=/opt/nfast/toolkits/pkcs11/libcknfast.so, slotListIndex=1}", p.toString());
    }
}
