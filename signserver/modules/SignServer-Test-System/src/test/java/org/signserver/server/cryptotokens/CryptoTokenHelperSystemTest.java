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
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.keys.util.KeyStoreTools;

/**
 * Tests for CryptoTokenHelper that can not be run as a real unit test.
 * 
 * Those tests are added here as a system test to worka round the issue that
 * CESeCore is compiled against BC 1.49+BufferingContentSigner from 1.50 which
 * is not available in the official Maven 1.49 jar.
 * 
 * TODO: After upgrading to BC version =&gt;1.50 this tests can be moved to
 * the unit tests in SignServer-Server and this file removed.
 *
 * @version $Id$
 */
public class CryptoTokenHelperSystemTest extends TestCase {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CryptoTokenHelperSystemTest.class);

    
    /**
     * Tests that a certificate generate by CESeCore code is detected to be a
     * dummy certificate.
     * @throws Exception 
     */
    public void testDummyCertificateFromSignServer() throws Exception {
        LOG.info("testDummyCertificateFromSignServer");
        
        Security.addProvider(new BouncyCastleProvider());
        
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, null);
        KeyStoreTools cesecoreTool = new KeyStoreTools(ks, "BC");
        cesecoreTool.generateKeyPair("1024", "entry1");
        
        X509Certificate certificate = (X509Certificate) ks.getCertificate("entry1");
        assertTrue("dummy cert: " + certificate.getSubjectX500Principal().getName(), 
                CryptoTokenHelper.isDummyCertificate(certificate));
    }
    
    /**
     * Tests that a certificate generate by createDummyCertificate is detected to
     * be a dummy certificate.
     * @throws Exception 
     */
    public void testDummyCertificateFromCreateDummyCertificate() throws Exception {
        LOG.info("testDummyCertificateFromCreateDummyCertificate");
        
        Security.addProvider(new BouncyCastleProvider());
        
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");    
        kpg.initialize(1024);
        KeyPair keyPair = kpg.generateKeyPair();
        
        X509Certificate certificate = CryptoTokenHelper.createDummyCertificate("entry1", "SHA256withRSA", keyPair, "BC");
        
        assertTrue("dummy cert: " + certificate.getSubjectX500Principal().getName(), 
                CryptoTokenHelper.isDummyCertificate(certificate));
    }
    
    /**
     * Tests that dummy DNs are detected correctly.
     * @throws Exception 
     */
    public void testDummyCertificateDN() throws Exception {
        assertTrue("contains SignServer marker", CryptoTokenHelper.isDummyCertificateDN("CN=Anything, L=_SignServer_DUMMY_CERT_, O=anything"));
        assertTrue("is CESeCore DN", CryptoTokenHelper.isDummyCertificateDN("CN=some guy, L=around, C=US"));
        assertFalse("not SignServer", CryptoTokenHelper.isDummyCertificateDN("CN=Anything, O=anything"));
        assertFalse("not CESeCore DN", CryptoTokenHelper.isDummyCertificateDN("CN=other guy, L=around, C=US"));
        assertFalse("not CESeCore DN", CryptoTokenHelper.isDummyCertificateDN("CN=some guy, L=Stockholm, C=US"));
        assertFalse("not CESeCore DN", CryptoTokenHelper.isDummyCertificateDN("CN=some guy, L=around, C=SE"));
    }
}
