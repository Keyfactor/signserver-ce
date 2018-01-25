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

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import javax.security.auth.x500.X500Principal;
import junit.framework.TestCase;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static junit.framework.TestCase.fail;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.keys.token.CachingKeyStoreWrapper;
import org.cesecore.keys.util.KeyStoreTools;

/**
 * Tests that the hard token properties are set correctly for PKCS11 crypto tokens.
 *
 * @version $Id$
 */
public class CryptoTokenHelperTest extends TestCase {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CryptoTokenHelperTest.class);
    
    private static final String KEYALIAS = "theAlias";
    
    /**
     * Tests some slot properties, including ATTRIBUTES.
     * @throws Exception
     */
    public final void testSlotProperties1() throws Exception {
        Properties prop = new Properties();
        prop.put("SHAREDLIBRARY", "/opt/nfast/toolkits/pkcs11/libcknfast.so");
        prop.put("SLOT", "1");
        prop.put("DEFAULTKEY", "default");
        prop.put("PIN", "1234");
        prop.put("ATTRIBUTES", "my attributes");
        SortedMap p = new TreeMap(CryptoTokenHelper.fixP11Properties(prop));
        assertEquals("{ATTRIBUTES=my attributes, DEFAULTKEY=default, PIN=1234, SHAREDLIBRARY=/opt/nfast/toolkits/pkcs11/libcknfast.so, SLOT=1, SLOTLABELTYPE=SLOT_NUMBER, SLOTLABELVALUE=1, defaultKey=default, pin=1234, sharedLibrary=/opt/nfast/toolkits/pkcs11/libcknfast.so, slot=1, slotLabelType=SLOT_NUMBER, slotLabelValue=1}", p.toString());
    }

    /**
     * Tests some slot properties, including ATTRIBUTESFILE.
     * @throws Exception
     */
    public final void testSlotProperties2() throws Exception {
        Properties prop = new Properties();
        prop.put("SHAREDLIBRARY", "/opt/nfast/toolkits/pkcs11/libcknfast.so");
        prop.put("SLOT", "1");
        prop.put("DEFAULTKEY", "default");
        prop.put("PIN", "1234");
        prop.put("ATTRIBUTESFILE", "/opt/attributes.cfg");
        SortedMap p = new TreeMap(CryptoTokenHelper.fixP11Properties(prop));
        assertEquals("{ATTRIBUTESFILE=/opt/attributes.cfg, DEFAULTKEY=default, PIN=1234, SHAREDLIBRARY=/opt/nfast/toolkits/pkcs11/libcknfast.so, SLOT=1, SLOTLABELTYPE=SLOT_NUMBER, SLOTLABELVALUE=1, attributesFile=/opt/attributes.cfg, defaultKey=default, pin=1234, sharedLibrary=/opt/nfast/toolkits/pkcs11/libcknfast.so, slot=1, slotLabelType=SLOT_NUMBER, slotLabelValue=1}", p.toString());
    }

    public final void testSlotIndexProperties() throws Exception {
        // When using nCipher we have to use slotListIndex instead of slot property
        Properties prop = new Properties();
        prop.put("SHAREDLIBRARY", "/opt/nfast/toolkits/pkcs11/libcknfast.so");
        prop.put("SLOTLISTINDEX", "1");
        prop.put("DEFAULTKEY", "default");
        prop.put("PIN", "1234");
        SortedMap p = new TreeMap(CryptoTokenHelper.fixP11Properties(prop));
        assertEquals("{DEFAULTKEY=default, PIN=1234, SHAREDLIBRARY=/opt/nfast/toolkits/pkcs11/libcknfast.so, SLOTLABELTYPE=SLOT_INDEX, SLOTLABELVALUE=1, SLOTLISTINDEX=1, defaultKey=default, pin=1234, sharedLibrary=/opt/nfast/toolkits/pkcs11/libcknfast.so, slotLabelType=SLOT_INDEX, slotLabelValue=1, slotListIndex=1}", p.toString());
    }

    /**
     * Tests some slot properties, including SLOTLISTTYPE and SLITLISTVALUE.
     * @throws Exception
     */
    public final void testSlotListTypePropertiesNumber() throws Exception {
        Properties prop = new Properties();
        prop.put("SHAREDLIBRARY", "/opt/nfast/toolkits/pkcs11/libcknfast.so");
        prop.put("SLOTLABELTYPE", "SLOT_NUMBER");
        prop.put("SLOTLABELVALUE", "1");
        prop.put("DEFAULTKEY", "default");
        prop.put("PIN", "1234");
        prop.put("ATTRIBUTESFILE", "/opt/attributes.cfg");
        SortedMap p = new TreeMap(CryptoTokenHelper.fixP11Properties(prop));
        assertEquals("{ATTRIBUTESFILE=/opt/attributes.cfg, DEFAULTKEY=default, PIN=1234, SHAREDLIBRARY=/opt/nfast/toolkits/pkcs11/libcknfast.so, SLOTLABELTYPE=SLOT_NUMBER, SLOTLABELVALUE=1, attributesFile=/opt/attributes.cfg, defaultKey=default, pin=1234, sharedLibrary=/opt/nfast/toolkits/pkcs11/libcknfast.so, slotLabelType=SLOT_NUMBER, slotLabelValue=1}", p.toString());
    }

    /**
     * Tests some slot properties, including SLOTLISTTYPE and SLITLISTVALUE.
     * @throws Exception
     */
    public final void testSlotListTypePropertiesIndex() throws Exception {
        Properties prop = new Properties();
        prop.put("SHAREDLIBRARY", "/opt/nfast/toolkits/pkcs11/libcknfast.so");
        prop.put("SLOTLABELTYPE", "SLOT_INDEX");
        prop.put("SLOTLABELVALUE", "1");
        prop.put("DEFAULTKEY", "default");
        prop.put("PIN", "1234");
        prop.put("ATTRIBUTESFILE", "/opt/attributes.cfg");
        SortedMap p = new TreeMap(CryptoTokenHelper.fixP11Properties(prop));
        assertEquals("{ATTRIBUTESFILE=/opt/attributes.cfg, DEFAULTKEY=default, PIN=1234, SHAREDLIBRARY=/opt/nfast/toolkits/pkcs11/libcknfast.so, SLOTLABELTYPE=SLOT_INDEX, SLOTLABELVALUE=1, attributesFile=/opt/attributes.cfg, defaultKey=default, pin=1234, sharedLibrary=/opt/nfast/toolkits/pkcs11/libcknfast.so, slotLabelType=SLOT_INDEX, slotLabelValue=1}", p.toString());
    }

    /**
     * Tests some slot properties, including SLOTLISTTYPE and SLITLISTVALUE.
     * @throws Exception
     */
    public final void testSlotListTypePropertiesLabel() throws Exception {
        Properties prop = new Properties();
        prop.put("SHAREDLIBRARY", "/opt/nfast/toolkits/pkcs11/libcknfast.so");
        prop.put("SLOTLABELTYPE", "SLOT_LABEL");
        prop.put("SLOTLABELVALUE", "MyLabel");
        prop.put("DEFAULTKEY", "default");
        prop.put("PIN", "1234");
        prop.put("ATTRIBUTESFILE", "/opt/attributes.cfg");
        SortedMap p = new TreeMap(CryptoTokenHelper.fixP11Properties(prop));
        assertEquals("{ATTRIBUTESFILE=/opt/attributes.cfg, DEFAULTKEY=default, PIN=1234, SHAREDLIBRARY=/opt/nfast/toolkits/pkcs11/libcknfast.so, SLOTLABELTYPE=SLOT_LABEL, SLOTLABELVALUE=MyLabel, attributesFile=/opt/attributes.cfg, defaultKey=default, pin=1234, sharedLibrary=/opt/nfast/toolkits/pkcs11/libcknfast.so, slotLabelType=SLOT_LABEL, slotLabelValue=MyLabel}", p.toString());
    }
    
    /**
     * Test an RSA keyspec with a public exponent expressed in decimal format.
     * 
     * @throws Exception 
     */
    public final void testRSAAlgorithmSpecWithDecimalExponent() throws Exception {
        final RSAKeyGenParameterSpec spec =
                (RSAKeyGenParameterSpec)
                CryptoTokenHelper.getPublicExponentParamSpecForRSA("2048 exp 65537");
        
        assertEquals("Key length", 2048, spec.getKeysize());
        assertEquals("Public exponent",
                     new BigInteger("65537"), spec.getPublicExponent());
    }
    
    /**
     * Test an RSA keyspec with a public exponent expressed in hexadecimal format.
     * 
     * @throws Exception 
     */
    public final void testRSAAlgorithmSpecWithHexExponent() throws Exception {
        final RSAKeyGenParameterSpec spec =
                (RSAKeyGenParameterSpec)
                CryptoTokenHelper.getPublicExponentParamSpecForRSA("2048 exp 0x10001");
        
        assertEquals("Key length", 2048, spec.getKeysize());
        assertEquals("Public exponent",
                     new BigInteger("65537"), spec.getPublicExponent());
    }
    
    /**
     * Test that using a mis-spelled exponent separator results in the correct
     * exception.
     * 
     * @throws Exception 
     */
    public final void testRSAAlgorithmSpecWithInvalidSeparator() throws Exception {
        try {
            CryptoTokenHelper.getPublicExponentParamSpecForRSA("2048 exr 65537");
            fail("Should throw an InvalidAlgorithmParameterException");
        } catch (InvalidAlgorithmParameterException ex) {
            // expected
        } catch (Exception ex) {
            fail("Unexpected exception: " + ex.getClass().getName());
        }
    }
    
    /**
     * Test that specifying the keyspec without spaces around "exp" also works.
     * 
     * @throws Exception 
     */
    public final void testRSAAlgorithmSpecWithoutSpaces() throws Exception {
        final RSAKeyGenParameterSpec spec =
                (RSAKeyGenParameterSpec)
                CryptoTokenHelper.getPublicExponentParamSpecForRSA("2048exp65537");
        
        assertEquals("Key length", 2048, spec.getKeysize());
        assertEquals("Public exponent",
                     new BigInteger("65537"), spec.getPublicExponent());
    }

    private static KeyStore createKeyStoreWithAnEntry() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, null);
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(1024);

        final KeyPair keyPair = kpg.generateKeyPair();
        Certificate[] chain = new Certificate[1];
        chain[0] = CryptoTokenHelper.createDummyCertificate(KEYALIAS, "SHA1withRSA", keyPair, "BC");

        ks.setKeyEntry(KEYALIAS, keyPair.getPrivate(), null, chain);
        return ks;
    }

    /**
     * Tests the regenerateCertIfWanted method.
     *
     * @throws Exception 
     */
    public void testRegenerateCertIfWanted() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        final KeyStore ks = createKeyStoreWithAnEntry();
        final KeyStoreDelegator delegator = new JavaKeyStoreDelegator(ks);
        final X509Certificate certificate = (X509Certificate) ks.getCertificate(KEYALIAS);
        
        // Test with no parameters: should not change the cert
        final Map<String, Object> params = new HashMap<>();
        CryptoTokenHelper.regenerateCertIfWanted(KEYALIAS, "foo123".toCharArray(), params, delegator, "BC");
        X509Certificate certAfter = (X509Certificate) ks.getCertificate(KEYALIAS);
        assertEquals("Same issuer DN", certificate.getIssuerX500Principal().getName(), certAfter.getIssuerX500Principal().getName());
        assertEquals("Same subject DN", certificate.getSubjectX500Principal().getName(), certAfter.getSubjectX500Principal().getName());
        assertEquals("Same signature algorithm", certificate.getSigAlgName(), certAfter.getSigAlgName());
        assertEquals("Same notBefore", certificate.getNotBefore(), certAfter.getNotBefore());
        assertEquals("Same notAfter", certificate.getNotAfter(), certAfter.getNotAfter());
        assertTrue("Validity time more than about 20 years: " + certAfter.getNotAfter(), TimeUnit.MILLISECONDS.toDays(certAfter.getNotAfter().getTime() - certAfter.getNotBefore().getTime()) > 7300);
        assertTrue("Same cert", Hex.toHexString(certificate.getEncoded()).equals(Hex.toHexString(certAfter.getEncoded())));
        
        // Custom DN
        params.clear();
        final String expectedDN = "CN=New Name, O=New Organization, C=SE";
        params.put("SELFSIGNED_DN", expectedDN);
        CryptoTokenHelper.regenerateCertIfWanted(KEYALIAS, "foo123".toCharArray(), params, delegator, "BC");
        certAfter = (X509Certificate) ks.getCertificate(KEYALIAS);
        assertEquals("New issuer DN", new X500Principal(expectedDN).getName(), certAfter.getIssuerX500Principal().getName());
        assertEquals("New subject DN", new X500Principal(expectedDN).getName(), certAfter.getSubjectX500Principal().getName());
        assertEquals("Same signature algorithm", certificate.getSigAlgName(), certAfter.getSigAlgName());
        assertTrue("Validity time more than about 20 years: " + certAfter.getNotAfter(), TimeUnit.MILLISECONDS.toDays(certAfter.getNotAfter().getTime() - certAfter.getNotBefore().getTime()) > 7300);
        
        // Custom signature algorithm
        params.clear();
        final String expectedSigAlg = "SHA256withRSA";
        params.put("SELFSIGNED_SIGNATUREALGORITHM", expectedSigAlg);
        CryptoTokenHelper.regenerateCertIfWanted(KEYALIAS, "foo123".toCharArray(), params, delegator, "BC");
        certAfter = (X509Certificate) ks.getCertificate(KEYALIAS);
        assertEquals("Same issuer DN", certificate.getIssuerX500Principal().getName(), certAfter.getIssuerX500Principal().getName());
        assertEquals("Same subject DN", certificate.getSubjectX500Principal().getName(), certAfter.getSubjectX500Principal().getName());
        assertEquals("New signature algorithm", expectedSigAlg, certAfter.getSigAlgName());
        assertTrue("Validity time more than about 20 years: " + certAfter.getNotAfter(), TimeUnit.MILLISECONDS.toDays(certAfter.getNotAfter().getTime() - certAfter.getNotBefore().getTime()) > 7300);

        // Custom validity
        params.clear();
        params.put("SELFSIGNED_VALIDITY", Long.valueOf(1 * 60 * 60)); // 1 hour
        CryptoTokenHelper.regenerateCertIfWanted(KEYALIAS, "foo123".toCharArray(), params,delegator, "BC");
        certAfter = (X509Certificate) ks.getCertificate(KEYALIAS);
        assertEquals("Same issuer DN", certificate.getIssuerX500Principal().getName(), certAfter.getIssuerX500Principal().getName());
        assertEquals("Same subject DN", certificate.getSubjectX500Principal().getName(), certAfter.getSubjectX500Principal().getName());
        assertEquals("Same signature algorithm", certificate.getSigAlgName(), certAfter.getSigAlgName());
        assertEquals("New validity time about 1 hour", 1L, TimeUnit.MILLISECONDS.toHours(certAfter.getNotAfter().getTime() - certAfter.getNotBefore().getTime()));
        
        // All at once
        params.clear();
        final String expectedDN2 = "CN=New Name 2, O=New Organization, C=SE";
        params.put("SELFSIGNED_DN", expectedDN2);
        final String expectedSigAlg2 = "SHA256withRSA";
        params.put("SELFSIGNED_SIGNATUREALGORITHM", expectedSigAlg2);
        params.put("SELFSIGNED_VALIDITY", Long.valueOf(2 * 60 * 60)); // 2 hour
        CryptoTokenHelper.regenerateCertIfWanted(KEYALIAS, "foo123".toCharArray(), params, delegator, "BC");
        certAfter = (X509Certificate) ks.getCertificate(KEYALIAS);
        assertEquals("New issuer DN", new X500Principal(expectedDN2).getName(), certAfter.getIssuerX500Principal().getName());
        assertEquals("New subject DN", new X500Principal(expectedDN2).getName(), certAfter.getSubjectX500Principal().getName());
        assertEquals("New signature algorithm", expectedSigAlg2, certAfter.getSigAlgName());
        assertEquals("New validity time about 2 hour", 2L, TimeUnit.MILLISECONDS.toHours(certAfter.getNotAfter().getTime() - certAfter.getNotBefore().getTime()));
    }

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
        KeyStoreTools cesecoreTool = new KeyStoreTools(new CachingKeyStoreWrapper(ks, false), "BC");
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
        assertTrue("Not a dummy certificate DN", CryptoTokenHelper.isDummyCertificateDN("CN=Dummy cert for testKey"));
        assertFalse("not SignServer", CryptoTokenHelper.isDummyCertificateDN("CN=Anything, O=anything"));
        assertFalse("not CESeCore DN", CryptoTokenHelper.isDummyCertificateDN("CN=other guy, L=around, C=US"));
        assertFalse("not CESeCore DN", CryptoTokenHelper.isDummyCertificateDN("CN=some guy, L=Stockholm, C=US"));
        assertFalse("not CESeCore DN", CryptoTokenHelper.isDummyCertificateDN("CN=some guy, L=around, C=SE"));
    }

}
