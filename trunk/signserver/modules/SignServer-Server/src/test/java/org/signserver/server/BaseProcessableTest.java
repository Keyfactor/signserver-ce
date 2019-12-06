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
package org.signserver.server;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import javax.persistence.EntityManager;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.util.CertTools;
import org.junit.Test;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.RequestContext;
import org.signserver.common.ResyncException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.server.aliasselectors.AliasSelector;
import org.signserver.server.cryptotokens.NullCryptoToken;
import org.signserver.server.signers.BaseSigner;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.server.cryptotokens.DefaultCryptoInstance;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.data.impl.ByteArrayReadableData;
import org.signserver.server.data.impl.TemporarlyWritableData;
import org.signserver.server.log.AdminInfo;

/**
 * Tests for the BaseProcessable class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class BaseProcessableTest extends TestCase {

    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(BaseProcessableTest.class);
    
    private final int workerId = 100;
    private final WorkerContext anyContext = new SignServerContext(null, null);

    private static final String SAMPLE_ATTRIBUTES = 
            "attributes(generate,CKO_PUBLIC_KEY,*) = {\n" +
            "        CKA_TOKEN = false\n" +
            "        CKA_ENCRYPT = true\n" +
            "        CKA_VERIFY = true\n" +
            "        CKA_WRAP = true\n" +
            "}\n" +
            "attributes(generate, CKO_PRIVATE_KEY,*) = {\n" +
            "        CKA_TOKEN = true\n" +
            "        CKA_PRIVATE = true\n" +
            "        CKA_SENSITIVE = true\n" +
            "        CKA_EXTRACTABLE = false\n" +
            "        CKA_DECRYPT = true\n" +
            "        CKA_SIGN = true\n" +
            "        CKA_UNWRAP = true\n" +
            "}";

    /**
    subject=/CN=Signer 4/OU=Testing/O=SignServer/C=SE
    issuer=/CN=DSS Root CA 10/OU=Testing/O=SignServer/C=SE
    valid until=27/05/2021 09:51:45 GMT
    */
    private static final String CERT1 =
              "MIIElTCCAn2gAwIBAgIITz1ZKtegWpgwDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UE"
            + "AwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNp"
            + "Z25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzA5NTE0NVoXDTIxMDUyNzA5"
            + "NTE0NVowRzERMA8GA1UEAwwIU2lnbmVyIDQxEDAOBgNVBAsMB1Rlc3RpbmcxEzAR"
            + "BgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEF"
            + "AAOCAQ8AMIIBCgKCAQEAnCGlYABPTW3Jx607cdkHPDJEGXpKCXkI29zj8BxCIvC3"
            + "3kyGZB6M7EICU+7vt200u1TmSjx2auTfZI6sA2cDsESlMhKJ+8nj2uj1f5g9MYRb"
            + "+IIq1IIhDArWwICswnZkWL/5Ncggg2bNcidCblDy5SUQ+xMeXtJQWCU8Zn3a+ySZ"
            + "Z1ZiYZ10gUu5JValsuOb8YpcT/pqBPF0cgEy6mIe3ANolzxLKNUBYAsQzQnCvgx+"
            + "GqgbzYHo8fkppSGUFVYdFI0MC9CBT72eOxxQoguICWXus8BdIwebZDGQdluKvTNs"
            + "ig4hM39G6WvPqoEi9I86VhY9mSyY+WOeU5Y3ZsC8CQIDAQABo38wfTAdBgNVHQ4E"
            + "FgQUGqddBv2s8iEa5B98MVTbQ2HiFkAwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAW"
            + "gBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYw"
            + "FAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4ICAQB8HpFOfiTb"
            + "ylu06tg0yqvix93zZrJWSKT5PjwpqAU+btQ4fFy4GUBG6VuuVr27+FaFND3oaIQW"
            + "BXdQ1+6ea3Nu9WCnKkLLjg7OjBNWw1LCrHXiAHdIYM3mqayPcf7ezbr6AMnmwDs6"
            + "/8YAXjyRLmhGb23M8db+3pgTf0Co/CoeQWVa1eJObH7aO4/Koeg4twwbKG0MjwEY"
            + "ZPi0ZWB93w/llEHbvMNI9dsQWSqIU7W56KRFN66WdqFhjdVPyg86NudH+9jmp4x1"
            + "Ac9GKGNOYYfDnQCdsrJwZMvcI7bZykbd77ZC3zBzuaISAeRJq3rjHygSeKPHCYDW"
            + "zAVEP9yaO0fL7HMZ2uqHxokvuOo5SxgVfvLr+kT4ioQHz+r9ehkCf0dbydm7EqyJ"
            + "Y7YSFUDEqk57dnZDxy7ZgUA/TZf3I3rPjSopDxqiqJbm9L0GPW3zk0pAZx7dgLcq"
            + "2I8fv+DBEKqJ47/H2V5aopxsRhiKC5u8nEEbAMbBYgjGQT/5K4mBt0gUJFNek7vS"
            + "a50VH05u8P6yo/3ppDxGCXE2d2JfWlEIx7DRWWij2PuOgDGkvVt2soxtp8Lx+kS6"
            + "K+G+tA5BGZMyEPdqAakyup7udi4LoB0wfJ58Jr5QNHCx4icUWvCBUM5CTcH4O/pQ"
            + "oj/7HSYZlqigM72nR8f/gv1TwLVKz+ygzg==";
    
    /**
    subject=/CN=Signer 1/OU=Testing/O=SignServer/C=SE
    issuer=/CN=DSS Root CA 10/OU=Testing/O=SignServer/C=SE
    valid until=2025-06-01
    Taken from res/test/dss10/dss10_signer1.pem
    */
    private static final String CERT2 =
            "MIIElTCCAn2gAwIBAgIIQZNa2mLuDoowDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UE"
          +  "AwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNp"
          +  "Z25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTE1MDYwMTE0MDQ0MVoXDTI1MDYwMTE0"
          +  "MDQ0MVowRzERMA8GA1UEAwwIU2lnbmVyIDExEDAOBgNVBAsMB1Rlc3RpbmcxEzAR"
          +  "BgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEF"
          +  "AAOCAQ8AMIIBCgKCAQEAy0GX45lzDRhUU/jhCCeqKKZcFWlOQiDxUcd6JOq38drU"
          +  "alL9u2+gr+dcBFKRBOGmFxjMGVJ4nDO8uI3dl+BOrFbykUAnf1Yk/t8E2ZmgdQMP"
          +  "4Cz6iXwlgWj8YRnQ6wEk2gcAp45SARfyEYdtArYvbTxOFoxb9KOjwji89yxCR/pb"
          +  "RHz/q3RoXgq6E/g8mTmIt4CAgvD5VVFiNP7XWKd4Ptw4bjQY8RW5k8291o1ErHbD"
          +  "Zvvqvps4E9cIu35v1LtXjlFkwVJ4xc0L61Ak+cjcwAUcGqTHQ7P9KdjcOLztsw0X"
          +  "3jTZi5nLg3y4FukeOzkjxk5nh0Jr3/F3M7wuY2BS6wIDAQABo38wfTAdBgNVHQ4E"
          +  "FgQUDsECWxG3XbAJooXiXmQrIz/d0l4wDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAW"
          +  "gBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYw"
          +  "FAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4ICAQAr2nSyOwkD"
          +  "WPWiIqomXHsBHXwr35kvwqNSqM5Lh9if0XUDj0HudXH+nenyH9FAMkX1rfOm+SjQ"
          +  "Wmw5mgwgvpDyaI8J6NBSf0Kve9Qxn8Yh224oVZogHS7LYFULd9FE3UdLv0ZrD2i+"
          +  "0aXEZXaCEJBxNY+iVOpGdBdBgY6c7MD6Ib1Py7bQeslSOjmHNs7OnE5aZaLfmUQ3"
          +  "0EprvX0Zzx0mhjm8BU41+m7Yg4W94mbZX0AGjEKL8v4NRQkNdv2/wgKNGKK+OvII"
          +  "E/a3g8i68Jy5xbEI5sVcp6Z6qIa+6+5li33Gblwr86DnQFmm0IrCmgVyT2RuzNeX"
          +  "FcgenbHJO/udOchn1b65wwzfIuqo5SpJmzsS9HvbsdJOCvXbRRJibjC0TN73Bmag"
          +  "H0wv4t9TawbRH/8M3JvWIAV7DIuyiosC6F9jN319zWkzPllesNsjmWzE05fwcZky"
          +  "4RSsS+eYmHxn9oEi1nS4igv0o/4lpz8WZ9KQSNTWP89wXPMW7bT1XUqMehSXk5Q1"
          +  "3Ao/AXPF+4ZP4QJZMa2OHdDaNPMBinK0fZzoV/RFx5mzQm+XJCcdZBHbB+JEw14V"
          +  "BQHSf/Icgab1tANxgQSk8IOhZ0/OQ6LdfoTmRVsrxz58tzvA8Fw+FcyyIni8p6ve"
          +  "2oETepx5f5yVfLJzAdcgTXwo6R52yBgw2w==";
    
    /**
     * Tests the base case were no default properties are used to configure the PKCS11CryptoToken.
     * 
     * @throws Exception
     */
    @Test
    public void testGetCryptoToken_noDefaults() throws Exception {
        LOG.info("testGetCryptoToken_noDefaults");
        
        Properties globalConfig = new Properties();
        WorkerConfig workerConfig = new WorkerConfig();
        MockServices services = new MockServices(globalConfig);
        
        // Exercising all properties (except SLOTLISTINDEX)
        workerConfig.setProperty(WorkerConfig.IMPLEMENTATION_CLASS, TestSigner.class.getName());
        workerConfig.setProperty(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, MockedCryptoToken.class.getName());
        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("SHAREDLIBRARY", "/opt/hsm/pkcs11.so");
        workerConfig.setProperty("SHAREDLIBRARYNAME", "P11Library");
        workerConfig.setProperty("SLOT", "3");
        workerConfig.setProperty("ATTRIBUTESFILE", "/opt/hsm/sunpkcs11.cfg");
        
        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        MockedCryptoToken actualToken = (MockedCryptoToken) instance.getCryptoToken(services);
        Properties actualProperties = actualToken.getProps();
        
        assertEquals("same as worker config", new TreeMap<>(workerConfig.getProperties()).toString(), new TreeMap<>(actualProperties).toString());
        
        // Exercising all properties (except SLOT)
        workerConfig.setProperty(WorkerConfig.IMPLEMENTATION_CLASS, TestSigner.class.getName());
        workerConfig.setProperty(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, MockedCryptoToken.class.getName());
        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("SHAREDLIBRARY", "/opt/hsm/pkcs11.so");
        workerConfig.setProperty("SHAREDLIBRARYNAME", "P11Library");
        workerConfig.setProperty("SLOTLISTINDEX", "2");
        workerConfig.setProperty("ATTRIBUTESFILE", "/opt/hsm/sunpkcs11.cfg");
        
        instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        actualToken = (MockedCryptoToken) instance.getCryptoToken(services);
        actualProperties = actualToken.getProps();
        
        assertEquals("same as worker config", new TreeMap<>(workerConfig.getProperties()).toString(), new TreeMap<>(actualProperties).toString());
    }
    
    /** 
     * Test default value for SLOTLISTINDEX and ATTRIBUTES. 
     * First the value is specified only as a default value and then the value 
     * is overriden by the worker.
     * 
     * @throws Exception
     */
    @Test
    public void testGetCryptoToken_defaultSlotListIndex() throws Exception {
        LOG.info("testGetCryptoToken_defaultSlotListIndex");
        
        Properties globalConfig = new Properties();
        WorkerConfig workerConfig = new WorkerConfig();
        MockServices services = new MockServices(globalConfig);
        
        // SLOTLISTINDEX only in GlobalConfiguration
        workerConfig.setProperty(WorkerConfig.IMPLEMENTATION_CLASS, TestSigner.class.getName());
        workerConfig.setProperty(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, MockedCryptoToken.class.getName());
        globalConfig.setProperty("GLOB.DEFAULT.SLOTLISTINDEX", "33");
        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("ATTRIBUTES", SAMPLE_ATTRIBUTES);
        
        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        MockedCryptoToken actualToken = (MockedCryptoToken) instance.getCryptoToken(services);
        Properties actualProperties = actualToken.getProps();
        
        Properties expectedProperties = new Properties(workerConfig.getProperties());
        expectedProperties.putAll(workerConfig.getProperties());
        expectedProperties.setProperty("SLOTLISTINDEX", "33");
        assertEquals("default SLOTLISTINDEX used", 
                expectedProperties.toString(), actualProperties.toString());
        
        // SLOTLISTINDEX both in GlobalConfiguration and in Worker Config
        workerConfig.setProperty(WorkerConfig.IMPLEMENTATION_CLASS, TestSigner.class.getName());
        workerConfig.setProperty(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, MockedCryptoToken.class.getName());
        globalConfig.setProperty("GLOB.DEFAULT.SLOTLISTINDEX", "33");
        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("SHAREDLIBRARY", "/opt/hsm/pkcs11.so");
        workerConfig.setProperty("SHAREDLIBRARYNAME", "P11Library");
        workerConfig.setProperty("SLOTLISTINDEX", "44");
        workerConfig.setProperty("ATTRIBUTES", SAMPLE_ATTRIBUTES);
        
        instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        actualToken = (MockedCryptoToken) instance.getCryptoToken(services);
        actualProperties = actualToken.getProps();
        
        expectedProperties = new Properties();
        expectedProperties.putAll(workerConfig.getProperties());
        expectedProperties.setProperty("SLOTLISTINDEX", "44");
        assertEquals("worker overriding SLOTLISTINDEX used", 
                expectedProperties.toString(), actualProperties.toString());
    }
    
    /**
     * Test default values for all PKCS11CryptoToken properties that can have
     * default values.
     * First the values are only specified as default values and then they are
     * overriden by the worker.
     * The SLOTLISTINDEX property is not specified here as it should not be 
     * specified at the same time as the SLOT property and it is also tested in 
     * a separate test.
     * 
     * @throws Exception
     */
    @Test
    public void testGetCryptoToken_defaultAll() throws Exception {
        LOG.info("testGetCryptoToken_defaultAll");
        
        Properties globalConfig = new Properties();
        WorkerConfig workerConfig = new WorkerConfig();
        MockServices services = new MockServices(globalConfig);
        
        // All PKCS#11 properties that can have default values in GlobalConfiguration (except SLOTLISTINDEX, ATTRIBUTES)
        workerConfig.setProperty(WorkerConfig.IMPLEMENTATION_CLASS, TestSigner.class.getName());
        workerConfig.setProperty(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, MockedCryptoToken.class.getName());
        globalConfig.setProperty("GLOB.DEFAULT.SHAREDLIBRARY", "/opt/hsm/default-pkcs11.so");
        globalConfig.setProperty("GLOB.DEFAULT.SHAREDLIBRARYNAME", "DefaultLibrary");
        globalConfig.setProperty("GLOB.DEFAULT.SLOT", "44");
        globalConfig.setProperty("GLOB.DEFAULT.ATTRIBUTESFILE", "/opt/hsm/default-sunpkcs11.cfg");
        globalConfig.setProperty("GLOB.DEFAULT.PIN", "FooBar789");
        workerConfig.setProperty("NAME", "TestSigner100");
        
        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        MockedCryptoToken actualToken = (MockedCryptoToken) instance.getCryptoToken(services);
        Properties actualProperties = actualToken.getProps();
        
        Properties expectedProperties = new Properties();
        expectedProperties.putAll(workerConfig.getProperties());
        expectedProperties.setProperty("SHAREDLIBRARY", "/opt/hsm/default-pkcs11.so");
        expectedProperties.setProperty("SHAREDLIBRARYNAME", "DefaultLibrary");
        expectedProperties.setProperty("SLOT", "44");
        expectedProperties.setProperty("ATTRIBUTESFILE", "/opt/hsm/default-sunpkcs11.cfg");
        expectedProperties.setProperty("PIN", "FooBar789");
        assertEquals("default SHAREDLIBRARY etc used", 
                new TreeMap<>(expectedProperties).toString(), new TreeMap<>(actualProperties).toString());

        // All PKCS#11 properties that can have default values GlobalConfiguration and overriden in Worker Config (except SLOTLISTINDEX, ATTRIBUTES)
        workerConfig.setProperty(WorkerConfig.IMPLEMENTATION_CLASS, TestSigner.class.getName());
        workerConfig.setProperty(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, MockedCryptoToken.class.getName());
        globalConfig.setProperty("GLOB.DEFAULT.SHAREDLIBRARY", "/opt/hsm/default-pkcs11.so");
        globalConfig.setProperty("GLOB.DEFAULT.SHAREDLIBRARYNAME", "DefaultLibrary");
        globalConfig.setProperty("GLOB.DEFAULT.SLOT", "44");
        globalConfig.setProperty("GLOB.DEFAULT.ATTRIBUTESFILE", "/opt/hsm/default-sunpkcs11.cfg");
        globalConfig.setProperty("GLOB.DEFAULT.PIN", "FooBar789");
        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("SHAREDLIBRARY", "/opt/hsm/pkcs11.so");
        workerConfig.setProperty("SHAREDLIBRARYNAME", "OverriddenLibrary");
        workerConfig.setProperty("SLOT", "3");
        workerConfig.setProperty("PIN", "AnotherPin");
        workerConfig.setProperty("ATTRIBUTESFILE", "/opt/hsm/sunpkcs11.cfg");
        
        instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        actualToken = (MockedCryptoToken) instance.getCryptoToken(services);
        actualProperties = actualToken.getProps();
        
        expectedProperties = new Properties();
        expectedProperties.putAll(workerConfig.getProperties());
        expectedProperties.setProperty("SHAREDLIBRARY", "/opt/hsm/pkcs11.so");
        expectedProperties.setProperty("SHAREDLIBRARYNAME", "OverriddenLibrary");
        assertEquals("worker overriding SHAREDLIBRARY, SHAREDLIBRARYNAME etc used", 
                expectedProperties.toString(), actualProperties.toString());
    }
    
    /**
     * Test the fatal error reported when setting an unknown crypto token class.
     * 
     * @throws Exception
     */
    @Test
    public void testCryptoToken_unknownClass() throws Exception {
        Properties globalConfig = new Properties();
        WorkerConfig workerConfig = new WorkerConfig();
        MockServices services = new MockServices(globalConfig);
        
        workerConfig.setProperty(WorkerConfig.IMPLEMENTATION_CLASS, TestSigner.class.getName());
        workerConfig.setProperty(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, "org.foo.Bar");
        workerConfig.setProperty("NAME", "TestSigner100");
        
        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        
        final List<String> fatalErrors = instance.getFatalErrors(services);
        
        assertTrue("Should contain error", fatalErrors.contains("Crypto token class not found: org.foo.Bar"));
    }

    /**
     * Tests that when no certificate is explicitly set in the configuration
     * then certificate from the token is used.
     * 
     * @throws Exception
     */
    @Test
    public void testCertificateInTokenUsed() throws Exception {
        LOG.info("testCertificateInTokenUsed");

        Properties globalConfig = new Properties();
        MockServices services = new MockServices(globalConfig);
        WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty(WorkerConfig.IMPLEMENTATION_CLASS, TestSigner.class.getName());
        workerConfig.setProperty(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, MockedCryptoToken.class.getName());
        workerConfig.setProperty("NAME", "TestSigner200");
        // Note: No SIGNERCERT or SIGNERCERTCHAIN configured so cert from token should be used

        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);

        // Certifcate in token is "CN=Signer 4"
        assertEquals("cert from token", "Signer 4", CertTools.getPartFromDN(((X509Certificate) instance.getSigningCertificate(services)).getSubjectX500Principal().getName(), "CN"));
        assertEquals("cert from token", "Signer 4", CertTools.getPartFromDN(((X509Certificate) instance.getSigningCertificateChain(services).get(0)).getSubjectX500Principal().getName(), "CN"));
    }

    /**
     * Tests that when a certificate is explicitly set in the configuration that
     * certificate is used instead of the one in the token.
     * 
     * @throws Exception
     */
    @Test
    public void testCertificateInTokenOverridden() throws Exception {
        LOG.info("testCertificateInTokenOverridden");

        Properties globalConfig = new Properties();
        WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty(WorkerConfig.IMPLEMENTATION_CLASS, TestSigner.class.getName());
        workerConfig.setProperty(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, MockedCryptoToken.class.getName());
        workerConfig.setProperty("NAME", "TestSigner200");

        // Configure certbytes3 (CN=End Entity 1)
        workerConfig.setProperty("SIGNERCERT", "-----BEGIN CERTIFICATE-----\n" + CERT2 + "\n-----END CERTIFICATE-----");
        workerConfig.setProperty("SIGNERCERTCHAIN", "-----BEGIN CERTIFICATE-----\n" + CERT2 + "\n-----END CERTIFICATE-----");

        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);

        // Certifcate in token is "CN=Signer 4", configured certificate is "CN=End Entity 1"
        assertEquals("cert from token", "Signer 1", CertTools.getPartFromDN(((X509Certificate) instance.getSigningCertificate((IServices) null)).getSubjectX500Principal().getName(), "CN"));
        assertEquals("cert from token", "Signer 1", CertTools.getPartFromDN(((X509Certificate) instance.getSigningCertificateChain((IServices) null).get(0)).getSubjectX500Principal().getName(), "CN"));
    }

    /**
     * Test that when specifying neither the SHAREDLIBRARYNAME or legacy
     * SHAREDLIBRARY property, a configuration error mentioning missing
     * SHAREDLIBRARYNAME is given (as that is the preferred one to use now).
     * 
     * @throws Exception 
     */
    @Test
    public void testCryptoToken_P11NoSharedLibrary() throws Exception {
        Properties globalConfig = new Properties();
        WorkerConfig workerConfig = new WorkerConfig();
        MockServices services = new MockServices(globalConfig);

        workerConfig.setProperty(WorkerConfig.IMPLEMENTATION_CLASS, TestSigner.class.getName());
        workerConfig.setProperty(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, 
                "org.signserver.server.cryptotokens.PKCS11CryptoToken");
        workerConfig.setProperty("NAME", "TestSigner100");
        
        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        
        final List<String> fatalErrors = instance.getFatalErrors(services);
        final String expectedErrorPrefix =
                "Failed to initialize crypto token: Missing SHAREDLIBRARYNAME property";
        boolean foundError = false;
        
        for (final String error : fatalErrors) {
            if (error.startsWith(expectedErrorPrefix)) {
                foundError = true;
                break;
            }
        }

        assertTrue("Should contain error", foundError);
    }
    
    /**
     * Test the override mechanism for alias selectors.
     * 
     * @throws Exception 
     */
    @Test
    public void testDefaulAliasSelector() throws Exception {
        Properties globalConfig = new Properties();
        WorkerConfig workerConfig = new WorkerConfig();
        MockServices services = new MockServices(globalConfig);
        
        TestSigner instance = new TestSigner(globalConfig);
        
        instance.init(workerId, workerConfig, anyContext, null);
        
        final AliasSelector selector = instance.createAliasSelector(null);
        
        assertTrue("Alias selector implementation: " + selector.getClass().getName(),
                    selector instanceof TestAliasSelector);
        assertEquals("Alias", "Test",
                selector.getAlias(workerId, instance, null, null));
        
        final List<String> errors = instance.getFatalErrors(services);
        
        assertTrue("Contains alias selector fatal error",
                errors.contains("Test alias selector error"));
    }
    
    /**
     * Test importing a certificate chain.
     * 
     * @throws Exception 
     */
    @Test
    public void testImportCertificateChain() throws Exception {
        LOG.info("testGetCryptoToken_noDefaults");
        
        Properties globalConfig = new Properties();
        WorkerConfig workerConfig = new WorkerConfig();
        MockServices services = new MockServices(globalConfig);
        
        // Exercising all properties (except SLOTLISTINDEX)
        workerConfig.setProperty(WorkerConfig.IMPLEMENTATION_CLASS, TestSigner.class.getName());
        workerConfig.setProperty(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, MockedCryptoToken.class.getName());
        workerConfig.setProperty("NAME", "TestSigner100");
        
        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        
            
        final List<Certificate> chain =
                Arrays.asList(CertTools.getCertfromByteArray(Base64.decode(CERT2)));
        
        instance.importCertificateChain(chain, "alias2", null, Collections.<String, Object>emptyMap(), services);
        
        final List<Certificate> importedChain =
                instance.getSigningCertificateChain("alias2", null);
        
        
        System.out.println("CERT2: " + chain.get(0).toString());
        System.out.println("ACTUAL: " + importedChain.get(0));
        
        assertTrue("Matching certificate",
                Arrays.equals(chain.get(0).getEncoded(),
                              importedChain.get(0).getEncoded()));
    }
    
    /**
     * Test that trying to generate a cert request with no crypto token set
     * will generate a proper CryptoTokenOfflineException.
     * 
     * @throws Exception 
     */
    @Test
    public void testGenerateCSRNoCryptoToken() throws Exception {
        LOG.info("testGenerateCSRNoCryptoToken");
        
        try {
            Properties globalConfig = new Properties();
            WorkerConfig workerConfig = new WorkerConfig();
            MockServices services = new MockServices(globalConfig);

            globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
            workerConfig.setProperty("NAME", "TestSigner100");
        
            TestSigner instance = new TestSigner(globalConfig);
            instance.init(workerId, workerConfig, anyContext, null);
            
            final ISignerCertReqInfo reqInfo =
                    new PKCS10CertReqInfo("SHA1withRSA", "CN=someguy", null);
            
            instance.genCertificateRequest(reqInfo, false, "somekey", services);
            fail("Should throw CryptoTokenOfflineException");
        } catch (CryptoTokenOfflineException e) {
            // expected
        } catch (Exception e) {
            fail("Unkown exception thrown: " + e.getClass().getName());
        }
    }
    
    /**
     * Tests the publicKeyEquals method and especially that it works with explicit ECC parameters.
     * @throws Exception in case of error
     */
    @Test
    public void testPublicKeyEquals() throws Exception {
        LOG.info("testPublicKeyEquals");
        
        BaseProcessable instance = new BaseProcessable() {
            @Override
            public Response processData(Request signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
                throw new UnsupportedOperationException("Not supported yet.");
            }
        };

        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        
        PublicKey key1 = kpg.generateKeyPair().getPublic();
        PublicKey key1ex = ECKeyUtil.publicToExplicitParameters(key1, "BC");
        PublicKey key2 = kpg.generateKeyPair().getPublic();
        
        kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048, new SecureRandom());
        
        PublicKey key3 = kpg.generateKeyPair().getPublic();
        
        assertTrue("key1 == key1", instance.publicKeyEquals(key1, key1));
        assertTrue("key1 == key1ex", instance.publicKeyEquals(key1, key1ex));
        assertTrue("key1ex == key1ex", instance.publicKeyEquals(key1ex, key1ex));
        assertFalse("key1 != key2", instance.publicKeyEquals(key1, key2));
        assertFalse("key2 != key1", instance.publicKeyEquals(key2, key1));
        assertFalse("key1 != key3", instance.publicKeyEquals(key1, key3));
        assertFalse("key3 != key1", instance.publicKeyEquals(key3, key1));
    }
    
    /**
     * Test that setting an illegal value for CACHE_PRIVATEKEY gives a
     * configuration error.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_illegalCachePrivateKey() throws Exception {
        final Properties globalConfig = new Properties();
        final TestSigner instance = new TestSigner(globalConfig);
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty("CACHE_PRIVATEKEY", "_illegal_");
        instance.init(42, config, anyContext, null);
 
        final List<String> fatalErrors =
                instance.getFatalErrors(new MockServices(globalConfig));
        
        assertTrue("Contains error",
                   fatalErrors.contains("Illegal value for CACHE_PRIVATEKEY: _illegal_"));
    }
    
    /**
     * Test that the default behaviour of the cache private key option is to
     * request caching when aquiring the token.
     * 
     * @throws Exception 
     */
    @Test
    public void testDefaultCachePrivateKey() throws Exception {
        final Properties globalConfig = new Properties();
        final TestSigner instance = new TestSigner(globalConfig);
        final WorkerConfig config = new WorkerConfig();
        final MockServices services = new MockServices(globalConfig);
        
        config.setProperty(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS,
                           MockedCryptoToken.class.getName());
        config.setProperty("DEFAULTKEY", TestAliasSelector.ALIAS);
        instance.init(42, config, anyContext, null);
        
        final RequestContext context = new RequestContext();
        final File tempDirFolder = new File(System.getProperty("java.io.tmpdir"));
        
        context.setServices(services);
        
        final SignatureRequest req = new SignatureRequest(42, new ByteArrayReadableData("abc".getBytes(StandardCharsets.UTF_8), tempDirFolder),
                                                              new TemporarlyWritableData(false, tempDirFolder));
        instance.acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, req, context);

        assertNotNull("aquireCryptoInstance called",
                      MockedCryptoToken.aquireCryptoInstanceParams);
        assertEquals("Requested caching of private key", true,
                    MockedCryptoToken.aquireCryptoInstanceParams.get(ICryptoTokenV4.PARAM_CACHEPRIVATEKEY));
    }
    
    /**
     * Test that setting the cache private key option to false results in not
     * requesting caching when aquiring the token.
     * 
     * @throws Exception 
     */
    @Test
    public void testCachePrivateKeyFalse() throws Exception {
        final Properties globalConfig = new Properties();
        final TestSigner instance = new TestSigner(globalConfig);
        final WorkerConfig config = new WorkerConfig();
        final MockServices services = new MockServices(globalConfig);
        
        config.setProperty(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS,
                           MockedCryptoToken.class.getName());
        config.setProperty("DEFAULTKEY", TestAliasSelector.ALIAS);
        config.setProperty("CACHE_PRIVATEKEY", "false");
        instance.init(42, config, anyContext, null);
        
        final RequestContext context = new RequestContext();
        final File tempDirFolder = new File(System.getProperty("java.io.tmpdir"));
        
        context.setServices(services);
        
        final SignatureRequest req = new SignatureRequest(42, new ByteArrayReadableData("abc".getBytes(StandardCharsets.UTF_8), tempDirFolder),
                                                              new TemporarlyWritableData(false, tempDirFolder));
        instance.acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, req, context);

        assertNotNull("aquireCryptoInstance called",
                      MockedCryptoToken.aquireCryptoInstanceParams);
        assertEquals("Requested caching of private key", false,
                    MockedCryptoToken.aquireCryptoInstanceParams.get(ICryptoTokenV4.PARAM_CACHEPRIVATEKEY));
    }
    
    /**
     * Test that setting the cache private key option to true results in
     * requesting caching when aquiring the token.
     * 
     * @throws Exception 
     */
    @Test
    public void testCachePrivateKeyTrue() throws Exception {
        final Properties globalConfig = new Properties();
        final TestSigner instance = new TestSigner(globalConfig);
        final WorkerConfig config = new WorkerConfig();
        final MockServices services = new MockServices(globalConfig);
        
        config.setProperty(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS,
                           MockedCryptoToken.class.getName());
        config.setProperty("DEFAULTKEY", TestAliasSelector.ALIAS);
        config.setProperty("CACHE_PRIVATEKEY", "true");
        instance.init(42, config, anyContext, null);
        
        final RequestContext context = new RequestContext();
        final File tempDirFolder = new File(System.getProperty("java.io.tmpdir"));
        
        context.setServices(services);
        
        final SignatureRequest req = new SignatureRequest(42, new ByteArrayReadableData("abc".getBytes(StandardCharsets.UTF_8), tempDirFolder),
                                                              new TemporarlyWritableData(false, tempDirFolder));
        instance.acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, req, context);

        assertNotNull("aquireCryptoInstance called",
                      MockedCryptoToken.aquireCryptoInstanceParams);
        assertEquals("Requested caching of private key", true,
                    MockedCryptoToken.aquireCryptoInstanceParams.get(ICryptoTokenV4.PARAM_CACHEPRIVATEKEY));
    }

    /** CryptoToken only holding its properties and offering a way to access them. */
    private static class MockedCryptoToken extends NullCryptoToken {

        private Properties props;

        private static final Certificate CERTIFICATE;
        private final Map<String, List<Certificate>> importedChains =
                new HashMap<>();

        static Map<String, Object> aquireCryptoInstanceParams = null;
        
        static {
            try {
                CERTIFICATE =
                        CertTools.getCertfromByteArray(Base64.decode(CERT1.getBytes()));
            } catch (CertificateException ex) {
                throw new RuntimeException("Load test certificate failed", ex);
            }
        }

        public MockedCryptoToken() {
            super(WorkerStatus.STATUS_ACTIVE);
        }

        @Override
        public void init(int workerId, Properties props, IServices services) {
            this.props = props;
        }

        public Properties getProps() {
            return props;
        }

        /** Harcoded to certbyte1. **/
        public static Certificate getCertificate() {
            return CERTIFICATE;
        }
        
        

        @Override
        public void importCertificateChain(List<Certificate> certChain, String alias, char[] athenticationCode, Map<String, Object> params, IServices services) throws CryptoTokenOfflineException, IllegalArgumentException {
            importedChains.put(alias, certChain);
        }

        @Override
        public ICryptoInstance acquireCryptoInstance(String alias, Map<String, Object> params, RequestContext context) throws CryptoTokenOfflineException {
            PrivateKey privateKey = null;
            aquireCryptoInstanceParams = params;
            return new DefaultCryptoInstance("anyAlias", context, new BouncyCastleProvider(), privateKey, importedChains.isEmpty() ? Arrays.asList(CERTIFICATE) : importedChains.get(alias));
        }

    }

    /** Test instance with mocked GlobalConfigurationSession containing the supplied properties. */
    private static class TestSigner extends BaseSigner {

        /** Simulates global configuration. **/
        private final Properties globalProperties;

        public TestSigner(Properties globalProperties) {
            this.globalProperties = globalProperties;
        }

        @Override
        public Response processData(Request signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected List<String> getFatalErrors(IServices services) {
            return super.getFatalErrors(services);
        }
        
        @Override
        protected AliasSelector createAliasSelector(final String className) {
            return new TestAliasSelector();
        }
        
    }
    
    private static class MockServices implements IServices {

        private HashMap<Class, Object> services = new HashMap<>();
        
        public MockServices(final Properties globalProperties) {
            services.put(GlobalConfigurationSessionLocal.class, new GlobalConfigurationSessionLocal() {

                @Override
                public void setProperty(String scope, String key, String value) {
                    throw new UnsupportedOperationException("Not supported yet.");
                }

                @Override
                public boolean removeProperty(String scope, String key) {
                    throw new UnsupportedOperationException("Not supported yet.");
                }

                @Override
                public GlobalConfiguration getGlobalConfiguration() {
                    return new GlobalConfiguration(globalProperties, GlobalConfiguration.STATE_INSYNC, "1.2.3");
                }

                @Override
                public void resync() throws ResyncException {
                    throw new UnsupportedOperationException("Not supported yet.");
                }

                @Override
                public void reload() {
                    throw new UnsupportedOperationException("Not supported yet.");
                }

                @Override
                public void setProperty(AdminInfo adminInfo, String scope, String key, String value) {
                    throw new UnsupportedOperationException("Not supported yet.");
                }

                @Override
                public boolean removeProperty(AdminInfo adminInfo, String scope, String key) {
                    throw new UnsupportedOperationException("Not supported yet.");
                }

                @Override
                public void resync(AdminInfo adminInfo) throws ResyncException {
                    throw new UnsupportedOperationException("Not supported yet.");
                }

                @Override
                public void reload(AdminInfo adminInfo) {
                    throw new UnsupportedOperationException("Not supported yet.");
                }
            });
        }
        
        @Override
        public <T> T get(Class<? extends T> type) {
            return (T) services.get(type);
        }

        @Override
        public <T> T put(Class<? extends T> type, T service) {
            return (T) services.put(type, service);
        }
        
    }
    
    private static class TestAliasSelector implements AliasSelector {

        public static final String ALIAS = "Test";
        
        @Override
        public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
            
        }

        @Override
        public String getAlias(int purpose, IProcessable processble, Request signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
            return ALIAS;
        }

        @Override
        public List<String> getFatalErrors() {
            return Collections.singletonList("Test alias selector error");
        }
        
    }
}
