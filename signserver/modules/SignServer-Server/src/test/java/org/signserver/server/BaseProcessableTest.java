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

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.persistence.EntityManager;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.util.CertTools;
import org.junit.Test;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.ResyncException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.server.aliasselectors.AliasSelector;
import org.signserver.server.cryptotokens.NullCryptoToken;
import org.signserver.server.signers.BaseSigner;

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
    
    private static byte[] certbytes1 = Base64.decode((
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
            + "oj/7HSYZlqigM72nR8f/gv1TwLVKz+ygzg==").getBytes());
    
    private static byte[] certbytes2 = Base64.decode((
              "MIID7zCCAqigAwIBAgIIWOzgRTcR/iAwPAYJKoZIhvcNAQEKMC+gDzANBglghkgB"
            + "ZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEFADA/MRMwEQYDVQQD"
            + "EwpTZXRlY1Rlc3QyMRswGQYDVQQKExJSaWtzcG9saXNzdHlyZWxzZW4xCzAJBgNV"
            + "BAYTAlNFMB4XDTA1MDkxMjA5MTg1MloXDTE1MDkwOTA5Mjg1MlowZzEcMBoGA1UE"
            + "AxMTVGVzdCBhdiBFeHByZXNzUGFzczEOMAwGA1UEBRMFMTIzNDUxDTALBgNVBAsT"
            + "BFBhc3MxGzAZBgNVBAoTElJpa3Nwb2xpc3N0eXJlbHNlbjELMAkGA1UEBhMCU0Uw"
            + "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDmZqPJNogVtiRZ9loOFJ7U"
            + "PMsrqWXZZ8R+nTPB72+kQ+4qOpgUHfto7QpSbs9/9wGrUsxc/mpadt/gRTztl6FW"
            + "GQ4TknOkoDFP+MilP08u5ZbOJrbN3E7vy0dEszzO9aHLBHXV1w2pWTlVV2kWABpl"
            + "4R4lfyWBroqpahhSReOrgL/utgcVgWkpYYb9Rx67aSl83F3lNZBMUTGR4gi/eQ5z"
            + "ug+VYDDWLyBPw7jymspQ+RwbeDaR7k8lS4sRI/QgJtVTDtzMgTPlfvWDQIxofdki"
            + "ZnG3t30aDxif5O3qaUbwMSA4Jfo6xgc2f+NPdFjhYarRTezNB8D4J4yT02U5bI6H"
            + "AgMBAAGjaTBnMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUKvx2IjcjhAFFpp80"
            + "ytO9KsC+rGgwHwYDVR0jBBgwFoAU19fDl5KAW2KqbuIHGG24AL+RfvAwFQYDVR0g"
            + "BA4wDDAKBggqhXBUCgEBATA8BgkqhkiG9w0BAQowL6APMA0GCWCGSAFlAwQCAQUA"
            + "oRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAA4IBAQBIH8UOXoaZ/ImkF6Co"
            + "eIII6KHsd+5CAro0hiBXDAkuLmPSVHp6jgv7chv0W7CL89veu7Vy+7aow1hVkGC9"
            + "XTmgrCGiKzw9+XGJsunLmAMhLj/QztnkJgQBo/09geM+w5UTdR+5PP9nRs9oJtlU"
            + "FCOcN8VJEeIvgDyWoMUDG7K1YvjmkEU6CPVYrL2PAdY0bPZvTIymC1HuyPmMnf83"
            + "QKHW0KKtb4uhkruTkX87yZm7fZZXfso6HeUKQ0+fbcqmQdXFEcJJEKSHTCcu5BVj"
            + "JebCC2FiSP88KPGGW5D351LJ+UL8En3oA5eHxZCy/LeGejPw0N02XjVFfBZEKnf6"
            + "5a94").getBytes());



    /** Tests the base case were no default properties are used to configure the PKCS11CryptoToken. */
    @Test
    public void testGetCryptoToken_noDefaults() throws Exception {
        LOG.info("testGetCryptoToken_noDefaults");
        
        Properties globalConfig = new Properties();
        WorkerConfig workerConfig = new WorkerConfig();
        
        // Exercising all properties (except SLOTLISTINDEX)
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", MockedCryptoToken.class.getName());
        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("SHAREDLIBRARY", "/opt/hsm/pkcs11.so");
        workerConfig.setProperty("SHAREDLIBRARYNAME", "P11Library");
        workerConfig.setProperty("SLOT", "3");
        workerConfig.setProperty("ATTRIBUTESFILE", "/opt/hsm/sunpkcs11.cfg");
        
        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        MockedCryptoToken actualToken = (MockedCryptoToken) instance.getCryptoToken();
        Properties actualProperties = actualToken.getProps();
        
        assertEquals("same as worker config", workerConfig.getProperties().toString(), actualProperties.toString());
        
        // Exercising all properties (except SLOT)
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", MockedCryptoToken.class.getName());
        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("SHAREDLIBRARY", "/opt/hsm/pkcs11.so");
        workerConfig.setProperty("SHAREDLIBRARYNAME", "P11Library");
        workerConfig.setProperty("SLOTLISTINDEX", "2");
        workerConfig.setProperty("ATTRIBUTESFILE", "/opt/hsm/sunpkcs11.cfg");
        
        instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        actualToken = (MockedCryptoToken) instance.getCryptoToken();
        actualProperties = actualToken.getProps();
        
        assertEquals("same as worker config", workerConfig.getProperties().toString(), actualProperties.toString());
    }
    
    /** 
     * Test default value for SLOTLISTINDEX and ATTRIBUTES. 
     * First the value is specified only as a default value and then the value 
     * is overriden by the worker.
     */
    @Test
    public void testGetCryptoToken_defaultSlotListIndex() throws Exception {
        LOG.info("testGetCryptoToken_defaultSlotListIndex");
        
        Properties globalConfig = new Properties();
        WorkerConfig workerConfig = new WorkerConfig();
        
        // SLOTLISTINDEX only in GlobalConfiguration
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", MockedCryptoToken.class.getName());
        globalConfig.setProperty("GLOB.DEFAULT.SLOTLISTINDEX", "33");
        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("ATTRIBUTES", SAMPLE_ATTRIBUTES);
        
        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        MockedCryptoToken actualToken = (MockedCryptoToken) instance.getCryptoToken();
        Properties actualProperties = actualToken.getProps();
        
        Properties expectedProperties = new Properties(workerConfig.getProperties());
        expectedProperties.putAll(workerConfig.getProperties());
        expectedProperties.setProperty("SLOTLISTINDEX", "33");
        assertEquals("default SLOTLISTINDEX used", 
                expectedProperties.toString(), actualProperties.toString());
        
        // SLOTLISTINDEX both in GlobalConfiguration and in Worker Config
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", MockedCryptoToken.class.getName());
        globalConfig.setProperty("GLOB.DEFAULT.SLOTLISTINDEX", "33");
        workerConfig.setProperty("NAME", "TestSigner100");
        workerConfig.setProperty("SHAREDLIBRARY", "/opt/hsm/pkcs11.so");
        workerConfig.setProperty("SHAREDLIBRARYNAME", "P11Library");
        workerConfig.setProperty("SLOTLISTINDEX", "44");
        workerConfig.setProperty("ATTRIBUTES", SAMPLE_ATTRIBUTES);
        
        instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        actualToken = (MockedCryptoToken) instance.getCryptoToken();
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
     */
    @Test
    public void testGetCryptoToken_defaultAll() throws Exception {
        LOG.info("testGetCryptoToken_defaultAll");
        
        Properties globalConfig = new Properties();
        WorkerConfig workerConfig = new WorkerConfig();
        
        // All PKCS#11 properties that can have default values in GlobalConfiguration (except SLOTLISTINDEX, ATTRIBUTES)
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", MockedCryptoToken.class.getName());
        globalConfig.setProperty("GLOB.DEFAULT.SHAREDLIBRARY", "/opt/hsm/default-pkcs11.so");
        globalConfig.setProperty("GLOB.DEFAULT.SHAREDLIBRARYNAME", "DefaultLibrary");
        globalConfig.setProperty("GLOB.DEFAULT.SLOT", "44");
        globalConfig.setProperty("GLOB.DEFAULT.ATTRIBUTESFILE", "/opt/hsm/default-sunpkcs11.cfg");
        globalConfig.setProperty("GLOB.DEFAULT.PIN", "FooBar789");
        workerConfig.setProperty("NAME", "TestSigner100");
        
        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        MockedCryptoToken actualToken = (MockedCryptoToken) instance.getCryptoToken();
        Properties actualProperties = actualToken.getProps();
        
        Properties expectedProperties = new Properties();
        expectedProperties.putAll(workerConfig.getProperties());
        expectedProperties.setProperty("SHAREDLIBRARY", "/opt/hsm/default-pkcs11.so");
        expectedProperties.setProperty("SHAREDLIBRARYNAME", "DefaultLibrary");
        expectedProperties.setProperty("SLOT", "44");
        expectedProperties.setProperty("ATTRIBUTESFILE", "/opt/hsm/default-sunpkcs11.cfg");
        expectedProperties.setProperty("PIN", "FooBar789");
        assertEquals("default SHAREDLIBRARY etc used", 
                expectedProperties.toString(), actualProperties.toString());
        
        // All PKCS#11 properties that can have default values GlobalConfiguration and overriden in Worker Config (except SLOTLISTINDEX, ATTRIBUTES)
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", MockedCryptoToken.class.getName());
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
        actualToken = (MockedCryptoToken) instance.getCryptoToken();
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
     * @throws Exception
     */
    @Test
    public void testCryptoToken_unknownClass() throws Exception {
        Properties globalConfig = new Properties();
        WorkerConfig workerConfig = new WorkerConfig();
        
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", "org.foo.Bar");
        workerConfig.setProperty("NAME", "TestSigner100");
        
        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        
        final List<String> fatalErrors = instance.getSignerFatalErrors();
        
        assertTrue("Should contain error", fatalErrors.contains("Crypto token class not found: org.foo.Bar"));
    }

    /**
     * Tests that when no certificate is explicitly set in the configuration
     * then certificate from the token is used.
     * @throws Exception
     */
    @Test
    public void testCertificateInTokenUsed() throws Exception {
        LOG.info("testCertificateInTokenUsed");

        Properties globalConfig = new Properties();
        WorkerConfig workerConfig = new WorkerConfig();
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", MockedCryptoToken.class.getName());
        workerConfig.setProperty("NAME", "TestSigner200");
        // Note: No SIGNERCERT or SIGNERCERTCHAIN configured so cert from token should be used

        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);

        // Certifcate in token is "CN=Signer 4"
        assertEquals("cert from token", "Signer 4", CertTools.getPartFromDN(((X509Certificate) instance.getSigningCertificate()).getSubjectX500Principal().getName(), "CN"));
        assertEquals("cert from token", "Signer 4", CertTools.getPartFromDN(((X509Certificate) instance.getSigningCertificateChain().get(0)).getSubjectX500Principal().getName(), "CN"));
    }

    /**
     * Tests that when a certificate is explicitly set in the configuration that
     * certificate is used instead of the one in the token.
     * @throws Exception
     */
    // TODO: this should be removed, I think
//    @Test
//    public void testCertificateInTokenOverridden() throws Exception {
//        LOG.info("testCertificateInTokenOverridden");
//
//        Properties globalConfig = new Properties();
//        WorkerConfig workerConfig = new WorkerConfig();
//        globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
//        globalConfig.setProperty("GLOB.WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", MockedCryptoToken.class.getName());
//        workerConfig.setProperty("NAME", "TestSigner200");
//
//        // Configure certbytes3 (CN=End Entity 1)
//        workerConfig.setProperty("SIGNERCERT", "-----BEGIN CERTIFICATE-----\n" + new String(Base64.encode(HardCodedCryptoToken.certbytes3)) + "\n-----END CERTIFICATE-----");
//        workerConfig.setProperty("SIGNERCERTCHAIN", "-----BEGIN CERTIFICATE-----\n" + new String(Base64.encode(HardCodedCryptoToken.certbytes3)) + "\n-----END CERTIFICATE-----");
//
//        TestSigner instance = new TestSigner(globalConfig);
//        instance.init(workerId, workerConfig, anyContext, null);
//
//        // Certifcate in token is "CN=Signer 4", configured certificate is "CN=End Entity 1"
//        assertEquals("cert from token", "End Entity 1", CertTools.getPartFromDN(((X509Certificate) instance.getSigningCertificate()).getSubjectX500Principal().getName(), "CN"));
//        assertEquals("cert from token", "End Entity 1", CertTools.getPartFromDN(((X509Certificate) instance.getSigningCertificateChain().get(0)).getSubjectX500Principal().getName(), "CN"));
//    }

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

        globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", 
                "org.signserver.server.cryptotokens.PKCS11CryptoToken");
        workerConfig.setProperty("NAME", "TestSigner100");
        
        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        
        final List<String> fatalErrors = instance.getSignerFatalErrors();
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
        
        TestSigner instance = new TestSigner(globalConfig);
        
        instance.init(workerId, workerConfig, anyContext, null);
        
        final AliasSelector selector = instance.createAliasSelector(null);
        
        assertTrue("Alias selector implementation: " + selector.getClass().getName(),
                    selector instanceof TestAliasSelector);
        assertEquals("Alias", "Test",
                selector.getAlias(workerId, instance, null, null));
        
        final List<String> errors = instance.getSignerFatalErrors();
        
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
        
        // Exercising all properties (except SLOTLISTINDEX)
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".CLASSPATH", TestSigner.class.getName());
        globalConfig.setProperty("GLOB.WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", MockedCryptoToken.class.getName());
        workerConfig.setProperty("NAME", "TestSigner100");
        
        TestSigner instance = new TestSigner(globalConfig);
        instance.init(workerId, workerConfig, anyContext, null);
        
            
        final List<Certificate> chain =
                Arrays.asList(CertTools.getCertfromByteArray(certbytes2));
        
        instance.importCertificateChain(chain, "alias2", null, Collections.<String, Object>emptyMap(), new ServicesImpl());
        
        final List<Certificate> importedChain =
                instance.getSigningCertificateChain("alias2");
        
        assertTrue("Matching certificate",
                Arrays.equals(chain.get(0).getEncoded(),
                              importedChain.get(0).getEncoded()));
    }
    
    /** CryptoToken only holding its properties and offering a way to access them. */
    private static class MockedCryptoToken extends NullCryptoToken {

        private Properties props;

        private static final Certificate CERTIFICATE;
        private final Map<String, List<Certificate>> importedChains =
                new HashMap<String, List<Certificate>>();
        
        static {
            try {
                CERTIFICATE = CertTools.getCertfromByteArray(certbytes1);
            } catch (CertificateException ex) {
                throw new RuntimeException("Load test certificate failed", ex);
            }
        }

        public MockedCryptoToken() {
            super(WorkerStatus.STATUS_ACTIVE);
        }

        @Override
        public void init(int workerId, Properties props) {
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
        public List<Certificate> getCertificateChain(int purpose) throws CryptoTokenOfflineException {
            return Arrays.asList(CERTIFICATE);
        }

        @Override
        public Certificate getCertificate(int purpose) throws CryptoTokenOfflineException {
            return CERTIFICATE;
        }

        @Override
        public void importCertificateChain(List<Certificate> certChain, String alias, char[] athenticationCode, Map<String, Object> params, IServices services) throws CryptoTokenOfflineException, IllegalArgumentException {
            importedChains.put(alias, certChain);
        }

        @Override
        public Certificate getCertificate(String alias) throws CryptoTokenOfflineException {
            return CERTIFICATE;
        }

        @Override
        public List<Certificate> getCertificateChain(String alias) throws CryptoTokenOfflineException {
            final List<Certificate> chain = importedChains.get(alias);
            
            if (chain == null) {
                // fall-back to the hard-coded cert
                return Collections.singletonList(CERTIFICATE);
            }
            
            return chain;
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
        protected IGlobalConfigurationSession getGlobalConfigurationSession() {
            return new IGlobalConfigurationSession() {

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
            };
        }

        @Override
        public ProcessResponse processData(ProcessRequest signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        List<String> getSignerFatalErrors() {
            return super.getFatalErrors();
        }
        
        @Override
        protected AliasSelector createAliasSelector(final String className) {
            return new TestAliasSelector();
        }
        
    }
    
    private static class TestAliasSelector implements AliasSelector {

        @Override
        public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
            
        }

        @Override
        public String getAlias(int purpose, IProcessable processble, ProcessRequest signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
            return "Test";
        }

        @Override
        public List<String> getFatalErrors() {
            return Collections.singletonList("Test alias selector error");
        }
        
    }
}
