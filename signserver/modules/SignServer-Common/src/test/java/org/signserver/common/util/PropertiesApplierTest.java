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
package org.signserver.common.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.util.PropertiesParser.GlobalProperty;
import org.signserver.common.util.PropertiesParser.WorkerProperty;

import junit.framework.TestCase;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.MatchIssuerWithType;
import org.signserver.common.MatchSubjectWithType;

/**
 * Tests for the property applier used for loading configuration property files.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class PropertiesApplierTest extends TestCase {
    
    final MockPropertiesApplier applier =
            new MockPropertiesApplier();
    
    private static String SIGNER_CERT =
            "MIIEkTCCAnmgAwIBAgIIeCvAS5OwAJswDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzEyMTU1NVoXDTIxMDUyNDEyMTU1NVowSjEUMBIGA1UEAwwLVFMgU2lnbmVyIDExEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnT38GG8i/bGnuFMwnOdg+caHMkdPBacRdBaIggwMPfE50SOZ2TLrDEHJotxYda7HS0+tX5dIcalmEYCls/ptHzO5TQpqdRTuTqxp5cMA379yhD0OqTVNAmHrvPj9IytktoAtB/xcjwkRTHagaCmg5SWNcLKyVUct7nbeRA5yDSJQsCAEGHNZbJ50vATg1DQEyKT87GKfSBsclA0WIIIHMt8/SRhpsUZxESayU6YA4KCxVtexF5x+COLB6CzzlRG9JA8WpX9yKgIMsMDAscsJLiLPjhET5hwAFm5ZRfQQG9LI06QNTGqukuTlDbYrQGAUR5ZXW00WNHfgS00CjUCu0QIDAQABo3gwdjAdBgNVHQ4EFgQUOF0FflO2G+IN6c92pCNlPoorGVwwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBADELkeIO9aiKjS/GaBUUhMr+k5UbVeK69WapU+7gTsWwa9D2vAOhAkfQ1OcUJoZaminv8pcNfo1Ey5qLtxBCmUy1fVomVWOPl6u1w8B6uYgE608hi2bfx28uIeksqpdqUX0Qf6ReUyl+FOh4xNrsyaF81TrIKt8ekq0iD+YAtT/jqgv4bUvs5fgIms4QOXgMUzNAP7cPU44KxcmR5I5Uy/Ag82hGIz64hZmeIDT0X59kbQvlZqFaiZvYOikoZSFvdM5kSVfItMgp7qmyLxuM/WaXqJWp6Mm+8ZZmcECugd4AEpE7xIiB7M/KEe+X4ItBNTKdAoaxWa+yeuYS7ol9rHt+Nogelj/06ZRQ0x03UqC7uKpgYAICjQEXIjcZofWSTh9KzKNfS1sQyIQ6yNTT2VMdYW9JC2OLKPV4AEJuBw30X8HOciJRRXOq9KRrIA2RSiaC5/3oAYscWuo31Fmj8CWQknXAIb39gPuZRwGOJbi1tUu2zmRsUNJfAe3hnvk+uxhnyp2vKB2KN5/VQgisx+8doEK/+Nbj/PPG/zASKimWG++5m0JNY4chIfR43gDDcF+4INof/8V84wbvUF+TpvP/mYM8wC9OkUyRvzqv9vjWOncCdbdjCuqPxDItwm9hhr+PbxsMaBes9rAiV9YT1FnpA++YpCufveFCQPDbCTgJ";
    
    private static String SIGNER_CERT_CHAIN =
            "MIIEkTCCAnmgAwIBAgIIeCvAS5OwAJswDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzEyMTU1NVoXDTIxMDUyNDEyMTU1NVowSjEUMBIGA1UEAwwLVFMgU2lnbmVyIDExEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnT38GG8i/bGnuFMwnOdg+caHMkdPBacRdBaIggwMPfE50SOZ2TLrDEHJotxYda7HS0+tX5dIcalmEYCls/ptHzO5TQpqdRTuTqxp5cMA379yhD0OqTVNAmHrvPj9IytktoAtB/xcjwkRTHagaCmg5SWNcLKyVUct7nbeRA5yDSJQsCAEGHNZbJ50vATg1DQEyKT87GKfSBsclA0WIIIHMt8/SRhpsUZxESayU6YA4KCxVtexF5x+COLB6CzzlRG9JA8WpX9yKgIMsMDAscsJLiLPjhET5hwAFm5ZRfQQG9LI06QNTGqukuTlDbYrQGAUR5ZXW00WNHfgS00CjUCu0QIDAQABo3gwdjAdBgNVHQ4EFgQUOF0FflO2G+IN6c92pCNlPoorGVwwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBADELkeIO9aiKjS/GaBUUhMr+k5UbVeK69WapU+7gTsWwa9D2vAOhAkfQ1OcUJoZaminv8pcNfo1Ey5qLtxBCmUy1fVomVWOPl6u1w8B6uYgE608hi2bfx28uIeksqpdqUX0Qf6ReUyl+FOh4xNrsyaF81TrIKt8ekq0iD+YAtT/jqgv4bUvs5fgIms4QOXgMUzNAP7cPU44KxcmR5I5Uy/Ag82hGIz64hZmeIDT0X59kbQvlZqFaiZvYOikoZSFvdM5kSVfItMgp7qmyLxuM/WaXqJWp6Mm+8ZZmcECugd4AEpE7xIiB7M/KEe+X4ItBNTKdAoaxWa+yeuYS7ol9rHt+Nogelj/06ZRQ0x03UqC7uKpgYAICjQEXIjcZofWSTh9KzKNfS1sQyIQ6yNTT2VMdYW9JC2OLKPV4AEJuBw30X8HOciJRRXOq9KRrIA2RSiaC5/3oAYscWuo31Fmj8CWQknXAIb39gPuZRwGOJbi1tUu2zmRsUNJfAe3hnvk+uxhnyp2vKB2KN5/VQgisx+8doEK/+Nbj/PPG/zASKimWG++5m0JNY4chIfR43gDDcF+4INof/8V84wbvUF+TpvP/mYM8wC9OkUyRvzqv9vjWOncCdbdjCuqPxDItwm9hhr+PbxsMaBes9rAiV9YT1FnpA++YpCufveFCQPDbCTgJ;MIIFfzCCA2egAwIBAgIIMk1BOK8CwTwwDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzA4MTQyN1oXDTM2MDUyNzA4MTQyN1owTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgblgjTTkMp1QAhgWDprhvqE9zX1Ux/A/RTOu4G4f6CTkd6JEEkbdKZv+CKv4cRoVCtfO3wnOokFRw/1JMmHHiQ1Z//uDoDjo8jk8nek0ArFE9R5NT02wMJCQa/mP1wU9ZSl1tx3jQRUFB+rTNeCcPTft+1FL7UjYMdkRzl261IOlmXzDMA+EYIGJ2c2wYhOv2DqfQygNz5GOf0EFqlQZIt/pzopSS+0K8mNb53ROhg9GJujwzugSH5Z+r0fsVHbCV0QUkZBfkRo9KMcdaDEPa8xpYTjsFPqU6RcnGkVABhn8OS8SIWw2re1f+htj6p9EGbk1m0I9pWGBA9ktWnrqlqDXV+tEhhh1O4f+LHieoxiscrF7RXxlYqyam6oabfXsX3VAC0M1UkwIciE8wA1Sj/+dgoSMqvEDNDfwpEYt6l8Z8czDTWDi7MM2u5VY0nP3+A+PepKrOtrdaGSP396f4a7A3un1o6nQWHsyWQ7kc8GIn8zN5nykQaghGyYlHHYe1XUSPtHmxjbdsyztrkIis3cfjFne0XgPAiQuYx3T/B+po9BhGIUwCV0Qi/gWVN6NkydsbzMeRXELQYyK+lHgIGiEaBzQRRtXbnB+wQXi2IacJNdKqICwDsl/PvvcZI9ZV6pB/KIzB+8IJm0CLY24K0OXJs3Bqij8gmpvbI+o0wUCAwEAAaNjMGEwHQYDVR0OBBYEFCB6Id7orbsCqPtxWKQJYrnYWAWiMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUIHoh3uituwKo+3FYpAliudhYBaIwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQAxFvpOZF6Kol48cQeKWQ48VAe+h5dmyKMfDLDZX51IRzfKKsHLpFPxzGNw4t9Uv4YOR0CD9z81dR+c93t1lwwIpKbx9Qmq8jViHEHKYD9FXThM+cVpsT25pg35m3ONeUX/b++l2d+2QNNTWMvdsCtaQdybZqbYFIk0IjPwLLqdsA8Io60kuES4JnQahPdLkfm70rgAdmRDozOfSDaaWHY20DovkfvKUYjPR6MGAPD5w9dEb4wp/ZjATblyZnH+LTflwfftUAonmAw46E0Zgg143sO6RfOOnbwjXEc+KXd/KQ6kTQ560mlyRd6q7EIDYRfD4n4agKV2R5gvVPhMD0+IK7kagqKNfWa9z8Ue2N3MedyWnb9wv4wC69qFndGaIfYADkUykoOyLsVVteJ70PVJPXO7s66LucfD2R0wo2MpuOYCsTOm7HHS+uZ9VjHl2qQ0ZQG89Xn+AXnzPbk1INe2z0lq3hzCW5DTYBKsJEexErzMpLwiEqUYJUfR9EeCM8UPMtLSqz1utdPoIYhULGzt5lSJEpMHMbquYfWJxQiKCbvfxQsP5dLUMEIqTgjNdo98OlM7Z7zjYH9Kimz3wgAKSAIoQZr7Oy1dMHO5GK4jBtZ8wgsyyQ6DzQQ7R68XFVKarIW8SATeyubAP+WjdMwk/ZXzsDjMZEtENaBXzAefYA==";
 
    /**
     * Test config setting up a worker.
     */
    private static String config1 =
            "GLOB.WORKER42.CLASSPATH = foo.bar.Worker\n" +
            "GLOB.SIGNER42.SIGNERTOKEN.CLASSPATH = foo.bar.Token\n" +
            "WORKER42.NAME = TestSigner\n" +
            "WORKER42.FOOBAR = Some value\n" +
            "SIGNER42.OLDPROPERTY = Some other value\n" +
            "WORKER42.SIGNERCERTIFICATE = " + SIGNER_CERT + "\n" +
            "WORKER42.SIGNERCERTCHAIN = " + SIGNER_CERT_CHAIN;
    
    /**
     * Test config removing a worker property from an existing worker.
     */
    private static String config2 =
            "-WORKER42.FOOBAR = Some value";
    
    /**
     * Test config with generated IDs.
     */
    private static String config3 =
            "GLOB.WORKERGENID1.CLASSPATH = foo.bar.Worker\n" +
            "GLOB.WORKERGENID1.SIGNERTOKEN.CLASSPATH = foo.bar.Token\n" +
            "WORKERGENID1.NAME = Worker1\n" +
            "GLOB.WORKERGENID2.CLASSPATH = foo.bar.Worker\n" +
            "GLOB.WORKERGENID2.SIGNERTOKEN.CLASSPATH = foo.bar.Token\n" +
            "WORKERGENID2.NAME = Worker2\n" +
            "GLOB.SIGNERGENID3.CLASSPATH = foo.bar.Worker\n" +
            "GLOB.SIGNERGENID3.SIGNERTOKEN.CLASSPATH = foo.bar.Token\n" +
            "SIGNERGENID3.NAME = Worker3\n";
    
    /**
     * Test config removing a global property.
     */
    private static String config4 =
            "-GLOB.WORKER42.CLASSPATH = foo.bar.Worker";
    
    /**
     * Test config adding auth clients.
     */
    private static String config5 =
            "WORKER42.AUTHCLIENT1 = 123456789;CN=Authorized\n" +
            "WORKER42.AUTHCLIENT2 = 987654321;CN=AlsoAuthorized";
    
    /**
     * Test config removing an authorized client.
     */
    private static String config6 =
            "-WORKER42.AUTHCLIENT1 = 123456789;CN=Authorized";
    
    /**
     *
     * /**
     * A properties file that should pass.
     */
    private static String authClientGen2Config1
            = "WORKER42.AUTHCLIENT1.ISSUER.TYPE = ISSUER_DN_BCSTYLE\n"
            + "WORKER42.AUTHCLIENT1.SUBJECT.TYPE=CERTIFICATE_SERIALNO\n"
            + "WORKER42.AUTHCLIENT1.SUBJECT.VALUE=723507815f93666666\n"
            + "WORKER42.AUTHCLIENT1.ISSUER.VALUE=CN\\=DSS Root CA 10,OU\\=Testing,O\\=SignServer,C\\=SE\n"
            + "WORKER42.AUTHCLIENT1.DESCRIPTION= test rule 1\n"
            
            + "WORKER42.AUTHCLIENT2.ISSUER.TYPE = ISSUER_DN_BCSTYLE\n"
            + "WORKER42.AUTHCLIENT2.SUBJECT.TYPE=CERTIFICATE_SERIALNO\n"
            + "WORKER42.AUTHCLIENT2.SUBJECT.VALUE=12345678\n"
            + "WORKER42.AUTHCLIENT2.ISSUER.VALUE=CN\\=DSS Root CA 10,OU\\=Testing,O\\=SignServer,C\\=SE\n"
            
            + "WORKER42.AUTHCLIENT11.ISSUER.TYPE = ISSUER_DN_BCSTYLE\n"
            + "WORKER42.AUTHCLIENT11.SUBJECT.TYPE=CERTIFICATE_SERIALNO\n"
            + "WORKER42.AUTHCLIENT11.SUBJECT.VALUE=987654321\n"
            + "WORKER42.AUTHCLIENT11.ISSUER.VALUE=CN\\=DSS Root CA 10,OU\\=Testing,O\\=SignServer,C\\=SE\n"
            + "WORKER42.AUTHCLIENT11.DESCRIPTION= test rule 2\n"
            
            + "WORKER42.AUTHCLIENT111.ISSUER.TYPE = ISSUER_DN_BCSTYLE\n"
            + "WORKER42.AUTHCLIENT111.SUBJECT.TYPE=CERTIFICATE_SERIALNO\n"
            + "WORKER42.AUTHCLIENT111.SUBJECT.VALUE=1212121212\n"
            + "WORKER42.AUTHCLIENT111.ISSUER.VALUE=CN\\=DSS Root CA 10,OU\\=Testing,O\\=SignServer,C\\=SE";
        
    /**
     *
     * /**
     * A properties file that should pass.
     */
    private static String authClientGen2Config2
            = "-WORKER42.AUTHCLIENT1.ISSUER.TYPE = ISSUER_DN_BCSTYLE\n"
            + "-WORKER42.AUTHCLIENT1.SUBJECT.TYPE=CERTIFICATE_SERIALNO\n"
            + "-WORKER42.AUTHCLIENT1.SUBJECT.VALUE=12345678\n"
            + "-WORKER42.AUTHCLIENT1.ISSUER.VALUE=CN\\=DSS Root CA 10,OU\\=Testing,O\\=SignServer,C\\=SE";
    
    
    /**
     * Test config with a malformed GENID.
     */
    private static String config7 =
            "GLOB.WORKERGENIDXXX.CLASSPATH = foo.bar.Worker\n" +
            "GLOB.WORKERGENIDXXX.SIGNERTOKEN.CLASSPATH = foo.bar.Token\n" +
            "WORKERGENIDXXX.NAME = Worker3";
    
    private static String test_two_workers_same_name
            = "WORKER100.TYPE=PROCESSABLE\n"
            + "WORKER100.IMPLEMENTATION_CLASS = org.signserver.module.tsa.TimeStampSigner\n"
            + "WORKER100.NAME=Alice\n"
            + "WORKER100.AUTHTYPE=NOAUTH\n"
            
            + "WORKER300.TYPE=PROCESSABLE\n"
            + "WORKER300.IMPLEMENTATION_CLASS = org.signserver.module.tsa.TimeStampSigner\n"
            + "WORKER300.NAME=Bob\n"
            + "WORKER300.AUTHTYPE=NOAUTH";
    
    private static String test_new_worker_genid
            = "WORKERGENID1.TYPE=PROCESSABLE\n"
            + "WORKERGENID1.IMPLEMENTATION_CLASS = org.signserver.module.tsa.TimeStampSigner\n"
            + "WORKERGENID1.NAME=Alice\n"
            + "WORKERGENID1.AUTHTYPE=NOAUTH";

    private static String test_two_workers_swapped
            = "WORKER100.TYPE=PROCESSABLE\n"
            + "WORKER100.IMPLEMENTATION_CLASS = org.signserver.module.tsa.TimeStampSigner\n"
            + "WORKER100.NAME=Bob\n"
            + "WORKER100.AUTHTYPE=NOAUTH\n"
            
            + "WORKER200.TYPE=PROCESSABLE\n"
            + "WORKER200.IMPLEMENTATION_CLASS = org.signserver.module.tsa.TimeStampSigner\n"
            + "WORKER200.NAME=Alice\n"
            + "WORKER200.AUTHTYPE=NOAUTH";
    
    private static String test_two_workers_one_with_existing_name
            = "WORKER100.TYPE=PROCESSABLE\n"
            + "WORKER100.IMPLEMENTATION_CLASS = org.signserver.module.tsa.TimeStampSigner\n"
            + "WORKER100.NAME=Cesar\n"
            + "WORKER100.AUTHTYPE=NOAUTH\n"
            
            + "WORKER200.TYPE=PROCESSABLE\n"
            + "WORKER200.IMPLEMENTATION_CLASS = org.signserver.module.tsa.TimeStampSigner\n"
            + "WORKER200.NAME=Alice\n"
            + "WORKER200.AUTHTYPE=NOAUTH";
    
    private static String test_two_workers
            = "WORKER100.TYPE=PROCESSABLE\n"
            + "WORKER100.IMPLEMENTATION_CLASS = org.signserver.module.tsa.TimeStampSigner\n"
            + "WORKER100.NAME=Alice\n"
            + "WORKER100.AUTHTYPE=NOAUTH\n"
            
            + "WORKER200.TYPE=PROCESSABLE\n"
            + "WORKER200.IMPLEMENTATION_CLASS = org.signserver.module.tsa.TimeStampSigner\n"
            + "WORKER200.NAME=Bob\n"
            + "WORKER200.AUTHTYPE=NOAUTH";
    
    private static String test_other_workers
            = "WORKER300.TYPE=PROCESSABLE\n"
            + "WORKER300.IMPLEMENTATION_CLASS = org.signserver.module.tsa.TimeStampSigner\n"
            + "WORKER300.NAME=Cesar\n"
            + "WORKER300.AUTHTYPE=NOAUTH\n"
            
            + "WORKER400.TYPE=PROCESSABLE\n"
            + "WORKER400.IMPLEMENTATION_CLASS = org.signserver.module.tsa.TimeStampSigner\n"
            + "WORKER400.NAME=Daniel\n"
            + "WORKER400.AUTHTYPE=NOAUTH";
    
    private static String test_two_workers_new_names
            = "WORKER100.TYPE=PROCESSABLE\n"
            + "WORKER100.IMPLEMENTATION_CLASS = org.signserver.module.tsa.TimeStampSigner\n"
            + "WORKER100.NAME=Cesar\n"
            + "WORKER100.AUTHTYPE=NOAUTH\n"
            
            + "WORKER200.TYPE=PROCESSABLE\n"
            + "WORKER200.IMPLEMENTATION_CLASS = org.signserver.module.tsa.TimeStampSigner\n"
            + "WORKER200.NAME=Daniel\n"
            + "WORKER200.AUTHTYPE=NOAUTH";
    /**
     * Test setting up global and worker properties.
     * Using both new WORKER and old SIGNER prefixes.
     * 
     * @throws Exception
     */
    public void testBasic() throws Exception {
        PropertiesParser parser;
        
        final Properties prop = new Properties();
        
        try {
            // test loading a basic config setting up a worker
            parser = new PropertiesParser();
            prop.load(new ByteArrayInputStream(config1.getBytes()));
            parser.process(prop);
            applier.apply(parser);
            
            assertEquals("Has set global property", "foo.bar.Worker",
                    applier.getGlobalProperty(PropertiesConstants.GLOBAL_PREFIX_DOT,
                            "WORKER42.CLASSPATH"));
            assertEquals("Has set global property", "foo.bar.Token",
                    applier.getGlobalProperty(PropertiesConstants.GLOBAL_PREFIX_DOT,
                            "WORKER42.SIGNERTOKEN.CLASSPATH"));
            assertEquals("Has set worker property", "TestSigner",
                    applier.getWorkerProperty(42, "NAME"));
            assertEquals("Has set worker property", "Some value",
                    applier.getWorkerProperty(42, "FOOBAR"));
            assertEquals("Has set worker property using old worker prefix", "Some other value",
                    applier.getWorkerProperty(42, "OLDPROPERTY"));
            assertTrue("Has uploaded signer certificate", Arrays.equals(Base64.decode(SIGNER_CERT.getBytes()), applier.getSignerCert(42)));
            assertFalse("No errors", applier.hasError());
            
            final List<byte[]> certChain = applier.getSignerCertChain(42);
            assertEquals("Number of certs in uploaded cert chain", 2, certChain.size());
            
            // test removing a worker property
            parser = new PropertiesParser();
            prop.clear();
            prop.load(new ByteArrayInputStream(config2.getBytes()));
            parser.process(prop);
            applier.apply(parser);
            
            assertNull("Should have remove worker property",
                    applier.getWorkerProperty(42, "FOOBAR"));
            assertFalse("No errors", applier.hasError());
            
            // test removing a global property
            parser = new PropertiesParser();
            prop.clear();
            prop.load(new ByteArrayInputStream(config4.getBytes()));
            parser.process(prop);
            applier.apply(parser);
            
            assertNull("Removed global property",
                    applier.getGlobalProperty(PropertiesConstants.GLOBAL_PREFIX_DOT, "WORKER42.CLASSPATH"));
            assertFalse("No errros", applier.hasError());
            
            // test adding auth clients
            parser = new PropertiesParser();
            prop.clear();
            prop.load(new ByteArrayInputStream(config5.getBytes()));
            parser.process(prop);
            applier.apply(parser);
            
            assertTrue("Authorized client", applier.isAuthorized(42, new AuthorizedClient("123456789", "CN=Authorized")));
            assertTrue("Authorized client", applier.isAuthorized(42, new AuthorizedClient("987654321", "CN=AlsoAuthorized")));
            assertFalse("No errors", applier.hasError());
            
            // test removing an auth client
            parser = new PropertiesParser();
            prop.clear();
            prop.load(new ByteArrayInputStream(config6.getBytes()));
            parser.process(prop);
            applier.apply(parser);
            
            assertFalse("Not authorized", applier.isAuthorized(42, new AuthorizedClient("123456789", "CN=Authorized")));
            assertTrue("Authorized client", applier.isAuthorized(42, new AuthorizedClient("987654321", "CN=AlsoAuthorized")));
            assertFalse("No errors", applier.hasError());
            
            // test adding gen2 auth clients
            parser = new PropertiesParser();
            prop.clear();
            prop.load(new ByteArrayInputStream(authClientGen2Config1.getBytes()));
            parser.process(prop);
            applier.apply(parser);            
            
            CertificateMatchingRule cmrToBeAdded1 = new CertificateMatchingRule(MatchSubjectWithType.valueOf("CERTIFICATE_SERIALNO"),
                    MatchIssuerWithType.valueOf("ISSUER_DN_BCSTYLE"), "723507815f93666666", "CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE", "test rule 1");
            CertificateMatchingRule cmrToBeAdded2 = new CertificateMatchingRule(MatchSubjectWithType.valueOf("CERTIFICATE_SERIALNO"),
                    MatchIssuerWithType.valueOf("ISSUER_DN_BCSTYLE"), "12345678", "CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE", "Imported rule");
            CertificateMatchingRule cmrToBeAdded3 = new CertificateMatchingRule(MatchSubjectWithType.valueOf("CERTIFICATE_SERIALNO"),
                    MatchIssuerWithType.valueOf("ISSUER_DN_BCSTYLE"), "987654321", "CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE", "test rule 2");
            CertificateMatchingRule cmrToBeAdded4 = new CertificateMatchingRule(MatchSubjectWithType.valueOf("CERTIFICATE_SERIALNO"),
                    MatchIssuerWithType.valueOf("ISSUER_DN_BCSTYLE"), "1212121212", "CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE", "Imported rule");

            assertTrue("Authorized client", applier.isAuthorizedGen2(42, cmrToBeAdded1));
            assertTrue("Authorized client", applier.isAuthorizedGen2(42, cmrToBeAdded2));
            assertTrue("Authorized client", applier.isAuthorizedGen2(42, cmrToBeAdded3));
            assertTrue("Authorized client", applier.isAuthorizedGen2(42, cmrToBeAdded4));
            assertFalse("No errors", applier.hasError());
            
            // test removing an gen2 auth client
            parser = new PropertiesParser();
            prop.clear();
            prop.load(new ByteArrayInputStream(authClientGen2Config2.getBytes()));
            parser.process(prop);
            applier.apply(parser);
            
            assertFalse("Not authorized", applier.isAuthorizedGen2(42, cmrToBeAdded2));
            assertTrue("Authorized client", applier.isAuthorizedGen2(42, cmrToBeAdded1));
            assertTrue("Authorized client", applier.isAuthorizedGen2(42, cmrToBeAdded3));
            assertTrue("Authorized client", applier.isAuthorizedGen2(42, cmrToBeAdded4));
            assertFalse("No errors", applier.hasError());
            
        } catch (IOException e) {
            fail("Failed to parse properties: " + e.getMessage());
        }
        
    }

    /**
     * Test setting up workers using generated IDs (GENIDx).
     * 
     * @throws Exception
     */
    public void testSetPropertiesGenIDs() throws Exception {
        final PropertiesParser parser = new PropertiesParser();
        
        final Properties prop = new Properties();
        
        try {
            prop.load(new ByteArrayInputStream(config3.getBytes()));
            parser.process(prop);
            applier.apply(parser);
            
            assertEquals("Set worker name for generated ID", "Worker1", applier.getWorkerProperty(1000, "NAME"));
            assertEquals("Set worker name for generated ID", "Worker2", applier.getWorkerProperty(1001, "NAME"));
            assertEquals("Set worker name for generated ID", "Worker3", applier.getWorkerProperty(1002, "NAME"));
            assertFalse("No errors", applier.hasError());
            
            final List<Integer> workerIds = applier.getWorkerIds();
            assertTrue("Contains worker ID", workerIds.contains(1000));
            assertTrue("Contains worker ID", workerIds.contains(1001));
            assertTrue("Contains worker ID", workerIds.contains(1002));
        } catch (IOException e) {
            fail("Failed to parse properties: " + e.getMessage());
        }
    }
    
    /**
     * Test using incorrect generated IDs (non-integer).
     * 
     * @throws Exception
     */
    public void testMalformedGenID() throws Exception {
        final PropertiesParser parser = new PropertiesParser();
        
        final Properties prop = new Properties();
        
        try {
            prop.load(new ByteArrayInputStream(config7.getBytes()));
            parser.process(prop);
            applier.apply(parser);
            
            assertEquals("Error message", "Illegal generated ID: GENIDXXX",
                    applier.getError());
            assertTrue("Has errors", applier.hasError());
        } catch (IOException e) {
            fail("Failed to parse properties: " + e.getMessage());
        } 
    }
    
    /**
     * Test that applying a properties file with a new worker with the same
     * name as an existing worker fails.
     * 
     * @throws Exception 
     */
    public void testSetpropertiesSameNameDifferentWorkerId() throws Exception {
        final PropertiesParser parser = new PropertiesParser();
        final Properties prop = new Properties();

        prop.load(new ByteArrayInputStream(test_two_workers_same_name.getBytes()));
        parser.process(prop);
        applier.apply(parser);

        assertEquals("Error message: " + applier.getError(), "Worker(s) with name already exists: Bob",
                applier.getError());
        assertTrue("Has errors", applier.hasError());
    }
    
    /**
     * Test that applying a properties file with a generated worker ID using the
     * same name as an existing worker fails.
     *
     * @throws Exception
     */
    public void testSetpropertiesSameNameGenId() throws Exception {
        final PropertiesParser parser = new PropertiesParser();
        final Properties prop = new Properties();

        prop.load(new ByteArrayInputStream(test_new_worker_genid.getBytes()));
        parser.process(prop);
        applier.apply(parser);

        assertEquals("Error message: " + applier.getError(), "Worker(s) with name already exists: Alice",
                applier.getError());
        assertTrue("Has errors", applier.hasError());
    }
    
    /**
     * Test that applying a properties file with the worker names of two existing
     * workers swapped fails.
     * Note: this case is currently expected to fail, but could theoretically
     * be made to work in the future (when setting a set of properties is
     * treated as an atomic operation).
     * 
     * @throws Exception 
     */
    public void testSetpropertiesSwappedWorkerNames() throws Exception {
        final PropertiesParser parser = new PropertiesParser();
        final Properties prop = new Properties();

        prop.load(new ByteArrayInputStream(test_two_workers_swapped.getBytes()));
        parser.process(prop);
        applier.apply(parser);

        assertEquals("Error message: " + applier.getError(), "Worker(s) with name already exists: Alice Bob",
                applier.getError());
        assertTrue("Has errors", applier.hasError());
    }
    
    /**
     * Test that applying the same properties twice works - one set of properties already in DB.
     * 
     * @throws Exception 
     */
    public void test01SetpropertiesTwice() throws Exception {
        final PropertiesParser parser = new PropertiesParser();
        final Properties prop = new Properties();
        
        prop.load(new ByteArrayInputStream(test_two_workers.getBytes()));
        parser.process(prop);
        applier.apply(parser);
        assertFalse("Has errors", applier.hasError());
    }
    
    /**
     * Test that applying a properties file where a worker's name is set
     * to a worker name already existing fails even in the case where that worker
     * was also renamed.
     * Note: this case could be made to work (in case setting a set of properties
     * would be treated as an atomic operation), but for now we don't support
     * this case. With the option of being more lenient in the future.
     * 
     * @throws Exception 
     */
    public void testSetpropertiesOneWithExistingName() throws Exception {
        final PropertiesParser parser = new PropertiesParser();
        final Properties prop = new Properties();

        prop.load(new ByteArrayInputStream(test_two_workers_one_with_existing_name.getBytes()));
        parser.process(prop);
        applier.apply(parser);

        assertEquals("Error message: " + applier.getError(), "Worker(s) with name already exists: Alice",
                applier.getError());
        assertTrue("Has errors", applier.hasError());
    }
    
    /**
     * Test that applying a properties file and then another with a different
     * set of workers, should work.
     * 
     * @throws Exception 
     */
    public void testSetpropertiesDifferentWorkers() throws Exception {
        final PropertiesParser parser = new PropertiesParser();
        final Properties prop = new Properties();

        prop.load(new ByteArrayInputStream(test_other_workers.getBytes()));
        parser.process(prop);
        applier.apply(parser);
        assertFalse("Has errors", applier.hasError());
    }
    
    /**
     * Test that changing name on two existing workers to completely new names
     * works.
     * 
     * @throws Exception 
     */
    public void testSetpropertiesRenameBoth() throws Exception {
        final PropertiesParser parser = new PropertiesParser();
        final Properties prop = new Properties();

        prop.load(new ByteArrayInputStream(test_two_workers_new_names.getBytes()));
        parser.process(prop);
        applier.apply(parser);
        assertFalse("Has errors", applier.hasError());
    }   
        
    /**
     * Mock implementation of the PropertiesApplier.
     * 
     */
    private static class MockPropertiesApplier extends PropertiesApplier {

        private Map<GlobalProperty, String> globalProperties = new HashMap<>();
        private Map<WorkerProperty, String> workerProperties = new HashMap<>();
        private Map<Integer, Set<AuthorizedClient>> authClients = new HashMap<>();
        private Map<Integer, Set<CertificateMatchingRule>> authClientsGen2 = new HashMap<>();
        private Map<Integer, byte[]> signerCerts = new HashMap<>();
        private Map<Integer, List<byte[]>> signerCertChains = new HashMap<>();
        
        private Map<String, String> mockedWokersInDB = Stream.of(new String[][]{
            {"100", "Alice"},
            {"200", "Bob"},}).collect(Collectors.toMap(data -> data[0], data -> data[1]));
               
        
        public static int FIRST_GENERATED_ID = 1000;
        
        public String getWorkerProperty(final int workerId, final String key) {
            return workerProperties.get(new WorkerProperty(Integer.toString(workerId), key));
        }
        
        public String getGlobalProperty(final String scope, final String key) {
            return globalProperties.get(new GlobalProperty(scope, key));
        }
        
        public boolean isAuthorized(final int workerId, final AuthorizedClient ac) {
            final Set<AuthorizedClient> acs = authClients.get(workerId);
            
            if (acs != null) {
                return acs.contains(ac);
            }
            
            return false;
        }
        
        public boolean isAuthorizedGen2(final int workerId, final CertificateMatchingRule ac) {
            final Set<CertificateMatchingRule> acs = authClientsGen2.get(workerId);

            if (acs != null) {
                return acs.contains(ac);
            }

            return false;
        }
        
        public byte[] getSignerCert(final int workerId) {
            return signerCerts.get(workerId);
        }
        
        public List<byte[]> getSignerCertChain(final int workerId) {
            return signerCertChains.get(workerId);
        }
        
        @Override
        protected void setGlobalProperty(String scope, String key, String value) {
            globalProperties.put(new GlobalProperty(scope, key), value);
        }

        @Override
        protected void removeGlobalProperty(String scope, String key) {
            globalProperties.remove(new GlobalProperty(scope, key));
        }

        @Override
        protected void setWorkerProperty(int workerId, String key, String value) {
            workerProperties.put(new WorkerProperty(Integer.toString(workerId), key), value);
        }

        @Override
        protected void removeWorkerProperty(int workerId, String key) {
            workerProperties.remove(new WorkerProperty(Integer.toString(workerId), key));
        }

        @Override
        protected void uploadSignerCertificate(int workerId, byte[] signerCert) {
            signerCerts.put(workerId, signerCert);
        }

        @Override
        protected void uploadSignerCertificateChain(int workerId,
                List<byte[]> signerCertChain) {
            signerCertChains.put(workerId, signerCertChain);
        }

        @Override
        protected void addAuthorizedClient(int workerId, AuthorizedClient ac) {
            Set<AuthorizedClient> acs = authClients.get(workerId);
            
            if (acs == null) {
                acs = new HashSet<>();
                authClients.put(workerId, acs);
            }
            
            acs.add(ac);
        }
        
        @Override
        protected void addAuthorizedClientGen2(int workerId, CertificateMatchingRule ac) {
            Set<CertificateMatchingRule> acs = authClientsGen2.get(workerId);
            
            if (acs == null) {
                acs = new HashSet<>();
                authClientsGen2.put(workerId, acs);
            }
            
            acs.add(ac);
        }

        @Override
        protected void removeAuthorizedClient(int workerId, AuthorizedClient ac) {
            final Set<AuthorizedClient> acs = authClients.get(workerId);
            
            if (acs != null) {
                acs.remove(ac);
            }
        }
        
        @Override
        protected void removeAuthorizedClientGen2(int workerId, CertificateMatchingRule ac) {
            final Set<CertificateMatchingRule> acs = authClientsGen2.get(workerId);
            
            if (acs != null) {
                acs.remove(ac);
            }
        }

        @Override
        protected int genFreeWorkerId() throws PropertiesApplierException {
            return FIRST_GENERATED_ID;
        }

        @Override
        protected int getWorkerId(String workerName)
                throws PropertiesApplierException {
            for (final WorkerProperty prop : workerProperties.keySet()) {
                if (PropertiesConstants.NAME.equals(prop.getKey())) {
                    final String value = workerProperties.get(prop);
                    
                    if (workerName.equals(value)) {
                        return Integer.valueOf(prop.getWorkerIdOrName());
                    }
                }
            }
            
            throw new PropertiesApplierException("No such worker: " + workerName);
        }

        @Override
        protected void checkWorkerNamesAlreadyExists(List<String> workerNames, List<String> workerIds) throws PropertiesApplierException {
            boolean workerWithNameAlreadyExists = false;
            StringBuffer errorMessage = new StringBuffer();
            final List<String> alreadyExistingWorkerNames = new ArrayList<String>();
            errorMessage.append("Worker(s) with name already exists:");

            List existingWorkerNamesInDB = mockedWokersInDB.values().stream().collect(Collectors.toList());
            for (int i = 0; i < workerNames.size(); i++) {
                final String workerName = workerNames.get(i);
                final String workerId = workerIds.get(i);
                if (existingWorkerNamesInDB.contains(workerName)) {
                    final String workerIdInDB = getWorkerIdByName(workerName);
                    if (!workerIdInDB.equals(workerId)) {
                        alreadyExistingWorkerNames.add(workerName);
                        workerWithNameAlreadyExists = true;
                    }
                }
            }

            // sort already found worker names to keep error message deterministic
            Collections.sort(alreadyExistingWorkerNames);

            alreadyExistingWorkerNames.forEach((name) -> {
                errorMessage.append(" ").append(name);
            });
            if (workerWithNameAlreadyExists) {
                throw new PropertiesApplierException(errorMessage.toString());
            }
        }
    
        
        private String getWorkerIdByName(String workerName) {
            String workerId = null;
            for (Map.Entry<String, String> entry : mockedWokersInDB.entrySet()) {
                if (workerName.equals(entry.getValue())) {
                    workerId = entry.getKey();
                }
            }
            return workerId;
        }
        
    }
    
}
