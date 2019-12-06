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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import org.junit.Test;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertBuilderException;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;

/**
 * System tests for the ClientCertAuthorizer, using gen2 auth rules.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ClientCertAuthorizerTest {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ClientCertAuthorizerTest.class);

    private final ModulesTestCase test = new ModulesTestCase();
    private final CLITestHelper cli = test.getAdminCLI();
    private final CLITestHelper client = test.getClientCLI();
    
    private final String SUBJECT_SERIALNUMBER = "723507815f93333";
    private final String SUBJECT_SERIALNUMBER_WITH_LEADING_ZERO = "0723507815f93333";
    private final String SUBJECT_SERIALNUMBER_UPPERCASE = "723507815F93333";
    private final String SUBJECT_RDN_CN = "Admin One";
    private final String SUBJECT_SERIALNUMBER_OTHER = "123456789ab";
    private final String ISSUER_DN = "CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE";
    private final String DESCRIPTION = "Test auth client";
    
    /**
     * Test authorization with a subject serial number rule.
     * 
     * @throws Exception 
     */
    @Test
    public void testSerialNumber() throws Exception {
        LOG.info("testSerialNumber");
        try {
            final int signerId = test.getSignerIdCMSSigner1();
            final String dss10Path = test.getSignServerHome().getAbsolutePath() +
                                           File.separator + "res" +
                                           File.separator + "test" +
                                           File.separator + "dss10";
            
            test.addCMSSigner1();
            test.getWorkerSession().setWorkerProperty(signerId, "AUTHTYPE",
                                                      "org.signserver.server.ClientCertAuthorizer");
            test.getWorkerSession().reloadConfiguration(signerId);
            
            // Add
            assertEquals("execute add", 0,
                    cli.execute("authorizedclients", "-worker", String.valueOf(signerId),
                    "-add", 
                    "-matchSubjectWithType", "CERTIFICATE_SERIALNO",
                    "-matchSubjectWithValue", SUBJECT_SERIALNUMBER,
                    "-matchIssuerWithValue", ISSUER_DN,
                    "-description", DESCRIPTION));
            test.getWorkerSession().reloadConfiguration(signerId);
            
            assertEquals("execute signdocument", 0,
                    client.execute("signdocument", "-workerid", String.valueOf(signerId),
                                   "-data", "foo", "-protocol", "CLIENTWS",
                                   "-host", "localhost",
                                   "-port", "8443",
                                   "-keystore",
                                   dss10Path + File.separator + "dss10_admin1.p12",
                                   "-keystorepwd", "foo123",
                                   "-truststore",
                                   dss10Path + File.separator + "dss10_truststore.jks",
                                   "-truststorepwd", "changeit"));
                                           
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
    }
    
    /**
     * Test authorization with a subject serial number rule specifying SN with
     * a leading zero.
     * 
     * @throws Exception 
     */
    @Test
    public void testSerialNumberWithLeadingZero() throws Exception {
        LOG.info("testSerialNumberWithLeadingZero");
        try {
            final int signerId = test.getSignerIdCMSSigner1();
            final String dss10Path = test.getSignServerHome().getAbsolutePath() +
                                           File.separator + "res" +
                                           File.separator + "test" +
                                           File.separator + "dss10";
            
            test.addCMSSigner1();
            test.getWorkerSession().setWorkerProperty(signerId, "AUTHTYPE",
                                                      "org.signserver.server.ClientCertAuthorizer");
            test.getWorkerSession().reloadConfiguration(signerId);
            
            // Add
            assertEquals("execute add", 0,
                    cli.execute("authorizedclients", "-worker", String.valueOf(signerId),
                    "-add", 
                    "-matchSubjectWithType", "CERTIFICATE_SERIALNO",
                    "-matchSubjectWithValue", SUBJECT_SERIALNUMBER_WITH_LEADING_ZERO,
                    "-matchIssuerWithValue", ISSUER_DN,
                    "-description", DESCRIPTION));
            test.getWorkerSession().reloadConfiguration(signerId);
            
            assertEquals("execute signdocument", 0,
                    client.execute("signdocument", "-workerid", String.valueOf(signerId),
                                   "-data", "foo", "-protocol", "CLIENTWS",
                                   "-host", "localhost",
                                   "-port", "8443",
                                   "-keystore",
                                   dss10Path + File.separator + "dss10_admin1.p12",
                                   "-keystorepwd", "foo123",
                                   "-truststore",
                                   dss10Path + File.separator + "dss10_truststore.jks",
                                   "-truststorepwd", "changeit"));
                                           
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
    }
    
    /**
     * Test authorization with a subject serial number rule. Specifying SN
     * with hex upper-case digits.
     * 
     * @throws Exception 
     */
    @Test
    public void testSerialNumberUppercase() throws Exception {
        LOG.info("testSerialNumberUppercase");
        try {
            final int signerId = test.getSignerIdCMSSigner1();
            final String dss10Path = test.getSignServerHome().getAbsolutePath() +
                                           File.separator + "res" +
                                           File.separator + "test" +
                                           File.separator + "dss10";
            
            test.addCMSSigner1();
            test.getWorkerSession().setWorkerProperty(signerId, "AUTHTYPE",
                                                      "org.signserver.server.ClientCertAuthorizer");
            test.getWorkerSession().reloadConfiguration(signerId);
            
            // Add
            assertEquals("execute add", 0,
                    cli.execute("authorizedclients", "-worker", String.valueOf(signerId),
                    "-add", 
                    "-matchSubjectWithType", "CERTIFICATE_SERIALNO",
                    "-matchSubjectWithValue", SUBJECT_SERIALNUMBER_UPPERCASE,
                    "-matchIssuerWithValue", ISSUER_DN,
                    "-description", DESCRIPTION));
            test.getWorkerSession().reloadConfiguration(signerId);
            
            assertEquals("execute signdocument", 0,
                    client.execute("signdocument", "-workerid", String.valueOf(signerId),
                                   "-data", "foo", "-protocol", "CLIENTWS",
                                   "-host", "localhost",
                                   "-port", "8443",
                                   "-keystore",
                                   dss10Path + File.separator + "dss10_admin1.p12",
                                   "-keystorepwd", "foo123",
                                   "-truststore",
                                   dss10Path + File.separator + "dss10_truststore.jks",
                                   "-truststorepwd", "changeit"));
                                           
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
    }
    
    /**
     * Test authorization with a subject serial number rule. With an additional
     * matching rule.
     * 
     * @throws Exception 
     */
    @Test
    public void testSerialNumberWithAdditionalRule() throws Exception {
        LOG.info("testSerialNumberWithAdditionalRule");
        try {
            final int signerId = test.getSignerIdCMSSigner1();
            final String dss10Path = test.getSignServerHome().getAbsolutePath() +
                                           File.separator + "res" +
                                           File.separator + "test" +
                                           File.separator + "dss10";
            
            test.addCMSSigner1();
            test.getWorkerSession().setWorkerProperty(signerId, "AUTHTYPE",
                                                      "org.signserver.server.ClientCertAuthorizer");
            test.getWorkerSession().reloadConfiguration(signerId);
            
            // Add
            assertEquals("execute add", 0,
                    cli.execute("authorizedclients", "-worker", String.valueOf(signerId),
                    "-add", 
                    "-matchSubjectWithType", "CERTIFICATE_SERIALNO",
                    "-matchSubjectWithValue", SUBJECT_SERIALNUMBER,
                    "-matchIssuerWithValue", ISSUER_DN,
                    "-description", DESCRIPTION));
            assertEquals("execute add", 0,
                    cli.execute("authorizedclients", "-worker", String.valueOf(signerId),
                    "-add", 
                    "-matchSubjectWithType", "CERTIFICATE_SERIALNO",
                    "-matchSubjectWithValue", SUBJECT_SERIALNUMBER_OTHER,
                    "-matchIssuerWithValue", ISSUER_DN,
                    "-description", DESCRIPTION));
            test.getWorkerSession().reloadConfiguration(signerId);
            
            assertEquals("execute signdocument", 0,
                    client.execute("signdocument", "-workerid", String.valueOf(signerId),
                                   "-data", "foo", "-protocol", "CLIENTWS",
                                   "-host", "localhost",
                                   "-port", "8443",
                                   "-keystore",
                                   dss10Path + File.separator + "dss10_admin1.p12",
                                   "-keystorepwd", "foo123",
                                   "-truststore",
                                   dss10Path + File.separator + "dss10_truststore.jks",
                                   "-truststorepwd", "changeit"));
                                           
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
    }
    
    /**
     * Test authorization with a subject serial number rule with a non-matching
     * SN.
     * 
     * @throws Exception 
     */
    @Test
    public void testSerialNumberNotMatching() throws Exception {
        LOG.info("testSerialNumberNotMatching");
        try {
            final int signerId = test.getSignerIdCMSSigner1();
            final String dss10Path = test.getSignServerHome().getAbsolutePath() +
                                           File.separator + "res" +
                                           File.separator + "test" +
                                           File.separator + "dss10";
            
            test.addCMSSigner1();
            test.getWorkerSession().setWorkerProperty(signerId, "AUTHTYPE",
                                                      "org.signserver.server.ClientCertAuthorizer");
            test.getWorkerSession().reloadConfiguration(signerId);
            
            // Add
            assertEquals("execute add", 0,
                    cli.execute("authorizedclients", "-worker", String.valueOf(signerId),
                    "-add", 
                    "-matchSubjectWithType", "CERTIFICATE_SERIALNO",
                    "-matchSubjectWithValue", SUBJECT_SERIALNUMBER_OTHER,
                    "-matchIssuerWithValue", ISSUER_DN,
                    "-description", DESCRIPTION));
            test.getWorkerSession().reloadConfiguration(signerId);
            
            assertNotEquals("execute signdocument", 0,
                    client.execute("signdocument", "-workerid", String.valueOf(signerId),
                                   "-data", "foo", "-protocol", "CLIENTWS",
                                   "-host", "localhost",
                                   "-port", "8443",
                                   "-keystore",
                                   dss10Path + File.separator + "dss10_admin1.p12",
                                   "-keystorepwd", "foo123",
                                   "-truststore",
                                   dss10Path + File.separator + "dss10_truststore.jks",
                                   "-truststorepwd", "changeit"));
                                           
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
    }
    
    /**
     * Test authorization with a subject RDN common name.
     * 
     * @throws Exception 
     */
    @Test
    public void testSubject_RDN_CN() throws Exception {
        LOG.info("testSubject_RDN_CN");
        try {
            final int signerId = test.getSignerIdCMSSigner1();
            final String dss10Path = test.getSignServerHome().getAbsolutePath() +
                                           File.separator + "res" +
                                           File.separator + "test" +
                                           File.separator + "dss10";
            
            test.addCMSSigner1();
            test.getWorkerSession().setWorkerProperty(signerId, "AUTHTYPE",
                                                      "org.signserver.server.ClientCertAuthorizer");
            test.getWorkerSession().reloadConfiguration(signerId);
            
            // Add
            assertEquals("execute add", 0,
                    cli.execute("authorizedclients", "-worker", String.valueOf(signerId),
                    "-add", 
                    "-matchSubjectWithType", "SUBJECT_RDN_CN",
                    "-matchSubjectWithValue", SUBJECT_RDN_CN,
                    "-matchIssuerWithValue", ISSUER_DN,
                    "-description", DESCRIPTION));
            test.getWorkerSession().reloadConfiguration(signerId);
            
            assertEquals("execute signdocument", 0,
                    client.execute("signdocument", "-workerid", String.valueOf(signerId),
                                   "-data", "foo", "-protocol", "CLIENTWS",
                                   "-host", "localhost",
                                   "-port", "8443",
                                   "-keystore",
                                   dss10Path + File.separator + "dss10_admin1.p12",
                                   "-keystorepwd", "foo123",
                                   "-truststore",
                                   dss10Path + File.separator + "dss10_truststore.jks",
                                   "-truststorepwd", "changeit"));
                                           
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
    }
    
    /**
     * Test authorization with RDN SERIALNUMBER.
     * 
     * @throws Exception 
     */
    @Test
    public void testWithSubjectDNSerialNumber() throws Exception {
        LOG.info("testWithSubjectDNSerialNumber");
        try {
            final int signerId = test.getSignerIdCMSSigner1();
            final String dss10Path = test.getSignServerHome().getAbsolutePath() +
                                               File.separator + "res" +
                                               File.separator + "test" +
                                               File.separator + "dss10";
            Security.addProvider(new BouncyCastleProvider());
            final KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            final String ksPath = dss10Path + File.separator + "DSSRootCA10.p12";

            ks.load(new FileInputStream(ksPath), "foo123".toCharArray());

            X509Certificate caCert =
                    (X509Certificate) ks.getCertificate("SignatureKeyAlias");
            PrivateKey issuerPrivKey = (PrivateKey)ks.getKey("SignatureKeyAlias", "foo123".toCharArray());

            final CertBuilder builder =
                    generateCertBuilderWithAdditionalDNComponent(caCert, issuerPrivKey,
                                                          BCStyle.SERIALNUMBER,
                                                          "123456789ab");
            final X509Certificate clientCert =
                    new JcaX509CertificateConverter().getCertificate(builder.build());
            final PrivateKey clientPrivKey = builder.getSubjectKeyPair().getPrivate();
            
            // store client cert in a keystore
            final File tmpFile = File.createTempFile("client", "p12");
            final KeyStore clientKs = KeyStore.getInstance("PKCS12", "BC");
            final Certificate[] chain = {clientCert, caCert};
            
            clientKs.load(null, "foo123".toCharArray());
            clientKs.setCertificateEntry("Admin Three", clientCert);
            clientKs.setKeyEntry("Admin Three", clientPrivKey, "foo123".toCharArray(), chain);
            clientKs.store(new FileOutputStream(tmpFile), "foo123".toCharArray());

            test.addCMSSigner1();
            test.getWorkerSession().setWorkerProperty(signerId, "AUTHTYPE",
                                                      "org.signserver.server.ClientCertAuthorizer");
            test.getWorkerSession().reloadConfiguration(signerId);

            // Add
            assertEquals("execute add", 0,
                    cli.execute("authorizedclients", "-worker", String.valueOf(signerId),
                    "-add", 
                    "-matchSubjectWithType", "SUBJECT_RDN_SERIALNO",
                    "-matchSubjectWithValue", "123456789ab",
                    "-matchIssuerWithValue", ISSUER_DN,
                    "-description", DESCRIPTION));
            test.getWorkerSession().reloadConfiguration(signerId);

            assertEquals("execute signdocument", 0,
                    client.execute("signdocument", "-workerid", String.valueOf(signerId),
                                   "-data", "foo", "-protocol", "CLIENTWS",
                                   "-host", "localhost",
                                   "-port", "8443",
                                   "-keystore",
                                   tmpFile.getAbsolutePath(),
                                   "-keystorepwd", "foo123",
                                   "-truststore",
                                   dss10Path + File.separator + "dss10_truststore.jks",
                                   "-truststorepwd", "changeit"));
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
        
    }
    
    /**
     * Test upgrade of authorization with a subject serial number rule. Specifying SN
     * with hex upper-case digits.
     * 
     * @throws Exception 
     */
    @Test
    public void testSerialNumberUppercase_upgrade() throws Exception {
        LOG.info("testSerialNumberUppercase_upgrade");
        try {
            final int signerId = test.getSignerIdCMSSigner1();
            final String dss10Path = test.getSignServerHome().getAbsolutePath() +
                                           File.separator + "res" +
                                           File.separator + "test" +
                                           File.separator + "dss10";
            
            test.addCMSSigner1();
            test.getWorkerSession().setWorkerProperty(signerId, "AUTHTYPE",
                                                      "org.signserver.server.ClientCertAuthorizer");
            test.getWorkerSession().reloadConfiguration(signerId);
            
            // Add using legacy command
            assertEquals("execute add", 0,
                    cli.execute("addauthorizedclient", String.valueOf(signerId),
                    SUBJECT_SERIALNUMBER_UPPERCASE, ISSUER_DN));
            test.getWorkerSession().reloadConfiguration(signerId);
            
            // Test signing
            assertEquals("execute signdocument", 0,
                    client.execute("signdocument", "-workerid", String.valueOf(signerId),
                                   "-data", "foo", "-protocol", "CLIENTWS",
                                   "-host", "localhost",
                                   "-port", "8443",
                                   "-keystore",
                                   dss10Path + File.separator + "dss10_admin1.p12",
                                   "-keystorepwd", "foo123",
                                   "-truststore",
                                   dss10Path + File.separator + "dss10_truststore.jks",
                                   "-truststorepwd", "changeit"));
                                           
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
    }
    
    /**
     * Test upgrade of authorization with a subject serial number rule with a non-matching
     * SN.
     * 
     * @throws Exception 
     */
    @Test
    public void testSerialNumberNotMatching_upgrade() throws Exception {
        LOG.info("testSerialNumberNotMatching_upgrade");
        try {
            final int signerId = test.getSignerIdCMSSigner1();
            final String dss10Path = test.getSignServerHome().getAbsolutePath() +
                                           File.separator + "res" +
                                           File.separator + "test" +
                                           File.separator + "dss10";
            
            test.addCMSSigner1();
            test.getWorkerSession().setWorkerProperty(signerId, "AUTHTYPE",
                                                      "org.signserver.server.ClientCertAuthorizer");
            test.getWorkerSession().reloadConfiguration(signerId);
            
            // Add legacy way
            assertEquals("execute add", 0,
                    cli.execute("addauthorizedclient", String.valueOf(signerId),
                    SUBJECT_SERIALNUMBER_OTHER, ISSUER_DN));
            test.getWorkerSession().reloadConfiguration(signerId);
            
            assertNotEquals("execute signdocument", 0,
                    client.execute("signdocument", "-workerid", String.valueOf(signerId),
                                   "-data", "foo", "-protocol", "CLIENTWS",
                                   "-host", "localhost",
                                   "-port", "8443",
                                   "-keystore",
                                   dss10Path + File.separator + "dss10_admin1.p12",
                                   "-keystorepwd", "foo123",
                                   "-truststore",
                                   dss10Path + File.separator + "dss10_truststore.jks",
                                   "-truststorepwd", "changeit"));
                                           
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
    }

    private static CertBuilder generateCertBuilderWithAdditionalDNComponent(
            final X509Certificate caCert,
            final PrivateKey caPrivKey,
            final ASN1ObjectIdentifier additionalDNComponent,
            final String additionalDNValue)
            throws CertBuilderException, CertificateException {
        final CertBuilder builder = new CertBuilder();
        
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.CN, "Admin Three");
        nameBuilder.addRDN(BCStyle.O, "SignServer Testing");
        nameBuilder.addRDN(BCStyle.C, "SE");
        nameBuilder.addRDN(additionalDNComponent, additionalDNValue);
        
        final X500Name subject = nameBuilder.build();
        
        builder.setIssuerPrivateKey(caPrivKey);
        builder.setIssuer(caCert.getIssuerDN().getName());
        builder.setSubject(subject);
        
        return builder;
    }
}
