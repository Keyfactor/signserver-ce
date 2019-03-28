/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server;

import java.io.File;
import org.apache.log4j.Logger;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import org.junit.Test;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;

/**
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
    private final String SUBJECT_RDN = "CN=Admin One,OU=Testing,O=SignServer,C=SE";
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
                    cli.execute("clients", "-worker", String.valueOf(signerId),
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
                    cli.execute("clients", "-worker", String.valueOf(signerId),
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
                    cli.execute("clients", "-worker", String.valueOf(signerId),
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
                    cli.execute("clients", "-worker", String.valueOf(signerId),
                    "-add", 
                    "-matchSubjectWithType", "CERTIFICATE_SERIALNO",
                    "-matchSubjectWithValue", SUBJECT_SERIALNUMBER,
                    "-matchIssuerWithValue", ISSUER_DN,
                    "-description", DESCRIPTION));
            assertEquals("execute add", 0,
                    cli.execute("clients", "-worker", String.valueOf(signerId),
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
                    cli.execute("clients", "-worker", String.valueOf(signerId),
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
     * Test authorization with a subject serial number rule.
     * 
     * @throws Exception 
     */
    @Test
    public void testSubject_RDN_CN() throws Exception {
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
                    cli.execute("clients", "-worker", String.valueOf(signerId),
                    "-add", 
                    "-matchSubjectWithType", "SUBJECT_RDN_CN",
                    "-matchSubjectWithValue", SUBJECT_RDN,
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
}
