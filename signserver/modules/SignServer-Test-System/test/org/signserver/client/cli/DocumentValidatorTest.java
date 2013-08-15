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
package org.signserver.client.cli;

import java.io.*;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.junit.After;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.client.cli.defaultimpl.ValidateDocumentCommand;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.SignServerUtil;
import org.signserver.module.xmlvalidator.XMLValidatorTestData;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestingSecurityManager;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;

/**
 * Tests for the validatedocument command of Client CLI.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DocumentValidatorTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DocumentValidatorTest.class);

    /** WORKERID used in this test case as defined in 
     * junittest-part-config.properties for XMLSigner. */
    private static final int WORKERID = 5677;

    private static final String VALIDATION_WORKER = "TestValidationWorker";

    private static String signserverhome;
	
    @Before
    protected void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        TestingSecurityManager.install();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull("Please set SIGNSERVER_HOME environment variable", signserverhome);
    }

    @After
    protected void tearDown() throws Exception {
        TestingSecurityManager.remove();
    }

    private String getTruststorePassword() {
        Properties config = new Properties();
        File confFile1 = new File("../../signserver_build.properties");
        File confFile2 = new File("../../conf/signserver_build.properties");
        try {
            if (confFile1.exists()) {
                config.load(new FileInputStream(confFile1));
            } else {
                config.load(new FileInputStream(confFile2));
            }
        } catch (FileNotFoundException ignored) {
            LOG.debug("No signserver_build.properties");
        } catch (IOException ex) {
            LOG.error("Not using signserver_build.properties: " + ex.getMessage());
        }
        return config.getProperty("java.trustpassword", "changeit");
    }
	
    public void test00SetupDatabase() throws Exception {

        // VALIDATION SERVICE
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER17.CLASSPATH", "org.signserver.validationservice.server.ValidationServiceWorker");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER17.SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.HardCodedCryptoToken");
        workerSession.setWorkerProperty(17, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(17, "NAME", VALIDATION_WORKER);
        workerSession.setWorkerProperty(17, "VAL1.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");
        workerSession.setWorkerProperty(17, "VAL1.ISSUER1.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\n" + XMLValidatorTestData.CERT_ISSUER + "\n-----END CERTIFICATE-----\n");
        workerSession.setWorkerProperty(17, "VAL1.ISSUER2.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\n" + XMLValidatorTestData.CERT_ISSUER4 + "\n-----END CERTIFICATE-----\n");
        workerSession.setWorkerProperty(17, "VAL1.TESTPROP", "TEST");
        workerSession.setWorkerProperty(17, "VAL1.REVOKED", "");
        workerSession.reloadConfiguration(17);

        // XMLVALIDATOR
        setProperties(new File(signserverhome, "modules/SignServer-Module-XMLValidator/src/conf/junittest-part-config.properties"));
        workerSession.setWorkerProperty(WORKERID, "VALIDATIONSERVICEWORKER", VALIDATION_WORKER);
        workerSession.reloadConfiguration(WORKERID);
    }

    public void test01missingArguments() throws Exception {
        try {
            execute("validatedocument");
            fail("Should have thrown exception about missing arguments");
        } catch (IllegalCommandArgumentsException expected) {}
    }
    
    
    private void testValidateDocumentFromParameter(final String protocol) throws Exception {
        try {
            String res =
                    new String(protocol == null ?
                            execute("validatedocument",
                                    "-workername", "TestXMLValidator",
                                    "-data", XMLValidatorTestData.TESTXML1,
                                    "-truststore", new File(new File(signserverhome), "p12/truststore.jks").getAbsolutePath(),
                                    "-truststorepwd", getTruststorePassword()) :
                            execute("validatedocument",
                                    "-workername", "TestXMLValidator",
                                    "-data", XMLValidatorTestData.TESTXML1,
                                    "-truststore", new File(new File(signserverhome), "p12/truststore.jks").getAbsolutePath(),
                                    "-truststorepwd", getTruststorePassword(),
                                    "-protocol", protocol));
                    
                        
            
            assertTrue("contains Valid: true: "
                    + res, res.contains("Valid: true"));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    private void testValidateDocumentFromFile(final String protocol) throws Exception {
        try {
            final File doc = File.createTempFile("test2.xml", null);
            FileOutputStream out = null;
            try {
                out = new FileOutputStream(doc);
                out.write(XMLValidatorTestData.TESTXML1.getBytes());
                out.close();
            } finally {
                if (out != null) {
                    out.close();
                }
            }

            String res =
                    new String(protocol == null ?
                            execute("validatedocument", "-workername",
                                    "TestXMLValidator", "-infile", doc.getAbsolutePath(),
                                    "-truststore", new File(new File(signserverhome), "p12/truststore.jks").getAbsolutePath(),
                                    "-truststorepwd", getTruststorePassword()) :
                            execute("validatedocument", "-workername",
                                    "TestXMLValidator", "-infile", doc.getAbsolutePath(),
                                    "-truststore", new File(new File(signserverhome), "p12/truststore.jks").getAbsolutePath(),
                                    "-truststorepwd", getTruststorePassword(),
                                    "-protocol", protocol));
            assertTrue("contains Valid: true: "
                    + res, res.contains("Valid: true"));
        } catch (IllegalArgumentException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }
    
    /**
     * Tests the sample use case a from the documentation.
     * <pre>
     * a) validatedocument -workername XMLSigner -data "&lt;root/&gt;" -truststore $SIGNSERVER_HOME/p12/truststore.jks -truststorepwd foo123
     * </pre>
     * @throws Exception
     */
    public void test02ValidateDocumentFromParameterDefaultProtocol() throws Exception {
        testValidateDocumentFromParameter(null);
    }
    
    /**
     * Test with explicitly setting -protocol WEBSERVICES (the default).
     * 
     * @throws Exception
     */
    public void test03ValidateDocumentFromParameterWebservices() throws Exception {
        testValidateDocumentFromParameter("WEBSERVICES");
    }
    
    /**
     * Test with -protocol HTTP.
     * 
     * @throws Exception
     */
    public void test04ValidateDocumentFromParameterHTTP() throws Exception {
        testValidateDocumentFromParameter("HTTP");
    }

    /**
     * Tests the sample use case b from the documentation.
     * <pre>
     * b) signdocument -workername XMLSigner -infile /tmp/document.xml
     * </pre>
     * @throws Exception
     */
    public void test05ValidateDocumentFromFileDefaultProtocol() throws Exception {
        testValidateDocumentFromFile(null);
    }

    /**
     * Test with -protcol WEBSERVICES and -infile.
     * 
     * @throws Exception
     */
    public void test06ValidateDocumentFromFileWebservices() throws Exception {
       testValidateDocumentFromFile("WEBSERVICES"); 
    }
    
    /**
     * Test with -protocol HTTP and -infile.
     * 
     * @throws Exception
     */
    public void test07ValidateDocumentFromFileHTTP() throws Exception {
        testValidateDocumentFromFile("HTTP");
    }

    public void test99TearDownDatabase() throws Exception {
        removeWorker(WORKERID);
    }

    private byte[] execute(String... args) throws IllegalCommandArgumentsException, IOException, CommandFailureException {
        byte[] output;
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        try {
            final ValidateDocumentCommand cli = new ValidateDocumentCommand();
            cli.execute(args);
        } finally {
            output = out.toByteArray();
            System.setOut(System.out);
            System.out.write(output);
        }
        return output;
    }
}
