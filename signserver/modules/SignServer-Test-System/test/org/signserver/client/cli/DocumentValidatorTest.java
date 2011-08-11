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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Properties;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.SignServerUtil;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.common.ServiceLocator;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.module.xmlvalidator.XMLValidatorTestData;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Tests for the validatedocument command of Client CLI.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class DocumentValidatorTest extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DocumentValidatorTest.class);

    /** WORKERID used in this test case as defined in 
     * junittest-part-config.properties for XMLSigner. */
    private static final int WORKERID = 5677;

    private static final String VALIDATION_WORKER = "TestValidationWorker";

    private static String signserverhome;
    private static int moduleVersion;

    private IWorkerSession.IRemote sSSession;
    private IGlobalConfigurationSession.IRemote gCSession;
	
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
        gCSession = ServiceLocator.getInstance().lookupRemote(
                        IGlobalConfigurationSession.IRemote.class);
        sSSession = ServiceLocator.getInstance().lookupRemote(
                IWorkerSession.IRemote.class);
        TestingSecurityManager.install();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull("Please set SIGNSERVER_HOME environment variable", signserverhome);
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        TestingSecurityManager.remove();
    }

    private String getTruststorePassword() {
        Properties config = new Properties();
        try {
            config.load(new FileInputStream(new File("../../signserver_build.properties")));
        } catch (FileNotFoundException ignored) {
            LOG.debug("No signserver_build.properties");
        } catch (IOException ex) {
            LOG.error("Not using signserver_build.properties: " + ex.getMessage());
        }
        return config.getProperty("java.trustpassword", "changeit");
    }
	
    public void test00SetupDatabase() throws Exception {

        MARFileParser marFileParser = new MARFileParser(signserverhome + "/dist-server/xmlvalidator.mar");
        moduleVersion = marFileParser.getVersionFromMARFile();

        // VALIDATION SERVICE
        gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER17.CLASSPATH", "org.signserver.validationservice.server.ValidationServiceWorker");
        gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER17.SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.HardCodedCryptoToken");
        sSSession.setWorkerProperty(17, "AUTHTYPE", "NOAUTH");
        sSSession.setWorkerProperty(17, "NAME", VALIDATION_WORKER);
        sSSession.setWorkerProperty(17, "VAL1.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");
        sSSession.setWorkerProperty(17, "VAL1.ISSUER1.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\n" + XMLValidatorTestData.CERT_ISSUER + "\n-----END CERTIFICATE-----\n");
        sSSession.setWorkerProperty(17, "VAL1.ISSUER2.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\n" + XMLValidatorTestData.CERT_ISSUER4 + "\n-----END CERTIFICATE-----\n");
        sSSession.setWorkerProperty(17, "VAL1.TESTPROP", "TEST");
        sSSession.setWorkerProperty(17, "VAL1.REVOKED", "");
        sSSession.reloadConfiguration(17);

        // XMLVALIDATOR
        TestUtils.assertSuccessfulExecution(new String[] { "module", "add", signserverhome + "/dist-server/xmlvalidator.mar", "junittest" });
        assertTrue(TestUtils.grepTempOut("Loading module XMLVALIDATOR"));
        assertTrue(TestUtils.grepTempOut("Module loaded successfully."));
        sSSession.setWorkerProperty(WORKERID, "VALIDATIONSERVICEWORKER", VALIDATION_WORKER);
        sSSession.reloadConfiguration(WORKERID);
    }

    public void test01missingArguments() throws Exception {
        try {
            execute("validatedocument");
            fail("Should have thrown exception about missing arguments");
        } catch (IllegalArgumentException expected) {}
    }

    /**
     * Tests the sample use case a from the documentation.
     * <pre>
     * a) signdocument -workername XMLSigner -data "&lt;root/&gt;"
     * </pre>
     * @throws Exception
     */
    public void test02validateDocumentFromParameter() throws Exception {
        try {
            String res =
                    new String(execute("validatedocument",
                    "-workername", "TestXMLValidator",
                    "-data", XMLValidatorTestData.TESTXML1,
                    "-truststore", new File(new File(signserverhome), "p12/truststore.jks").getAbsolutePath(),
                    "-truststorepwd", getTruststorePassword()));
            assertTrue("contains Valid: true: "
                    + res, res.contains("Valid: true"));
        } catch (IllegalArgumentException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Tests the sample use case b from the documentation.
     * <pre>
     * b) signdocument -workername XMLSigner -infile /tmp/document.xml
     * </pre>
     * @throws Exception
     */
    public void test02signDocumentFromFile() throws Exception {
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
                    new String(execute("validatedocument", "-workername",
                    "TestXMLValidator", "-infile", doc.getAbsolutePath(),
                    "-truststore", new File(new File(signserverhome), "p12/truststore.jks").getAbsolutePath(),
                    "-truststorepwd", getTruststorePassword()));
            assertTrue("contains Valid: true: "
                    + res, res.contains("Valid: true"));
        } catch (IllegalArgumentException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }


    public void test99TearDownDatabase() throws Exception {
        TestUtils.assertSuccessfulExecution(new String[] {
            "removeworker",
            String.valueOf(WORKERID)
        });

        TestUtils.assertSuccessfulExecution(new String[] {
            "module",
            "remove",
            "XMLVALIDATOR",
            String.valueOf(moduleVersion)
        });
        assertTrue("module remove",
                TestUtils.grepTempOut("Removal of module successful."));
        sSSession.reloadConfiguration(WORKERID);
    }

    private byte[] execute(String... args) throws IllegalArgumentException, IOException {
        byte[] output = null;
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        try {
            final DocumentValidatorCLI cli = new DocumentValidatorCLI(args);
            cli.run();
        } finally {
            output = out.toByteArray();
            System.setOut(System.out);
            System.out.write(output);
        }
        return output;
    }
}
