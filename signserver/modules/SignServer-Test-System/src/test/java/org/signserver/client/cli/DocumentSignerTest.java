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

import io.jsonwebtoken.SignatureAlgorithm;
import java.io.*;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import org.junit.runners.MethodSorters;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.client.cli.defaultimpl.SignDocumentCommand;
import org.signserver.common.SignServerUtil;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.cli.spi.CommandContext;
import org.signserver.cli.spi.CommandFactoryContext;
import org.signserver.client.cli.defaultimpl.ConsolePasswordReader;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.test.utils.builders.CryptoUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests for the signdocument command of Client CLI.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DocumentSignerTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DocumentSignerTest.class);

    /** WORKERID used in this test case as defined in
     * junittest-part-config.properties for XMLSigner. */
    private static final int WORKERID = 5676;

    /** WORKERID used in this test case as defined in
     * junittest-part-config.properties for PDFSigner. */
    private static final int WORKERID2 = 5675;

    /** Worker ID for the dummy metadata echo signer. */
    private static final int WORKERID3 = 6676;

    private static final int[] WORKERS = new int[] {WORKERID, WORKERID2, WORKERID3};

    private static File signserverhome;

    private final WorkerSession workerSession = getWorkerSession();

    // key pair used to generate test JWT token
    private static KeyPair keyPair;

    @Rule
    public TemporaryFolder inDir = new TemporaryFolder();

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        signserverhome = PathUtil.getAppHome();
        setupSSLKeystores();
        keyPair = CryptoUtils.generateRSA(2048);
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        LOG.info("test00SetupDatabase");
        // Worker 1
        addDummySigner(WORKERID, "TestXMLSigner", true);

        // Worker 2
        addPDFSigner(WORKERID2, "TestPDFSigner", true);

        // Worker 3 (dummy signer echoing request metadata)
        addSigner("org.signserver.server.signers.EchoRequestMetadataSigner", WORKERID3, "EchoRequestMetadataSigner", true);
    }

    @Test
    public void test01missingArguments() throws Exception {
        LOG.info("test01missingArguments");
        try {
            execute("signdocument");
            fail("Should have thrown exception about missing arguments");
        } catch (IllegalCommandArgumentsException expected) {} // NOPMD
    }

    /**
     * Test that setting both -host and -hosts is not allowed.
     */
    @Test
    public void test01hostAndHostsNotAllowed() throws Exception {
        LOG.info("test01hostAndHostsNotAllowed");
        try {
            execute("signdocument", "-host", "localhost", "-hosts",
                    "localhost,otherhost");
            fail("Should have thrown exception about illegal combination of arguments");
        } catch (IllegalCommandArgumentsException expected) {} // NOPMD
    }

    /**
     * Test that setting -hosts options is not allowed for -protocol CLIENTWS.
     */
    @Test
    public void test01hostsWithProtocolClientWSNotAllowed() throws Exception {
        LOG.info("test01hostsWithProtocolClientWSNotAllowed");
        try {
            execute("signdocument", "-hosts", "localhost,otherhost", "-protocol",
                    "CLIENTWS");
            fail("Should have thrown exception about illegal combination of arguments");
        } catch (IllegalCommandArgumentsException expected) {} // NOPMD
    }

    /**
     * Test that setting -hosts options is not allowed for -protocol WEBSERVICES.
     */
    @Test
    public void test01hostsWithProtocolWebservicesNotAllowed() throws Exception {
        LOG.info("test01hostsWithProtocolWebservicesNotAllowed");
        try {
            execute("signdocument", "-hosts", "localhost,otherhost", "-protocol",
                    "WEBSERVICES");
            fail("Should have thrown exception about illegal combination of arguments");
        } catch (IllegalCommandArgumentsException expected) {} // NOPMD
    }

    /**
     * Test that setting -timeout options is not allowed for -protocol
     * WEBSERVICES.
     */
    @Test
    public void test01timeoutsWithProtocolWebservicesNotAllowed() throws Exception {
        LOG.info("test01timeoutsWithProtocolWebservicesNotAllowed");
        try {
            execute("signdocument", "-timeout", "5000", "-protocol",
                    "WEBSERVICES");
            fail("Should have thrown exception about illegal combination of arguments");
        } catch (IllegalCommandArgumentsException expected) {
        } // NOPMD
    }

    /**
     * Test that setting -timeout options is not allowed for -protocol
     * CLIENTWS.
     */
    @Test
    public void test01timeoutsWithProtocolClientWSNotAllowed() throws Exception {
        LOG.info("test01timeoutsWithProtocolClientWSNotAllowed");
        try {
            execute("signdocument", "-timeout", "5000", "-protocol",
                    "CLIENTWS");
            fail("Should have thrown exception about illegal combination of arguments");
        } catch (IllegalCommandArgumentsException expected) {
        } // NOPMD
    }

    /**
     * Test that setting -loadbalancing options is not allowed for -protocol
     * CLIENTWS.
     */
    @Test
    public void test01loadbalancingWithProtocolClientWSNotAllowed() throws Exception {
        LOG.info("test01loadbalancingWithProtocolClientWSNotAllowed");
        try {
            execute("signdocument", "-loadbalancing", "ROUND_ROBIN", "-protocol",
                    "CLIENTWS");
            fail("Should have thrown exception about illegal combination of arguments");
        } catch (IllegalCommandArgumentsException expected) {
        } // NOPMD
    }

    /**
     * Test that setting -loadbalancing options is not allowed for -protocol
     * WEBSERVICES.
     */
    @Test
    public void test01loadbalancingWithProtocolWebservicesNotAllowed() throws Exception {
        LOG.info("test01loadbalancingWithProtocolWebservicesNotAllowed");
        try {
            execute("signdocument", "-loadbalancing", "ROUND_ROBIN", "-protocol",
                    "WEBSERVICES");
            fail("Should have thrown exception about illegal combination of arguments");
        } catch (IllegalCommandArgumentsException expected) {
        } // NOPMD
    }

    /**
     * Test that setting -hosts option with no argument is not allowed.
     */
    @Test
    public void test01hostsNoArg() throws Exception {
        LOG.info("test01hostsNoArg");
        try {
            execute("signdocument", "-hosts");
            fail("Should have thrown exception about no argument");
        } catch (IllegalCommandArgumentsException expected) {} // NOPMD
    }

    /**
     * Test that setting -hosts option with empty argument is not allowed.
     */
    @Test
    public void test01hostsEmpty() throws Exception {
        LOG.info("test01hostsEmpty");
        try {
            execute("signdocument", "-hosts", "");
            fail("Should have thrown exception about no argument");
        } catch (IllegalCommandArgumentsException expected) {} // NOPMD
    }

    /**
     * Test that setting -hosts option with empty argument is not allowed.
     */
    @Test
    public void test01hostEmpty() throws Exception {
        LOG.info("test01hostsEmpty");
        try {
            execute("signdocument", "-host", "");
            fail("Should have thrown exception about empty argument");
        } catch (IllegalCommandArgumentsException expected) {} // NOPMD
    }

    /**
     * Test that setting -loadbalancing option with empty argument is not allowed.
     */
    @Test
    public void test01loadbalancingEmptyNotAllowed() throws Exception {
        LOG.info("test01loadbalancingEmptyNotAllowed");
        try {
            execute("signdocument", "-workername", "TestXMLSigner", "-loadbalancing", " ", "-data", "<root/>");
            fail("Should have thrown exception about empty argument");
        } catch (IllegalCommandArgumentsException expected) {} // NOPMD
    }

    /**
     * Tests that it is not allowed to specify both -infile and -outdir.
     */
    @Test
    public void test25Both_infile_And_outdir_NotAllowed() throws Exception {
        LOG.info("test25Both_infile_And_outdir_NotAllowed");
        try {
            execute("signdocument", "-workername", "TestXMLSigner", "-outdir", "imaginary_out_dir_path", "-infile", "imaginary_in_file_path");
            fail("Should have thrown exception about invalid combination of arguments");
        } catch (IllegalCommandArgumentsException expected) {
        } // NOPMD
    }

    /**
     * Tests that it is not allowed to use a directory as -infile
     */
    @Test
    public void test14InfilePointingToDirectory() throws Exception {
        LOG.info("test14InfilePointingToDirectory");
        try {
            execute("signdocument", "-workername", "TestPDFSigner", "-infile", inDir.getRoot().getAbsolutePath());
            fail("Should have thrown CommandFailureException");
        } catch (CommandFailureException expected) {
        } // NOPMD
    }

    /**
     * Test that illegal -loadbalancing value is not allowed.
     */
    @Test
    public void test01IllegalLoadbalancingNotAllowed() throws Exception {
        LOG.info("test01IllegalLoadbalancingNotAllowed");
        try {
            execute("signdocument", "-workername", "TestXMLSigner", "-loadbalancing", "invalid", "-data", "<root/>");
            fail("Should have thrown exception about illegal timeout value");
        } catch (IllegalCommandArgumentsException expected) {
        } // NOPMD
    }

    /**
     * Test that illegal timeout (non-numeric) value is not allowed.
     */
    @Test
    public void test01IllegalTimeOutNotAllowed() throws Exception {
        LOG.info("test01IllegalTimeOutNotAllowed");
        try {
            execute("signdocument", "-workername", "TestXMLSigner", "-hosts", "invalidhost", "-timeout", "illegaltimeout", "-data", "<root/>");
            fail("Should have thrown exception about illegal timeout value");
        } catch (IllegalCommandArgumentsException expected) {
        } // NOPMD
    }

    /**
     * Test that negative timeout value is not allowed.
     */
    @Test
    public void test01NegativeTimeOutNotAllowed() throws Exception {
        LOG.info("test01IllegalTimeOutNotAllowed");
        String negativeTimeOut = "-1000";
        try {
            execute("signdocument", "-workername", "TestXMLSigner", "-hosts", "invalidhost", "-timeout", negativeTimeOut, "-data", "<root/>");
            fail("Should have thrown exception about negative timeout value");
        } catch (IllegalCommandArgumentsException expected) {
        } // NOPMD
    }

    /**
     * Tests the sample use case a from the documentation.
     * <pre>
     * a) signdocument -workername XMLSigner -data "&lt;root/&gt;"
     * </pre>
     */
    @Test
    public void test02signDocumentFromParameter() throws Exception {
        LOG.info("test02signDocumentFromParameter");
        try {
            String res =
                    new String(execute("signdocument", "-workername", "TestXMLSigner", "-data", "<root/>"));
            assertTrue("contains signature tag: "
                    + res, res.contains("<root><Signature"));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Tests the sample use case b from the documentation.
     * <pre>
     * b) signdocument -workername XMLSigner -infile /tmp/document.xml
     * </pre>
     */
    @Test
    public void test02signDocumentFromFile() throws Exception {
        LOG.info("test02signDocumentFromFile");
        File doc = null;
        try {
            doc = File.createTempFile("test.xml", null);
            try (FileOutputStream out = new FileOutputStream(doc)) {
                out.write("<tag/>".getBytes());
            }

            String res =
                    new String(execute("signdocument", "-workername",
                    "TestXMLSigner", "-infile", doc.getAbsolutePath()));
            assertTrue("contains signature tag: "
                    + res, res.contains("<tag><Signature"));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        } finally {
            FileUtils.deleteQuietly(doc);
        }
    }

    /**
     * Test signing a file with multiple hosts set with -hosts with the first
     * host failing.
     */
    @Test
    public void test02signDocumentFromFileWithFallbackHost() throws Exception {
        LOG.info("test02signDocumentFromFileWithFallbackHost");
        File doc = null;
        try {
            doc = File.createTempFile("test.xml", null);
            try (FileOutputStream out = new FileOutputStream(doc)) {
                out.write("<tag/>".getBytes());
            }

            String res =
                    new String(execute("signdocument", "-workername",
                    "TestXMLSigner", "-infile", doc.getAbsolutePath(),
                    "-hosts", "nonexistinghost,localhost"));
            assertTrue("contains signature tag: "
                    + res, res.contains("<tag><Signature"));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        } finally {
            FileUtils.deleteQuietly(doc);
        }
    }

    /**
     * Test signing a file with multiple hosts set with -hosts with the first
     * host succeeding.
     */
    @Test
    public void test02signDocumentFromFileFallingHostFirstSuccess() throws Exception {
        LOG.info("test02signDocumentFromFileWithFallbackHostFirstSuccess");
        File doc = null;
        try {
            doc = File.createTempFile("test.xml", null);
            try (FileOutputStream out = new FileOutputStream(doc)) {
                out.write("<tag/>".getBytes());
            }

            String res =
                    new String(execute("signdocument", "-workername",
                    "TestXMLSigner", "-infile", doc.getAbsolutePath(),
                    "-hosts", "localhost, nonexisting"));
            assertTrue("contains signature tag: "
                    + res, res.contains("<tag><Signature"));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        } finally {
            FileUtils.deleteQuietly(doc);
        }
    }

    /**
     * Tests signing from a file and output the results to a file.
     * <pre>
     * signdocument -workername XMLSigner
     *     -infile /tmp/document.xml
     *     -outfile /tmp/document-signed.xml
     * </pre>
     */
    @Test
    public void test02signDocumentFromFileToFile() throws Exception {
        LOG.info("test02signDocumentFromFileToFile");
        File inFile = null;
        File outFile = null;
        try {
            inFile = File.createTempFile("test.xml", null);
            FileUtils.writeStringToFile(inFile, "<tag/>");
            outFile = new File(inFile.getParentFile(), inFile.getName() + "-signed");

            String res =
                    new String(execute("signdocument",
                            "-workername", "TestXMLSigner",
                            "-infile", inFile.getAbsolutePath(),
                            "-outfile", outFile.getAbsolutePath()));
            assertFalse("not containing signature tag: "
                    + res, res.contains("<tag><Signature"));

            String file1Content = FileUtils.readFileToString(outFile);

            assertTrue("contains signature tag: "
                    + file1Content, file1Content.contains("<tag><Signature"));

        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        } finally {
            FileUtils.deleteQuietly(inFile);
            FileUtils.deleteQuietly(outFile);
        }
    }

    /**
     * Test for the "-pdfpassword" argument.
     * signdocument -workername TestPDFSigner -infile $SIGNSERVER_HOME/res/test/pdf/sample-open123.pdf
     */
    @Test
    public void test03signPDFwithPasswordOverHTTP() throws Exception {
        LOG.info("test03signPDFwithPasswordOverHTTP");
        try {

            byte[] res = execute("signdocument", "-workername",
                    "TestPDFSigner", "-infile", signserverhome + "/res/test/pdf/sample-open123.pdf",
                    "-pdfpassword", "open123");
            assertNotNull("No result", res);
            assertNotSame("Empty result", 0, res.length);
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Test for the "-pdfpassword" argument.
     * signdocument -workername TestPDFSigner -infile $SIGNSERVER_HOME/res/test/pdf/sample-open123.pdf -protocol WEBSERVICES
     */
    @Test
    public void test04signPDFwithPasswordOverWebservices() throws Exception {
        LOG.info("test04signPDFwithPasswordOverWebservices");
        try {

            byte[] res = execute("signdocument", "-workername",
                    "TestPDFSigner", "-infile", signserverhome + "/res/test/pdf/sample-open123.pdf",
                    "-pdfpassword", "open123", "-protocol", "WEBSERVICES",
                    "-truststore", signserverhome + "/p12/truststore.jks", "-truststorepwd", "changeit",
                    "-host", getHTTPHost(), "-port", String.valueOf(getPublicHTTPSPort()));
            assertNotNull("No result", res);
            assertNotSame("Empty result", 0, res.length);
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Test for the "-pdfpassword" argument.
     * signdocument -workername TestPDFSigner -infile $SIGNSERVER_HOME/res/test/pdf/sample-open123.pdf -protocol CLIENTWS
     */
    @Test
    public void test04signPDFwithPasswordOverClientWS() throws Exception {
        LOG.info("test04signPDFwithPasswordOverClientWS");
        try {

            byte[] res = execute("signdocument", "-workername",
                    "TestPDFSigner", "-infile", signserverhome + "/res/test/pdf/sample-open123.pdf",
                    "-pdfpassword", "open123", "-protocol", "CLIENTWS",
                    "-truststore", signserverhome + "/p12/truststore.jks", "-truststorepwd", "changeit",
                    "-host", getHTTPHost(), "-port", String.valueOf(getPublicHTTPSPort()));
            assertNotNull("No result", res);
            assertNotSame("Empty result", 0, res.length);
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Test signing over webservices with the -servlet argument set as SignServerWSService/SignServerWS
     */
    @Test
    public void test05signPDFOverWebservicesServletArg() throws Exception {
        LOG.info("test05signPDFOverWebservicesServletArg");
        try {
            final String res = new String(execute("signdocument", "-workername", "TestXMLSigner",
            		"-data", "<root/>", "-protocol", "WEBSERVICES",
            		"-servlet", "/signserver/SignServerWSService/SignServerWS?wsdl",
            		"-truststore", signserverhome + "/p12/truststore.jks", "-truststorepwd", "changeit",
                        "-host", getHTTPHost(), "-port", String.valueOf(getPublicHTTPSPort())));
            assertTrue("contains signature tag: "
                    + res, res.contains("<root><Signature"));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Test signing over webservices with the -servlet argument set as ClientWSService/ClientWS
     */
    @Test
    public void test05signPDFOverClientWSServletArg() throws Exception {
        LOG.info("test05signPDFOverClientWSServletArg");
        try {
            final String res = new String(execute("signdocument", "-workername", "TestXMLSigner",
            		"-data", "<root/>", "-protocol", "CLIENTWS",
            		"-servlet", "/signserver/ClientWSService/ClientWS?wsdl",
            		"-truststore", signserverhome + "/p12/truststore.jks", "-truststorepwd", "changeit",
                        "-host", getHTTPHost(), "-port", String.valueOf(getPublicHTTPSPort())));
            assertTrue("contains signature tag: "
                    + res, res.contains("<root><Signature"));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Test signing over webservices with the -servlet argument set as signserverws/signserverws
     */
    @Test
    public void test06signPDFOverWebservicesServletArg2() throws Exception {
        LOG.info("test06signPDFOverWebservicesServletArg2");
        try {
            final String res = new String(execute("signdocument", "-workername", "TestXMLSigner",
                        "-data", "<root/>", "-protocol", "WEBSERVICES",
                        "-servlet", "/signserver/SignServerWSService/SignServerWS?wsdl",
                        "-truststore", signserverhome + "/p12/truststore.jks", "-truststorepwd", "changeit",
                        "-host", getHTTPHost(), "-port", String.valueOf(getPublicHTTPSPort())));
            assertTrue("contains signature tag: "
                    + res, res.contains("<root><Signature"));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Test signing over webservices with the -servlet argument set as an invalid WS servlet URL
     */
    @Test
    public void test07signPDFOverWebservicesServletArgInvalid() throws Exception {
        LOG.info("test07signPDFOverWebservicesServletArgInvalid");
        try {
            final String res = new String(execute("signdocument", "-workername", "TestXMLSigner",
                        "-data", "<root/>", "-protocol", "WEBSERVICES",
                        "-servlet", "/signserver/nonexistant/wsurl",
                        "-truststore", signserverhome + "/p12/truststore.jks", "-truststorepwd", "changeit",
                        "-host", getHTTPHost(), "-port", String.valueOf(getPublicHTTPSPort())));
            fail("Should not accept invalid WS -servlet argument");
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        } catch (Exception ex) {
            // this is expected for the invalid URL
        }
    }

    /**
     * Test signing over webservices with the -servlet argument set as an invalid WS servlet URL
     */
    @Test
    public void test07signPDFOverClientWSServletArgInvalid() throws Exception {
        LOG.info("test07signPDFOverClientWSServletArgInvalid");
        try {
            final String res = new String(execute("signdocument", "-workername", "TestXMLSigner",
                        "-data", "<root/>", "-protocol", "CLIENTWS",
                        "-servlet", "/signserver/nonexistant/wsurl",
                        "-truststore", signserverhome + "/p12/truststore.jks", "-truststorepwd", "changeit",
                        "-host", getHTTPHost(), "-port", String.valueOf(getPublicHTTPSPort())));
            fail("Should not accept invalid WS -servlet argument");
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        } catch (Exception ex) {
            // this is expected for the invalid URL
        }
    }

    /**
     * Test signing a document supplying an additional metadata parameter.
     */
    @Test
    public void test08signDocumentWithMetadata() throws Exception {
        LOG.info("test08signDocumentWithMetadata");
        try {
            String res =
                    new String(execute("signdocument", "-workername", "EchoRequestMetadataSigner", "-data", "<root/>",
                            "-metadata", "foo=bar"));
            assertTrue("contains metadata parameter: "
                    + res, res.contains("foo=bar"));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Test signing a document supplying additional metadata parameters (more than one occurance).
     */
    @Test
    public void test09signDocumentWithMetadataMultipleParams() throws Exception {
        LOG.info("test09signDocumentWithMetadataMultipleParams");
        try {
            String res =
                    new String(execute("signdocument", "-workername", "EchoRequestMetadataSigner", "-data", "<root/>",
                            "-metadata", "foo=bar", "-metadata", "foo2=bar2"));
            assertTrue("contains metadata parameter: "
                    + res, res.contains("foo=bar"));
            assertTrue("contains metadata parameter: "
                    + res, res.contains("foo2=bar2"));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Test signing a document using webservices supplying additional metadata.
     */
    @Test
    public void test10signDocumentWithMetadataWebservices() throws Exception {
        LOG.info("test10signDocumentWithMetadataWebservices");
        try {
            String res =
                    new String(execute("signdocument", "-workername", "EchoRequestMetadataSigner", "-data", "<root/>",
                            "-protocol", "WEBSERVICES", "-metadata", "foo=bar", "-metadata", "foo2=bar2",
                            "-truststore", signserverhome + "/p12/truststore.jks", "-truststorepwd", "changeit",
                            "-host", getHTTPHost(), "-port", String.valueOf(getPublicHTTPSPort())));
            assertTrue("contains metadata parameter: "
                    + res, res.contains("foo=bar"));
            assertTrue("contains metadata parameter: "
                    + res, res.contains("foo2=bar2"));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Test signing a document using client-authenticated webservices supplying additional metadata.
     */
    @Test
    public void test11signDocumentWithMetadataClientWS() throws Exception {
        LOG.info("test11signDocumentWithMetadataClientWS");
        try {
            String res =
                    new String(execute("signdocument", "-workername", "EchoRequestMetadataSigner", "-data", "<root/>",
                            "-protocol", "CLIENTWS", "-metadata", "foo=bar", "-metadata", "foo2=bar2",
                            "-truststore", signserverhome + "/p12/truststore.jks", "-truststorepwd", "changeit",
                            "-host", getHTTPHost(), "-port", String.valueOf(getPublicHTTPSPort())));
            assertTrue("contains metadata parameter: "
                    + res, res.contains("foo=bar"));
            assertTrue("contains metadata parameter: "
                    + res, res.contains("foo2=bar2"));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Test that passing a malformed metadata argument is rejected.
     */
    @Test
    public void test12signDocumentInvalidMetadata() throws Exception {
        LOG.info("test12signDocumentInvalidMetadata");
        try {
            execute("signdocument", "-workername", "EchoRequestMetadataSigner", "-data", "<root/>",
                    "-protocol", "HTTP", "-metadata", "bogus");
            fail("Should throw an IllegalCommandArgumentsException");
        } catch (IllegalCommandArgumentsException ex) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName() + ": " + e.getMessage());
        }
    }

    /**
     * Tests that when not specifying any truststore password on the command
     * line the code for prompting for the password is called once.
     */
    @Test
    public void test13promptForTruststorePassword() throws Exception {
        LOG.info("test13promptForTruststorePassword");
        // Override the password reading
        final ArrayList<Boolean> called = new ArrayList<>();
        SignDocumentCommand instance = new SignDocumentCommand() {
            @Override
            public ConsolePasswordReader createConsolePasswordReader() {
                return new ConsolePasswordReader() {
                    @Override
                    public char[] readPassword() {
                        called.add(true);
                        return "changeit".toCharArray();
                    }
                };
            }
        };

        // Sign anything and check that the readPassword was called once
        try {
            String res =
                    new String(execute(instance, "signdocument", "-workername", "TestXMLSigner", "-data", "<root/>",
                            "-truststore", signserverhome + "/p12/truststore.jks"));
            assertEquals("calls to readPassword", 1, called.size());
            assertTrue("contains signature tag: "
                    + res, res.contains("<root><Signature"));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Tests that when providing a username but not a password the code for
     * prompting for password is called once.
     */
    @Test
    public void test13promptForUserPassword() throws Exception {
        LOG.info("test13promptForUserPassword");
        // Override the password reading
        final ArrayList<Boolean> called = new ArrayList<>();
        SignDocumentCommand instance = new SignDocumentCommand() {
            @Override
            public ConsolePasswordReader createConsolePasswordReader() {
                return new ConsolePasswordReader() {
                    @Override
                    public char[] readPassword() {
                        called.add(true);
                        return "foo123".toCharArray();
                    }
                };
            }
        };

        // Sign anything and check that the readPassword was called once
        try {
            String res =
                    new String(execute(instance, "signdocument", "-workername", "TestXMLSigner", "-data", "<root/>",
                            "-username", "user1"));
            assertEquals("calls to readPassword", 1, called.size());
            assertTrue("contains signature tag: "
                    + res, res.contains("<root><Signature"));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Tests that when not specifying any keystore password on the command
     * line the code for prompting for the password is called once.
     */
    @Test
    public void test13promptForKeystorePassword() throws Exception {
        LOG.info("test13promptForKeystorePassword");
        // Override the password reading
        final ArrayList<Boolean> called = new ArrayList<>();
        SignDocumentCommand instance = new SignDocumentCommand() {
            @Override
            public ConsolePasswordReader createConsolePasswordReader() {
                return new ConsolePasswordReader() {
                    @Override
                    public char[] readPassword() {
                        called.add(true);
                        return "changeit".toCharArray();
                    }
                };
            }
        };

        // The test might not have been setup to work with client cert auth
        // so we will not be checking that signing works, just that the prompt
        // gets called.
        // We use the truststore, any keystore should do it.
        try {
            execute(instance, "signdocument", "-workername", "TestXMLSigner", "-data", "<root/>",
                            "-keystore", signserverhome + "/p12/truststore.jks");
        } catch (CommandFailureException ignored) {} // NOPMD
        assertEquals("calls to readPassword", 1, called.size());
    }

    /**
     * Tests that when not specifying any keystore password on the command
     * line the code for prompting for the password is called and if the wrong
     * password is typed the question is asked again.
     */
    @Test
    public void test13promptForKeystorePasswordAgain() throws Exception {
        LOG.info("test13promptForKeystorePasswordAgain");
        // Override the password reading
        final ArrayList<Boolean> calls = new ArrayList<>();
        final String[] passwords = new String[] { "incorrect1", "changeit" };
        SignDocumentCommand instance = new SignDocumentCommand() {
            @Override
            public ConsolePasswordReader createConsolePasswordReader() {
                return new ConsolePasswordReader() {
                    @Override
                    public char[] readPassword() {
                        final String password = passwords[calls.size()];
                        calls.add(true);
                        return password.toCharArray();
                    }
                };
            }
        };

        // The test might not have been setup to work with client cert auth
        // so we will not be checking that signing works, just that the prompt
        // gets called.
        // We use the truststore, any keystore should do it.
        try {
            execute(instance, "signdocument", "-workername", "TestXMLSigner", "-data", "<root/>",
                            "-keystore", signserverhome + "/p12/truststore.jks");
        } catch (CommandFailureException ignored) {} // NOPMD

        assertEquals("calls to readPassword", 2, calls.size());
    }

    /**
     * Tests that when not specifying any keystore password on the command
     * line the code for prompting for the password is called and if the wrong
     * password is typed the question is asked again.
     */
    @Test
    public void test13promptForKeystorePassword3Times() throws Exception {
        LOG.info("test13promptForKeystorePasswordAgain");
        // Override the password reading
        final ArrayList<Boolean> calls = new ArrayList<>();
        final String[] passwords = new String[] { "incorrect1", "incorrect2", "incorrect3", "incorrect4", "incorrect5" };
        SignDocumentCommand instance = new SignDocumentCommand() {
            @Override
            public ConsolePasswordReader createConsolePasswordReader() {
                return new ConsolePasswordReader() {
                    @Override
                    public char[] readPassword() {
                        final String password = passwords[calls.size()];
                        calls.add(true);
                        return password.toCharArray();
                    }
                };
            }
        };

        // The test might not have been setup to work with client cert auth
        // so we will not be checking that signing works, just that the prompt
        // gets called.
        // We use the truststore, any keystore should do it.
        try {
            execute(instance, "signdocument", "-workername", "TestXMLSigner", "-data", "<root/>",
                            "-keystore", signserverhome + "/p12/truststore.jks");
        } catch (IllegalCommandArgumentsException expected) {
            assertTrue("message: " + expected, expected.toString().contains("password was incorrect"));
            assertEquals("calls to readPassword", 3, calls.size());
        }
    }

    /**
     * Tests that when not specifying any of user and truststore password they
     * are both prompted for.
     */
    @Test
    public void test13promptForUserAndTruststore() throws Exception {
        LOG.info("test13promptForUserAndTruststore");
        // Override the password reading
        final ArrayList<Boolean> called = new ArrayList<>();
        SignDocumentCommand instance = new SignDocumentCommand() {
            @Override
            public ConsolePasswordReader createConsolePasswordReader() {
                return new ConsolePasswordReader() {
                    @Override
                    public char[] readPassword() {
                        called.add(true);
                        return "changeit".toCharArray();
                    }
                };
            }
        };

        // Sign anything and check that the readPassword was called twice
        try {
            String res =
                    new String(execute(instance, "signdocument", "-workername", "TestXMLSigner", "-data", "<root/>",
                            "-username", "user1",
                            "-truststore", signserverhome + "/p12/truststore.jks"));
            assertTrue("contains signature tag: "
                    + res, res.contains("<root><Signature"));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
        assertEquals("calls to readPassword", 2, called.size());
    }

    @Test
    public void test20handleError() throws Exception {
        LOG.info("test20handleError");
        File doc = null;
        try {
            doc = File.createTempFile("test.xml", null);
            try (FileOutputStream out = new FileOutputStream(doc)) {
                out.write("<tag/>".getBytes());
            }

            execute("signdocument", "-workername",
                    "TestXMLSignerNotExisting_", "-infile", doc.getAbsolutePath());
            fail("Should have thrown exception because of the missing worker");
        } catch (CommandFailureException expected) { // NOPMD

        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        } finally {
            FileUtils.deleteQuietly(doc);
        }
    }

    /**
     * Test that using -clientside with -data is not allowed.
     */
    @Test
    public void test21clientSideWithData() throws Exception {
        LOG.info("test21clientSideWithData");
        try {
            execute("signdocument", "-clientside", "-data", "foo",
                    "-workername", "MSAuthCodeCMSSigner", "-outfile", "signed.exe");
            fail("Should have thrown exception about missing arguments");
        } catch (IllegalCommandArgumentsException expected) {} // NOPMD
    }

    /**
     * Test that using -clientside without -digestalgorithm is not allowed.
     */
    @Test
    public void test22clientSideNoDigestalgo() throws Exception {
        LOG.info("test21clientSideWithData");
        try {
            execute("signdocument", "-clientside", "-infile", "foo.exe",
                    "-workername", "MSAuthCodeCMSSigner", "-outfile", "signed.exe");
            fail("Should have thrown exception about missing arguments");
        } catch (IllegalCommandArgumentsException expected) {} // NOPMD
    }

    /**
     * Tests that output file is removed but input file is not touched when command is specified with 'infile' flag and fails.
     */
    @Test
    public void test23cleanUpWhenFailure() throws Exception {
        LOG.info("test23cleanUpWhenFailure");
        File inFile = null;
        File outFile = null;
        File renamedFile = null;
        try {
            inFile = File.createTempFile("test.xml", null);
            LOG.info("inFile " + inFile);
            FileUtils.writeStringToFile(inFile, "Invalid xml file");
            outFile = new File(inFile.getParentFile(), inFile.getName() + "-signed");

            execute("signdocument",
                    "-workername", "TestXMLSigner",
                    "-infile", inFile.getAbsolutePath(),
                    "-outfile", outFile.getAbsolutePath());
            fail("This should have failed");

        } catch (CommandFailureException ex) {
            assertTrue("Output file exists: ", outFile != null && !outFile.exists());
            // input file should be present
            assertTrue("Input file not exists: ", inFile != null && inFile.exists());
        } finally {
            FileUtils.deleteQuietly(inFile);
            FileUtils.deleteQuietly(outFile);
            FileUtils.deleteQuietly(renamedFile);
        }
    }

    /**
     * Test that command failure occurs within 15 seconds if connection is not established with specified host
     * within time specified by timeout flag (10 seconds).
     */
    @Test
    public void test24TimeOut_10Seconds() throws Exception {
        LOG.info("test24TimeOut_10Seconds");
        long startTime = 0, endTime, processingTime = 0;
        String timeoutString = "10000"; //milliseconds
        long timeout = Long.parseLong(timeoutString);
        long timediffBetweenProcessingAndTimeout;
        long assumedTimeDiffBetweenProcessingAndTimeout = 5000; // Let's assume that there would not be more than 5 seconds of time difference between timeout and processing time
        try {
            startTime = System.currentTimeMillis();
            execute("signdocument", "-workername", "TestXMLSigner", "-hosts", "primekey.com", "-timeout", timeoutString, "-data", "<root/>");
            fail("Should have thrown SocketTimeoutException");
        } catch (CommandFailureException expected) {
            endTime = System.currentTimeMillis();
            processingTime = endTime - startTime;
            timediffBetweenProcessingAndTimeout = processingTime - timeout;
            assertTrue("processing time should be less than timeout limit, diff (ms): " + timediffBetweenProcessingAndTimeout, timediffBetweenProcessingAndTimeout < assumedTimeDiffBetweenProcessingAndTimeout);
        } // NOPMD
    }

    /**
     * Test that command failure occurs within 25 seconds if connection is not established with specified host
     * within time specified by timeout flag (20 seconds).
     */
    @Test
    public void test24TimeOut_20Seconds() throws Exception {
        LOG.info("test24TimeOut_20Seconds");
        long startTime = 0, endTime, processingTime = 0;
        String timeoutString = "20000"; //milliseconds
        long timeout = Long.parseLong(timeoutString);
        long timediffBetweenProcessingAndTimeout;
        long assumedTimeDiffBetweenProcessingAndTimeout = 5000; // Let's assume that there would not be more than 5 seconds of time difference between timeout and processing time
        try {
            startTime = System.currentTimeMillis();
            execute("signdocument", "-workername", "TestXMLSigner", "-hosts", "primekey.com", "-timeout", timeoutString, "-data", "<root/>");
            fail("Should have thrown SocketTimeoutException");
        } catch (CommandFailureException expected) {
            endTime = System.currentTimeMillis();
            processingTime = endTime - startTime;
            timediffBetweenProcessingAndTimeout = processingTime - timeout;
            assertTrue("processing time should be less than timeout limit, diff (ms): " + timediffBetweenProcessingAndTimeout, timediffBetweenProcessingAndTimeout < assumedTimeDiffBetweenProcessingAndTimeout);
        } // NOPMD
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        LOG.info("test99TearDownDatabase");
        removeWorker(WORKERID2);
        for (int workerId : WORKERS) {
            removeWorker(workerId);
        }
    }

    private byte[] execute(String... args) throws IOException, IllegalCommandArgumentsException, CommandFailureException {
        return execute(new SignDocumentCommand(), args);
    }

    private byte[] execute(SignDocumentCommand instance, String... args) throws IOException, IllegalCommandArgumentsException, CommandFailureException {
        byte[] result;
        final PrintStream origOut = System.out;
        final PrintStream origErr = System.err;

        final ByteArrayOutputStream bStdOut = new ByteArrayOutputStream();
        final PrintStream stdOut = new PrintStream(bStdOut);
        System.setOut(stdOut);

        final ByteArrayOutputStream bErrOut = new ByteArrayOutputStream();
        final PrintStream errOut = new PrintStream(bErrOut);
        System.setErr(errOut);

        instance.init(new CommandContext("group1", "signdocument", new CommandFactoryContext(new Properties(), stdOut, errOut)));
        try {
            instance.execute(args);
        } finally {
            result = bStdOut.toByteArray();
            System.setOut(origOut);
            System.setErr(origErr);
            System.out.write(result);

            byte[] error = bErrOut.toByteArray();
            System.err.write(error);
        }
        return result;
    }

}
