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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.signserver.common.SignServerUtil;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.common.ServiceLocator;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Tests for the signdocument command of Client CLI.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class DocumentSignerTest extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DocumentSignerTest.class);

    /** WORKERID used in this test case as defined in 
     * junittest-part-config.properties for XMLSigner. */
    private static final int WORKERID = 5676;

    /** WORKERID used in this test case as defined in 
     * junittest-part-config.properties for PDFSigner. */
    private static final int WORKERID2 = 5675;

    private static IWorkerSession.IRemote workerSession;
    private static String signserverhome;
    private static int moduleVersion;
	
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
        workerSession = ServiceLocator.getInstance().lookupRemote(
                IWorkerSession.IRemote.class);
        TestingSecurityManager.install();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull("Please set SIGNSERVER_HOME environment variable", signserverhome);
        TestUtils.setupSSLTruststore();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        TestingSecurityManager.remove();
    }	
	
    public void test00SetupDatabase() throws Exception {

        final MARFileParser marFileParser = new MARFileParser(signserverhome
                + "/dist-server/xmlsigner.mar");
        moduleVersion = marFileParser.getVersionFromMARFile();

        TestUtils.redirectToTempOut();
        TestUtils.redirectToTempErr();
        
        // Worker 1
        TestUtils.assertSuccessfulExecution(new String[] {
                "module",
                "add",
                signserverhome + "/dist-server/xmlsigner.mar",
                "junittest"
            });
        assertTrue("Loading module",
                TestUtils.grepTempOut("Loading module XMLSIGNER"));
        assertTrue("Module loaded",
                TestUtils.grepTempOut("Module loaded successfully."));
        workerSession.reloadConfiguration(WORKERID);
        
        // Worker 2
        TestUtils.assertSuccessfulExecution(new String[] {
                "module",
                "add",
                signserverhome + "/dist-server/pdfsigner.mar",
                "junittest"
            });
        assertTrue("Loading module",
                TestUtils.grepTempOut("Loading module PDFSIGNER"));
        assertTrue("Module loaded",
                TestUtils.grepTempOut("Module loaded successfully."));
        workerSession.reloadConfiguration(WORKERID2);
        TestUtils.flushTempOut();
        TestUtils.flushTempErr();
    }

    public void test01missingArguments() throws Exception {
        try {
            execute("signdocument");
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
    public void test02signDocumentFromParameter() throws Exception {
        try {
            String res =
                    new String(execute("signdocument", "-workername", "TestXMLSigner", "-data", "<root/>"));
            assertTrue("contains signature tag: "
                    + res, res.contains("<root><Signature"));
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
            final File doc = File.createTempFile("test.xml", null);
            FileOutputStream out = null;
            try {
                out = new FileOutputStream(doc);
                out.write("<tag/>".getBytes());
                out.close();
            } finally {
                if (out != null) {
                    out.close();
                }
            }

            String res =
                    new String(execute("signdocument", "-workername", 
                    "TestXMLSigner", "-infile", doc.getAbsolutePath()));
            assertTrue("contains signature tag: "
                    + res, res.contains("<tag><Signature"));
        } catch (IllegalArgumentException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Test for the "-pdfpassword" argument.
     * signdocument -workername TestPDFSigner -infile $SIGNSERVER_HOME/res/test/pdf/sample-open123.pdf
     * @throws Exception
     */
    public void test03signPDFwithPasswordOverHTTP() throws Exception {
        try {

            byte[] res = execute("signdocument", "-workername", 
                    "TestPDFSigner", "-infile", signserverhome + "/res/test/pdf/sample-open123.pdf",
                    "-pdfpassword", "open123");
            assertNotNull("No result", res);
            assertNotSame("Empty result", 0, res.length);
        } catch (IllegalArgumentException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }
    
    /**
     * Test for the "-pdfpassword" argument.
     * signdocument -workername TestPDFSigner -infile $SIGNSERVER_HOME/res/test/pdf/sample-open123.pdf -protocol WEBSERVICES
     * @throws Exception
     */
    public void test04signPDFwithPasswordOverWebservices() throws Exception {
        try {
            
            byte[] res = execute("signdocument", "-workername", 
                    "TestPDFSigner", "-infile", signserverhome + "/res/test/pdf/sample-open123.pdf",
                    "-pdfpassword", "open123", "-protocol", "WEBSERVICES",
                    "-truststore", "../../p12/truststore.jks", "-truststorepwd", "changeit");
            assertNotNull("No result", res);
            assertNotSame("Empty result", 0, res.length);
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
            "XMLSIGNER",
            String.valueOf(moduleVersion)
        });
        assertTrue("module remove",
                TestUtils.grepTempOut("Removal of module successful."));
        workerSession.reloadConfiguration(WORKERID);
        
        TestUtils.assertSuccessfulExecution(new String[] {
            "removeworker",
            String.valueOf(WORKERID2)
        });

        TestUtils.assertSuccessfulExecution(new String[] {
            "module",
            "remove",
            "PDFSIGNER",
            String.valueOf(moduleVersion)
        });
        assertTrue("module remove",
                TestUtils.grepTempOut("Removal of module successful."));
        workerSession.reloadConfiguration(WORKERID2);
    }

    private byte[] execute(String... args) throws IllegalArgumentException, IOException {
        byte[] output = null;
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        try {
            final DocumentSignerCLI cli = new DocumentSignerCLI(args);
            cli.run();
        } finally {
            output = out.toByteArray();
            System.setOut(System.out);
            System.out.write(output);
        }
        return output;
    }
}
