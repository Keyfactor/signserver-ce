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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.ejbca.ui.cli.util.ConsolePasswordReader;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.runners.MethodSorters;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.client.cli.defaultimpl.SignDocumentCommand;
import org.signserver.common.SignServerUtil;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestingSecurityManager;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.signserver.cli.spi.CommandContext;
import org.signserver.cli.spi.CommandFactoryContext;

/**
 * Tests for the signdocument command of Client CLI using the batch mode where
 * an input and output directory is specified and optionally the number of 
 * threads to run in parallel etc.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DocumentSignerBatchTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DocumentSignerBatchTest.class);

    /** WORKERID used in this test case as defined in 
     * junittest-part-config.properties for XMLSigner. */
    private static final int WORKERID = 5676;

    private static final int[] WORKERS = new int[] { WORKERID };

    private static String signserverhome;
    
    private final IWorkerSession workerSession = getWorkerSession();
    
    @Rule
    private final TemporaryFolder inDir = new TemporaryFolder();
    
    @Rule
    private final TemporaryFolder outDir = new TemporaryFolder();
    
    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        TestingSecurityManager.install();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull("Please set SIGNSERVER_HOME environment variable", signserverhome);
        setupSSLKeystores();
    }

    @After
    public void tearDown() throws Exception {
        TestingSecurityManager.remove();
    }	
	
    @Test
    public void test00SetupDatabase() throws Exception {
        // Worker 1
        setProperties(new File(signserverhome, "res/test/test-xmlsigner-configuration.properties"));
        workerSession.reloadConfiguration(WORKERID);
    }

    // TODO: Add tests for different illegal combinations of input parameters
    /*@Test
    public void test01missingArguments() throws Exception {
        try {
            execute("signdocument");
            fail("Should have thrown exception about missing arguments");
        } catch (IllegalCommandArgumentsException expected) {} // NOPMD
    }*/

    /**
     * Tests the simple case of siging 1 document from the input directory.
     * <pre>
     * signdocument -workername XMLSigner -indir /tmp/input -outdir /tmp/output
     * </pre>
     * @throws Exception
     */
    @Test
    public void test02sign1DocumentFromInDir() throws Exception {
        inDir.create();
        File file1 = inDir.newFile("doc1.xml");
        FileUtils.writeStringToFile(file1, "<document1/>");
        outDir.create();
        
        try {

            String res =
                    new String(execute("signdocument", 
                            "-workername", "TestXMLSigner",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath()));
            assertFalse("should not contain the document: "
                    + res, res.contains("<document1"));
            Set<String> expectedOutFiles = Collections.singleton("doc1.xml");
            
            assertEquals("outfiles", expectedOutFiles, new HashSet<String>(Arrays.asList(outDir.getRoot().list())));
            
            String file1Content = FileUtils.readFileToString(new File(outDir.getRoot(), file1.getName()));
            
            assertTrue("contains signature tag: "
                    + file1Content, file1Content.contains("<document1><Signature"));
            
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    
    @Test
    public void test99TearDownDatabase() throws Exception {
        for (int workerId : WORKERS) {
            removeWorker(workerId);
        }
    }

    private byte[] execute(String... args) throws IOException, IllegalCommandArgumentsException, CommandFailureException {
        return execute(new SignDocumentCommand(), args);
    }
    
    private byte[] execute(SignDocumentCommand instance, String... args) throws IOException, IllegalCommandArgumentsException, CommandFailureException {
        byte[] output;
        final ByteArrayOutputStream bout = new ByteArrayOutputStream();
        final PrintStream out = new PrintStream(bout);
        System.setOut(out);
        instance.init(new CommandContext("group1", "signdocument", new CommandFactoryContext(new Properties(), out, System.err)));
        try {
            instance.execute(args);
        } finally {
            output = bout.toByteArray();
            System.setOut(System.out);
            System.out.write(output);
        }
        return output;
    }
}
