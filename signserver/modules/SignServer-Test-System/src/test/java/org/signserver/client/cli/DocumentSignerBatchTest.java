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
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.runners.MethodSorters;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.client.cli.defaultimpl.SignDocumentCommand;
import org.signserver.common.SignServerUtil;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestingSecurityManager;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.signserver.cli.spi.CommandContext;
import org.signserver.cli.spi.CommandFactoryContext;
import org.signserver.client.cli.defaultimpl.ConsolePasswordReader;

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
    
    private static final int WORKERID_AUTH = 8000;

    private static final int[] WORKERS = new int[] { WORKERID, WORKERID_AUTH };

    private static String signserverhome;

    @Rule
    private final TemporaryFolder inDir = new TemporaryFolder();
    
    @Rule
    private final TemporaryFolder outDir = new TemporaryFolder();
    
    @Before
    @Override
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        TestingSecurityManager.install();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull("Please set SIGNSERVER_HOME environment variable", signserverhome);
        setupSSLKeystores();
    }

    @After
    @Override
    public void tearDown() throws Exception {
        TestingSecurityManager.remove();
    }	
	
    @Test
    public void test00SetupDatabase() throws Exception {
        LOG.info("test00SetupDatabase");
        // Worker 1
        addDummySigner(WORKERID, "TestXMLSigner", true);
        
        // Worker with password auth
        addDummySigner(WORKERID_AUTH, "TestXMLSignerAuth", true);
        getWorkerSession().setWorkerProperty(WORKERID_AUTH, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
        getWorkerSession().setWorkerProperty(WORKERID_AUTH, "USER.USER1", "foo123");
        getWorkerSession().reloadConfiguration(WORKERID_AUTH);
    }

    /**
     * Tests that values for threads must be larger than 0.
     * @throws Exception 
     */
    @Test
    public void test01incorrectOptionThreads() throws Exception {
        LOG.info("test01incorrectOptionThreads");
        inDir.create();
        File file1 = inDir.newFile("doc1.xml");
        FileUtils.writeStringToFile(file1, "<document1/>");
        outDir.create();

        try {
            execute("signdocument", "-workername", "TestXMLSigner",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath(),
                            "-threads", "0");
            fail("Should have thrown exception threads");
        } catch (IllegalCommandArgumentsException e) {
            assertTrue("exception about threads: " + e.getMessage(),
                    e.getMessage().contains("threads"));
        }
        
        try {
            execute("signdocument", "-workername", "TestXMLSigner",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath(),
                            "-threads", "-1");
            fail("Should have thrown exception threads");
        } catch (IllegalCommandArgumentsException e) {
            assertTrue("exception about threads: " + e.getMessage(),
                    e.getMessage().contains("threads"));
        }
    }
    
    /**
     * Tests that it is not allowed to specify both -indir and -data.
     * @throws Exception 
     */
    @Test
    public void test01incorrectOptionData() throws Exception {
        LOG.info("test01incorrectOptionData");
        inDir.create();
        File file1 = inDir.newFile("doc1.xml");
        FileUtils.writeStringToFile(file1, "<document1/>");
        outDir.create();

        try {
            execute("signdocument", "-workername", "TestXMLSigner",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath(),
                            "-data", "<data/>");
            fail("Should have thrown exception threads");
        } catch (IllegalCommandArgumentsException e) {
            assertTrue("exception about data: " + e.getMessage(),
                    e.getMessage().contains("data") && e.getMessage().contains("indir"));
        }
    }
    
    /**
     * Tests that it is not allowed to specify the same -indir and -outdir.
     * @throws Exception 
     */
    @Test
    public void test01incorrectOptionSameDirs() throws Exception {
        LOG.info("test01incorrectOptionSameDirs");
        inDir.create();
        File file1 = inDir.newFile("doc1.xml");
        FileUtils.writeStringToFile(file1, "<document1/>");

        try {
            execute("signdocument", "-workername", "TestXMLSigner",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", inDir.getRoot().getAbsolutePath()); // Note: indir==outdir
            fail("Should have thrown exception about indir & outdir");
        } catch (IllegalCommandArgumentsException e) {
            assertTrue("exception about indir & outdir: " + e.getMessage(),
                    e.getMessage().contains("indir") && e.getMessage().contains("outdir"));
        }
    }
    
    /**
     * Tests that it is not allowed to specify both -onefirst and -startall
     * @throws Exception 
     */
    @Test
    public void test01incorrectOptionBothOneFirstAndStartAll() throws Exception {
        LOG.info("test01incorrectOptionBothOneFirstAndStartAll");
        inDir.create();
        File file1 = inDir.newFile("doc1.xml");
        FileUtils.writeStringToFile(file1, "<document1/>");
        outDir.create();

        try {
            execute("signdocument", "-workername", "TestXMLSigner",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath(),
                            "-onefirst", "-startall"); // Note: both
            fail("Should have thrown exception about onefirst & startall");
        } catch (IllegalCommandArgumentsException e) {
            assertTrue("exception about onefirst & startall: " + e.getMessage(),
                    e.getMessage().contains("onefirst") && e.getMessage().contains("startall"));
        }
    }

    /**
     * Tests the simple case of siging 1 document from the input directory.
     * <pre>
     * signdocument -workername XMLSigner -indir /tmp/input -outdir /tmp/output
     * </pre>
     * @throws Exception
     */
    @Test
    public void test02sign1DocumentFromInDir() throws Exception {
        LOG.info("test02sign1DocumentFromInDir");
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
            
            assertEquals("outfiles", expectedOutFiles, new HashSet<>(Arrays.asList(outDir.getRoot().list())));
            
            String file1Content = FileUtils.readFileToString(new File(outDir.getRoot(), file1.getName()));
            
            assertTrue("contains signature tag: "
                    + file1Content, file1Content.contains("<document1><Signature"));
            
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }
    
    /**
     * Tests the simple case of siging 2 documents from the input directory.
     * <pre>
     * signdocument -workername XMLSigner -indir /tmp/input -outdir /tmp/output
     * </pre>
     * @throws Exception
     */
    @Test
    public void test02sign2DocumentsFromInDir() throws Exception {
        LOG.info("test02sign2DocumentsFromInDir");
        inDir.create();
        File file1 = inDir.newFile("doc1.xml");
        FileUtils.writeStringToFile(file1, "<document1/>");
        File file2 = inDir.newFile("doc2.xml");
        FileUtils.writeStringToFile(file2, "<document2/>");
        outDir.create();
        
        try {

            String res =
                    new String(execute("signdocument", 
                            "-workername", "TestXMLSigner",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath()));
            assertFalse("should not contain the document: "
                    + res, res.contains("<document"));
            Set<String> expectedOutFiles = new HashSet<>(Arrays.asList("doc2.xml", "doc1.xml"));
            
            assertEquals("outfiles", expectedOutFiles, new HashSet<>(Arrays.asList(outDir.getRoot().list())));
            
            String file1Content = FileUtils.readFileToString(new File(outDir.getRoot(), file1.getName()));
            assertTrue("contains signature tag: "
                    + file1Content, file1Content.contains("<document1><Signature"));
            
            String file2Content = FileUtils.readFileToString(new File(outDir.getRoot(), file2.getName()));
            assertTrue("contains signature tag: "
                    + file2Content, file2Content.contains("<document2><Signature"));
            
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }
    
    private ArrayList<File> createInputFiles(int count) throws IOException {
        ArrayList<File> result = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            File f = inDir.newFile("file" + i + ".xml");
            FileUtils.writeStringToFile(f, "<doc" + i + "/>");
            result.add(f);
        }
        return result;
    }
    
    private Set<String> getExpectedNames(ArrayList<File> files) {
        final HashSet<String> results = new HashSet<>();
        for (File file : files) {
            results.add(file.getName());
        }
        return results;
    }
    
    private void assertOutfilesSignatures(ArrayList<File> files) throws IOException {
        assertEquals("outfiles", getExpectedNames(files), new HashSet<>(Arrays.asList(outDir.getRoot().list())));
        
        for (int i = 0; i < files.size(); i++) {
            final File file = files.get(i);
            String content = FileUtils.readFileToString(new File(outDir.getRoot(), file.getName()));
            assertTrue(file.getName() + " contains signature tag: "
                + content, content.contains("<doc" + i + "><Signature"));
        }
    }
    
    /**
     * Tests signing 13 documents from the input directory using 3 threads.
     * <pre>
     * signdocument -workername XMLSigner -indir /tmp/input -outdir /tmp/output
     * </pre>
     * @throws Exception
     */
    @Test
    public void test02sign13DocumentsFromInDirWith3Threads() throws Exception {
        LOG.info("test02sign13DocumentsFromInDirWith3Threads");
        // Create 13 input files
        inDir.create();
        outDir.create();
        final ArrayList<File> files = createInputFiles(13);

        try {
            String res =
                    new String(execute("signdocument", 
                            "-workername", "TestXMLSigner",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath(),
                            "-threads", "3"));
            assertFalse("should not contain any document: "
                    + res, res.contains("<doc"));
            
            assertOutfilesSignatures(files);
            
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }
    
    /**
     * Tests signing 50 documents from the input directory using 30 threads and loadbalancing as ROUND_ROBIN
     * <pre>
     * signdocument -workername XMLSigner -indir /tmp/input -outdir /tmp/output
     * </pre>
     * @throws Exception
     */
    @Test
    public void test02sign50DocumentsFromInDirWith30ThreadsWithLoadBalancing() throws Exception {
        LOG.info("test02sign50DocumentsFromInDirWith30ThreadsWithLoadBalancing");
        // Create 50 input files
        inDir.create();
        outDir.create();
        final ArrayList<File> files = createInputFiles(50);

        try {
            String res
                    = new String(execute("signdocument",
                            "-workername", "TestXMLSigner",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath(),
                            "-threads", "30", "loadbalancing", "ROUND_ROBIN", "-hosts", "invalidhost1,invalidhost2,localhost"));
            assertFalse("should not contain any document: "
                    + res, res.contains("<doc"));

            assertOutfilesSignatures(files);

        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }    
    
    /**
     * Test for asking for user password with single thread.
     * @throws Exception 
     */
    @Test
    public void test03promptForUserPassword1Thread() throws Exception {
        LOG.info("test03promptForUserPassword1Thread");
        // Create a few input files
        inDir.create();
        outDir.create();
        final ArrayList<File> files = createInputFiles(5);
        
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
            execute(instance, "signdocument",
                    "-workername", "TestXMLSignerAuth", 
                    "-indir", inDir.getRoot().getAbsolutePath(),
                    "-outdir", outDir.getRoot().getAbsolutePath(),
                    "-username", "user1",
                    "-threads", "1");
            assertEquals("calls to readPassword", 1, called.size());
            
            assertOutfilesSignatures(files);
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }
    
    /**
     * Test for asking for user password with multiple threads.
     * @throws Exception 
     */
    @Test
    public void test03promptForUserPassword3Thread() throws Exception {
        LOG.info("test03promptForUserPassword3Thread");
        // Create a few input files
        inDir.create();
        outDir.create();
        final ArrayList<File> files = createInputFiles(5);
        
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
            execute(instance, "signdocument",
                    "-workername", "TestXMLSignerAuth", 
                    "-indir", inDir.getRoot().getAbsolutePath(),
                    "-outdir", outDir.getRoot().getAbsolutePath(),
                    "-username", "user1",
                    "-threads", "3");
            assertEquals("calls to readPassword", 1, called.size());
            
            assertOutfilesSignatures(files);
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }
    
    /**
     * Test for re-asking for user password with single thread + check that it 
     * is only asked 1 more time.
     * @throws Exception 
     */
    @Test
    public void test04promptForUserPasswordAgain1Thread() throws Exception {
        LOG.info("test04promptForUserPasswordAgain1Thread");
        // Create a few input files
        inDir.create();
        outDir.create();
        final ArrayList<File> files = createInputFiles(5);
        
        // Override the password reading
        final String[] passwords = new String[] { "incorrect1", "foo123" };
        final ArrayList<Boolean> calls = new ArrayList<>();
        SignDocumentCommand instance = new SignDocumentCommand() {
            @Override
            public ConsolePasswordReader createConsolePasswordReader() {
                return new ConsolePasswordReader() {
                    @Override
                    public char[] readPassword() {
                        synchronized (calls) {
                            final String password = passwords[calls.size()];
                            calls.add(true);
                            return password.toCharArray();
                        }
                    }
                };
            }
        };
        
        // Sign anything and check that the readPassword was called 2 times
        try {
            execute(instance, "signdocument",
                    "-workername", "TestXMLSignerAuth", 
                    "-indir", inDir.getRoot().getAbsolutePath(),
                    "-outdir", outDir.getRoot().getAbsolutePath(),
                    "-username", "user1",
                    "-threads", "1");
            assertEquals("calls to readPassword", 2, calls.size());
            
            assertOutfilesSignatures(files);
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }
    
    /**
     * Test that one password is specified in command line we do not re-ask.
     * @throws Exception 
     */
    @Test
    public void test04promptForUserPasswordNotIfSpecified() throws Exception {
        LOG.info("test04promptForUserPasswordNotIfSpecified");
        // Create a few input files
        inDir.create();
        outDir.create();
        createInputFiles(5);
        
        // Override the password reading
        final ArrayList<Boolean> calls = new ArrayList<>();
        SignDocumentCommand instance = new SignDocumentCommand() {
            @Override
            public ConsolePasswordReader createConsolePasswordReader() {
                return new ConsolePasswordReader() {
                    @Override
                    public char[] readPassword() {
                        synchronized (calls) {
                            calls.add(true);
                            return "anything".toCharArray();
                        }
                    }
                };
            }
        };
        
        // Sign anything and check that the readPassword was not called
        try {
            execute(instance, "signdocument",
                    "-workername", "TestXMLSignerAuth", 
                    "-indir", inDir.getRoot().getAbsolutePath(),
                    "-outdir", outDir.getRoot().getAbsolutePath(),
                    "-username", "user1",
                    "-password", "incorrect123",
                    "-threads", "1");
        } catch (CommandFailureException expexted) {
            assertEquals("calls to readPassword", 0, calls.size());
        }
    }
    
    /**
     * Test for re-asking for user password with multiple threads + check that
     * it is only asked 1 more time.
     * @throws Exception 
     */
    @Test
    public void test04promptForUserPasswordAgain3Threads() throws Exception {
        LOG.info("test04promptForUserPasswordAgain3Threads");
        // Create a few input files
        inDir.create();
        outDir.create();
        final ArrayList<File> files = createInputFiles(5);
        
        // Override the password reading
        final String[] passwords = new String[] { "incorrect1", "foo123" };
        final ArrayList<Boolean> calls = new ArrayList<>();
        SignDocumentCommand instance = new SignDocumentCommand() {
            @Override
            public ConsolePasswordReader createConsolePasswordReader() {
                return new ConsolePasswordReader() {
                    @Override
                    public char[] readPassword() {
                        synchronized (calls) {
                            final String password = passwords[calls.size()];
                            calls.add(true);
                            return password.toCharArray();
                        }
                    }
                };
            }
        };
        
        // Sign anything and check that the readPassword was called 2 times
        try {
            execute(instance, "signdocument",
                    "-workername", "TestXMLSignerAuth", 
                    "-indir", inDir.getRoot().getAbsolutePath(),
                    "-outdir", outDir.getRoot().getAbsolutePath(),
                    "-username", "user1",
                    "-threads", "3");
            assertEquals("calls to readPassword", 2, calls.size());
            
            assertOutfilesSignatures(files);
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }
    
    /**
     * Test for re-asking for user password with multiple threads + check that
     * it is only asked 2 more times.
     * @throws Exception 
     */
    @Test
    public void test04promptForUserPasswordAgain2_3Threads() throws Exception {
        LOG.info("test04promptForUserPasswordAgain2_3Threads");
        // Create a few input files
        inDir.create();
        outDir.create();
        final ArrayList<File> files = createInputFiles(5);
        
        // Override the password reading
        final String[] passwords = new String[] { "incorrect1", "incorrect2", "foo123" };
        final ArrayList<Boolean> calls = new ArrayList<>();
        SignDocumentCommand instance = new SignDocumentCommand() {
            @Override
            public ConsolePasswordReader createConsolePasswordReader() {
                return new ConsolePasswordReader() {
                    @Override
                    public char[] readPassword() {
                        synchronized (calls) {
                            final String password = passwords[calls.size()];
                            calls.add(true);
                            return password.toCharArray();
                        }
                    }
                };
            }
        };
        
        // Sign anything and check that the readPassword was called 2 times
        try {
            execute(instance, "signdocument",
                    "-workername", "TestXMLSignerAuth", 
                    "-indir", inDir.getRoot().getAbsolutePath(),
                    "-outdir", outDir.getRoot().getAbsolutePath(),
                    "-username", "user1",
                    "-threads", "3");
            assertEquals("calls to readPassword", 3, calls.size());
            
            assertOutfilesSignatures(files);
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Test for re-asking for user password with multiple threads + check that
     * it stops asking for password.
     * @throws Exception 
     */
    @Test
    public void test04promptForUserPasswordAgainStops_3Threads() throws Exception {
        LOG.info("test04promptForUserPasswordAgainStops_3Threads");
        // Create a few input files
        inDir.create();
        outDir.create();
        final ArrayList<File> files = createInputFiles(5);
        
        // Override the password reading
        final String[] passwords = new String[] { "incorrect1", "incorrect2", "incorrect3", "incorrect4", "incorrect5" };
        final ArrayList<Boolean> calls = new ArrayList<>();
        SignDocumentCommand instance = new SignDocumentCommand() {
            @Override
            public ConsolePasswordReader createConsolePasswordReader() {
                return new ConsolePasswordReader() {
                    @Override
                    public char[] readPassword() {
                        synchronized (calls) {
                            final String password = passwords[calls.size()];
                            calls.add(true);
                            return password.toCharArray();
                        }
                    }
                };
            }
        };
        
        // Sign anything and check that the readPassword was called 2 times
        try {
            execute(instance, "signdocument",
                    "-workername", "TestXMLSignerAuth", 
                    "-indir", inDir.getRoot().getAbsolutePath(),
                    "-outdir", outDir.getRoot().getAbsolutePath(),
                    "-username", "user1",
                    "-threads", "3");
            
            assertOutfilesSignatures(files);
        } catch (CommandFailureException expected) {
            assertEquals("calls to readPassword", 4, calls.size());
        }
    }
    
    /**
     * Tests that output files are removed and input files are renamed with failed extension in case of command failure.
     * @throws Exception
     */
    @Test
    public void test05cleanUpWhenFailure() throws Exception {
        LOG.info("test05cleanUpWhenFailure");
        inDir.create();
        File file1 = inDir.newFile("doc1.xml");
        FileUtils.writeStringToFile(file1, "InvalidXML1");
        File file2 = inDir.newFile("doc2.xml");
        FileUtils.writeStringToFile(file2, "InvalidXML2");
        outDir.create();

        try {
            execute("signdocument",
                    "-workername", "TestXMLSigner",
                    "-indir", inDir.getRoot().getAbsolutePath(),
                    "-outdir", outDir.getRoot().getAbsolutePath());
            fail("This should have failed");
        } catch (CommandFailureException ex) {
            // output files should have been deleted 
            File outFile1 = new File(outDir.getRoot().getAbsolutePath(), "doc1.xml");
            File outFile2 = new File(outDir.getRoot().getAbsolutePath(), "doc2.xml");
            assertTrue("Output file1 exists: ", !outFile1.exists());
            assertTrue("Output file2 exists: ", !outFile2.exists());
            // input files with original names should be present
            assertTrue("Input file1 not exists: ", file1.exists());
            assertTrue("Input file2 not exists: ", file2.exists());
        } finally {
            inDir.delete();
            outDir.delete();
        }
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        LOG.info("test99TearDownDatabase");
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