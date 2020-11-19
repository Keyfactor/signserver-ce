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
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.internal.runners.JUnit4ClassRunner;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.JUnit4;
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

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
    private static final int WORKER_ID = 5676;

    private static final int WORKER_ID_AUTH = 8000;

    private static final int[] WORKERS = new int[] {WORKER_ID, WORKER_ID_AUTH};

    private static final String SIGNSERVER_HOME = System.getenv("SIGNSERVER_HOME");

    @Rule
    public ExpectedException expectedException = ExpectedException.none();
    @Rule
    public TemporaryFolder inDir = new TemporaryFolder();
    @Rule
    public TemporaryFolder outDir = new TemporaryFolder();

    @Before
    public void setUp() throws Exception {
        assertNotNull("Please set SIGNSERVER_HOME environment variable", SIGNSERVER_HOME);
        // Configure
        SignServerUtil.installBCProvider();
        TestingSecurityManager.install();
        setupSSLKeystores();
        // Create tmp dirs
        inDir.create();
        outDir.create();
    }

    @After
    public void tearDown() throws Exception {
        TestingSecurityManager.remove();
        // Remove tmp dirs
//        inDir.delete();
//        outDir.delete();
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        LOG.info("test00SetupDatabase");
        // Worker 1
        addDummySigner(WORKER_ID, "TestXMLSigner", true);

        // Worker with password auth
        addDummySigner(WORKER_ID_AUTH, "TestXMLSignerAuth", true);
        getWorkerSession().setWorkerProperty(WORKER_ID_AUTH, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
        getWorkerSession().setWorkerProperty(WORKER_ID_AUTH, "USER.USER1", "foo123");
        getWorkerSession().reloadConfiguration(WORKER_ID_AUTH);
    }

//    /**
//     * Tests that values for threads must be larger than 0.
//     */
//    @Test
//    public void test01incorrectOptionThreads() throws Exception {
//        LOG.info("test01incorrectOptionThreads");
//
////        createInputFiles(1);
//
//        try {
//            execute("signdocument", "-workername", "TestXMLSigner",
//                            "-indir", inDir.getRoot().getAbsolutePath(),
//                            "-outdir", outDir.getRoot().getAbsolutePath(),
//                            "-threads", "0");
//            fail("Should have thrown exception threads");
//        } catch (IllegalCommandArgumentsException e) {
//            assertTrue("exception about threads: " + e.getMessage(),
//                    e.getMessage().contains("threads"));
//        }
//
//        try {
//            execute("signdocument", "-workername", "TestXMLSigner",
//                            "-indir", inDir.getRoot().getAbsolutePath(),
//                            "-outdir", outDir.getRoot().getAbsolutePath(),
//                            "-threads", "-1");
//            fail("Should have thrown exception threads");
//        } catch (IllegalCommandArgumentsException e) {
//            assertTrue("exception about threads: " + e.getMessage(),
//                    e.getMessage().contains("threads"));
//        }
//    }

//    /**
//     * Tests that it is not allowed to specify both -indir and -data.
//     */
//    @Test
//    public void test01incorrectOptionData() throws Exception {
//        LOG.info("test01incorrectOptionData");
//
////        createInputFiles(1);
//
//        try {
//            execute("signdocument", "-workername", "TestXMLSigner",
//                            "-indir", inDir.getRoot().getAbsolutePath(),
//                            "-outdir", outDir.getRoot().getAbsolutePath(),
//                            "-data", "<data/>");
//            fail("Should have thrown exception threads");
//        } catch (IllegalCommandArgumentsException e) {
//            assertTrue("exception about data: " + e.getMessage(),
//                    e.getMessage().contains("data") && e.getMessage().contains("indir"));
//        }
//    }

//    /**
//     * Tests that it is not allowed to specify both -indir and -data.
//     */
//    @Test(expected = IllegalCommandArgumentsException.class)
//    public void test01incorrectOptionData() throws Exception {
//        LOG.info("test01incorrectOptionData");
//
////        expectedException.expect(IllegalCommandArgumentsException.class);
//        //expectedException.expectMessage("data");
//        //expectedException.expectMessage("indir");
//
//        execute("signdocument", "-workername", "TestXMLSigner",
//                        "-indir", inDir.getRoot().getAbsolutePath(),
//                        "-outdir", outDir.getRoot().getAbsolutePath(),
//                        "-data", "<data/>");
//    }

    @Test
    public void testA() {
        LOG.info("test01incorrectOptionData");

        expectedException.expect(NullPointerException.class);

        throw new NullPointerException();
    }

//    /**
//     * Tests that it is not allowed to specify the same -indir and -outdir.
//     */
//    @Test
//    public void test01incorrectOptionSameDirs() throws Exception {
//        LOG.info("test01incorrectOptionSameDirs");
//
////        createInputFiles(1);
//
//        try {
//            execute("signdocument", "-workername", "TestXMLSigner",
//                            "-indir", inDir.getRoot().getAbsolutePath(),
//                            "-outdir", inDir.getRoot().getAbsolutePath()); // Note: indir==outdir
//            fail("Should have thrown exception about indir & outdir");
//        } catch (IllegalCommandArgumentsException e) {
//            assertTrue("exception about indir & outdir: " + e.getMessage(),
//                    e.getMessage().contains("indir") && e.getMessage().contains("outdir"));
//        }
//    }

//    /**
//     * Tests that it is not allowed to specify both -onefirst and -startall
//     */
//    @Test
//    public void test01incorrectOptionBothOneFirstAndStartAll() throws Exception {
//        LOG.info("test01incorrectOptionBothOneFirstAndStartAll");
//
////        createInputFiles(1);
//
//        try {
//            execute("signdocument", "-workername", "TestXMLSigner",
//                            "-indir", inDir.getRoot().getAbsolutePath(),
//                            "-outdir", outDir.getRoot().getAbsolutePath(),
//                            "-onefirst", "-startall"); // Note: both
//            fail("Should have thrown exception about onefirst & startall");
//        } catch (IllegalCommandArgumentsException e) {
//            assertTrue("exception about onefirst & startall: " + e.getMessage(),
//                    e.getMessage().contains("onefirst") && e.getMessage().contains("startall"));
//        }
//    }

    /**
     * Tests the simple case of siging 1 document from the input directory.
     * <pre>
     * signdocument -workername XMLSigner -indir /tmp/input -outdir /tmp/output
     * </pre>
     */
    @Test
    public void test02sign1DocumentFromInDir() throws Exception {
        LOG.info("test02sign1DocumentFromInDir");

        final ArrayList<File> inputFiles = createInputFiles(1);

        try {

            final String res =
                    new String(execute("signdocument",
                            "-workername", "TestXMLSigner",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath()));
            assertFalse("should not contain the document: "
                    + res, res.contains("<document1"));

            assertOutFilesSignatures(inputFiles);

        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

//    /**
//     * Tests the simple case of siging 2 documents from the input directory.
//     * <pre>
//     * signdocument -workername XMLSigner -indir /tmp/input -outdir /tmp/output
//     * </pre>
//     */
//    @Test
//    public void test02sign2DocumentsFromInDir() throws Exception {
//        LOG.info("test02sign2DocumentsFromInDir");
//
//        final ArrayList<File> files = createInputFiles(2);
//
//        try {
//
//            String res =
//                    new String(execute("signdocument",
//                            "-workername", "TestXMLSigner",
//                            "-indir", inDir.getRoot().getAbsolutePath(),
//                            "-outdir", outDir.getRoot().getAbsolutePath()));
//            assertFalse("should not contain the document: "
//                    + res, res.contains("<document"));
//            Set<String> expectedOutFiles = new HashSet<>(Arrays.asList("doc2.xml", "doc1.xml"));
//
//            assertEquals("outfiles", expectedOutFiles, new HashSet<>(Arrays.asList(outDir.getRoot().list())));
//
//            assertOutFilesSignatures(files);
//
//        } catch (IllegalCommandArgumentsException ex) {
//            LOG.error("Execution failed", ex);
//            fail(ex.getMessage());
//        }
//    }


//    /**
//     * Tests signing 13 documents from the input directory using 3 threads.
//     * <pre>
//     * signdocument -workername XMLSigner -indir /tmp/input -outdir /tmp/output
//     * </pre>
//     */
//    @Test
//    public void test02sign13DocumentsFromInDirWith3Threads() throws Exception {
//        LOG.info("test02sign13DocumentsFromInDirWith3Threads");
//
//        // Create 13 input files
//        final ArrayList<File> files = createInputFiles(13);
//
//        try {
//            String res =
//                    new String(execute("signdocument",
//                            "-workername", "TestXMLSigner",
//                            "-indir", inDir.getRoot().getAbsolutePath(),
//                            "-outdir", outDir.getRoot().getAbsolutePath(),
//                            "-threads", "3"));
//            assertFalse("should not contain any document: "
//                    + res, res.contains("<doc"));
//
//            assertOutFilesSignatures(files);
//
//        } catch (IllegalCommandArgumentsException ex) {
//            LOG.error("Execution failed", ex);
//            fail(ex.getMessage());
//        }
//    }

//    /**
//     * Tests signing 50 documents from the input directory using 30 threads and loadbalancing as ROUND_ROBIN.
//     * <pre>
//     * signdocument -workername XMLSigner -indir /tmp/input -outdir /tmp/output
//     * </pre>
//     */
//    @Test
//    public void test02sign50DocumentsFromInDirWith30ThreadsWithLoadBalancing() throws Exception {
//        LOG.info("test02sign50DocumentsFromInDirWith30ThreadsWithLoadBalancing");
//
//        // Create 50 input files
//        final ArrayList<File> files = createInputFiles(50);
//
//        try {
//            String res
//                    = new String(execute("signdocument",
//                            "-workername", "TestXMLSigner",
//                            "-indir", inDir.getRoot().getAbsolutePath(),
//                            "-outdir", outDir.getRoot().getAbsolutePath(),
//                            "-threads", "30", "-loadbalancing", "ROUND_ROBIN", "-hosts", "invalidhost1,invalidhost2,localhost"));
//            assertFalse("should not contain any document: "
//                    + res, res.contains("<doc"));
//
//            assertOutFilesSignatures(files);
//
//        } catch (IllegalCommandArgumentsException ex) {
//            LOG.error("Execution failed", ex);
//            fail(ex.getMessage());
//        }
//    }

//    /**
//     * Tests signing 200 documents from the input directory using 100 threads and loadbalancing as ROUND_ROBIN.
//     * <pre>
//     * signdocument -workername XMLSigner -indir /tmp/input -outdir /tmp/output
//     * </pre>
//     */
//    @Test
//    public void test02sign200DocumentsFromInDirWith100ThreadsWithLoadBalancing() throws Exception {
//        LOG.info("test02sign200DocumentsFromInDirWith100ThreadsWithLoadBalancing");
//
//        // Create 200 input files
//        final ArrayList<File> files = createInputFiles(200);
//
//        try {
//
//            // Disabling KEYUSAGECOUNTER is required currently to avoid a issue JBAS014516 (Failed to acquire a permit within 5 MINUTES)
//            getWorkerSession().setWorkerProperty(WORKER_ID, "DISABLEKEYUSAGECOUNTER", "TRUE");
//            getWorkerSession().reloadConfiguration(WORKER_ID);
//
//            String res
//                    = new String(execute("signdocument",
//                            "-workername", "TestXMLSigner",
//                            "-indir", inDir.getRoot().getAbsolutePath(),
//                            "-outdir", outDir.getRoot().getAbsolutePath(),
//                            "-threads", "100", "-loadbalancing", "ROUND_ROBIN", "-hosts", "primekey.com, localhost,localhost,localhost",
//                            "-timeout", "1000"));
//            assertFalse("should not contain any document: "
//                    + res, res.contains("<doc"));
//
//            assertOutFilesSignatures(files);
//
//        } catch (IllegalCommandArgumentsException ex) {
//            LOG.error("Execution failed", ex);
//            fail(ex.getMessage());
//        }
//    }

//    /**
//     * Test for asking for user password with single thread.
//     */
//    @Test
//    public void test03promptForUserPassword1Thread() throws Exception {
//        LOG.info("test03promptForUserPassword1Thread");
//
//        // Create a few input files
//        final ArrayList<File> files = createInputFiles(5);
//
//        // Override the password reading
//        final ArrayList<Boolean> called = new ArrayList<>();
//        SignDocumentCommand instance = new SignDocumentCommand() {
//            @Override
//            public ConsolePasswordReader createConsolePasswordReader() {
//                return () -> {
//                    called.add(true);
//                    return "foo123".toCharArray();
//                };
//            }
//        };
//
//        // Sign anything and check that the readPassword was called once
//        try {
//            execute(instance, "signdocument",
//                    "-workername", "TestXMLSignerAuth",
//                    "-indir", inDir.getRoot().getAbsolutePath(),
//                    "-outdir", outDir.getRoot().getAbsolutePath(),
//                    "-username", "user1",
//                    "-threads", "1");
//            assertEquals("calls to readPassword", 1, called.size());
//
//            assertOutFilesSignatures(files);
//        } catch (IllegalCommandArgumentsException ex) {
//            LOG.error("Execution failed", ex);
//            fail(ex.getMessage());
//        }
//    }

//    /**
//     * Test for asking for user password with multiple threads.
//     */
//    @Test
//    public void test03promptForUserPassword3Thread() throws Exception {
//        LOG.info("test03promptForUserPassword3Thread");
//
//        // Create a few input files
//        final ArrayList<File> files = createInputFiles(5);
//
//        // Override the password reading
//        final ArrayList<Boolean> called = new ArrayList<>();
//        SignDocumentCommand instance = new SignDocumentCommand() {
//            @Override
//            public ConsolePasswordReader createConsolePasswordReader() {
//                return () -> {
//                    called.add(true);
//                    return "foo123".toCharArray();
//                };
//            }
//        };
//
//        // Sign anything and check that the readPassword was called once
//        try {
//            execute(instance, "signdocument",
//                    "-workername", "TestXMLSignerAuth",
//                    "-indir", inDir.getRoot().getAbsolutePath(),
//                    "-outdir", outDir.getRoot().getAbsolutePath(),
//                    "-username", "user1",
//                    "-threads", "3");
//            assertEquals("calls to readPassword", 1, called.size());
//
//            assertOutFilesSignatures(files);
//        } catch (IllegalCommandArgumentsException ex) {
//            LOG.error("Execution failed", ex);
//            fail(ex.getMessage());
//        }
//    }

//    /**
//     * Test for re-asking for user password with single thread + check that it
//     * is only asked 1 more time.
//     */
//    @Test
//    public void test04promptForUserPasswordAgain1Thread() throws Exception {
//        LOG.info("test04promptForUserPasswordAgain1Thread");
//
//        // Create a few input files
//        final ArrayList<File> files = createInputFiles(5);
//
//        // Override the password reading
//        final String[] passwords = new String[] { "incorrect1", "foo123" };
//        final ArrayList<Boolean> calls = new ArrayList<>();
//        SignDocumentCommand instance = new SignDocumentCommand() {
//            @Override
//            public ConsolePasswordReader createConsolePasswordReader() {
//                return () -> {
//                    synchronized (calls) {
//                        final String password = passwords[calls.size()];
//                        calls.add(true);
//                        return password.toCharArray();
//                    }
//                };
//            }
//        };
//
//        // Sign anything and check that the readPassword was called 2 times
//        try {
//            execute(instance, "signdocument",
//                    "-workername", "TestXMLSignerAuth",
//                    "-indir", inDir.getRoot().getAbsolutePath(),
//                    "-outdir", outDir.getRoot().getAbsolutePath(),
//                    "-username", "user1",
//                    "-threads", "1");
//            assertEquals("calls to readPassword", 2, calls.size());
//
//            assertOutFilesSignatures(files);
//        } catch (IllegalCommandArgumentsException ex) {
//            LOG.error("Execution failed", ex);
//            fail(ex.getMessage());
//        }
//    }

//    /**
//     * Test that one password is specified in command line we do not re-ask.
//     */
//    @Test
//    public void test04promptForUserPasswordNotIfSpecified() throws Exception {
//        LOG.info("test04promptForUserPasswordNotIfSpecified");
//
//        // Create a few input files
//        createInputFiles(5);
//
//        // Override the password reading
//        final ArrayList<Boolean> calls = new ArrayList<>();
//        SignDocumentCommand instance = new SignDocumentCommand() {
//            @Override
//            public ConsolePasswordReader createConsolePasswordReader() {
//                return () -> {
//                    synchronized (calls) {
//                        calls.add(true);
//                        return "anything".toCharArray();
//                    }
//                };
//            }
//        };
//
//        // Sign anything and check that the readPassword was not called
//        try {
//            execute(instance, "signdocument",
//                    "-workername", "TestXMLSignerAuth",
//                    "-indir", inDir.getRoot().getAbsolutePath(),
//                    "-outdir", outDir.getRoot().getAbsolutePath(),
//                    "-username", "user1",
//                    "-password", "incorrect123",
//                    "-threads", "1");
//        } catch (CommandFailureException expexted) {
//            assertEquals("calls to readPassword", 0, calls.size());
//        }
//    }

//    /**
//     * Test for re-asking for user password with multiple threads + check that
//     * it is only asked 1 more time.
//     */
//    @Test
//    public void test04promptForUserPasswordAgain3Threads() throws Exception {
//        LOG.info("test04promptForUserPasswordAgain3Threads");
//
//        // Create a few input files
//        final ArrayList<File> files = createInputFiles(5);
//
//        // Override the password reading
//        final String[] passwords = new String[] { "incorrect1", "foo123" };
//        final ArrayList<Boolean> calls = new ArrayList<>();
//        SignDocumentCommand instance = new SignDocumentCommand() {
//            @Override
//            public ConsolePasswordReader createConsolePasswordReader() {
//                return () -> {
//                    synchronized (calls) {
//                        final String password = passwords[calls.size()];
//                        calls.add(true);
//                        return password.toCharArray();
//                    }
//                };
//            }
//        };
//
//        // Sign anything and check that the readPassword was called 2 times
//        try {
//            execute(instance, "signdocument",
//                    "-workername", "TestXMLSignerAuth",
//                    "-indir", inDir.getRoot().getAbsolutePath(),
//                    "-outdir", outDir.getRoot().getAbsolutePath(),
//                    "-username", "user1",
//                    "-threads", "3");
//            assertEquals("calls to readPassword", 2, calls.size());
//
//            assertOutFilesSignatures(files);
//        } catch (IllegalCommandArgumentsException ex) {
//            LOG.error("Execution failed", ex);
//            fail(ex.getMessage());
//        }
//    }

//    /**
//     * Test for re-asking for user password with multiple threads + check that
//     * it is only asked 2 more times.
//     */
//    @Test
//    public void test04promptForUserPasswordAgain2_3Threads() throws Exception {
//        LOG.info("test04promptForUserPasswordAgain2_3Threads");
//
//        // Create a few input files
//        final ArrayList<File> files = createInputFiles(5);
//
//        // Override the password reading
//        final String[] passwords = new String[] { "incorrect1", "incorrect2", "foo123" };
//        final ArrayList<Boolean> calls = new ArrayList<>();
//        SignDocumentCommand instance = new SignDocumentCommand() {
//            @Override
//            public ConsolePasswordReader createConsolePasswordReader() {
//                return () -> {
//                    synchronized (calls) {
//                        final String password = passwords[calls.size()];
//                        calls.add(true);
//                        return password.toCharArray();
//                    }
//                };
//            }
//        };
//
//        // Sign anything and check that the readPassword was called 2 times
//        try {
//            execute(instance, "signdocument",
//                    "-workername", "TestXMLSignerAuth",
//                    "-indir", inDir.getRoot().getAbsolutePath(),
//                    "-outdir", outDir.getRoot().getAbsolutePath(),
//                    "-username", "user1",
//                    "-threads", "3");
//            assertEquals("calls to readPassword", 3, calls.size());
//
//            assertOutFilesSignatures(files);
//        } catch (IllegalCommandArgumentsException ex) {
//            LOG.error("Execution failed", ex);
//            fail(ex.getMessage());
//        }
//    }

//    /**
//     * Test for re-asking for user password with multiple threads + check that
//     * it stops asking for password.
//     */
//    @Test
//    public void test04promptForUserPasswordAgainStops_3Threads() throws Exception {
//        LOG.info("test04promptForUserPasswordAgainStops_3Threads");
//
//        // Create a few input files
//        final ArrayList<File> files = createInputFiles(5);
//
//        // Override the password reading
//        final String[] passwords = new String[] { "incorrect1", "incorrect2", "incorrect3", "incorrect4", "incorrect5" };
//        final ArrayList<Boolean> calls = new ArrayList<>();
//        SignDocumentCommand instance = new SignDocumentCommand() {
//            @Override
//            public ConsolePasswordReader createConsolePasswordReader() {
//                return new ConsolePasswordReader() {
//                    @Override
//                    public char[] readPassword() {
//                        synchronized (calls) {
//                            final String password = passwords[calls.size()];
//                            calls.add(true);
//                            return password.toCharArray();
//                        }
//                    }
//                };
//            }
//        };
//
//        // Sign anything and check that the readPassword was called 2 times
//        try {
//            execute(instance, "signdocument",
//                    "-workername", "TestXMLSignerAuth",
//                    "-indir", inDir.getRoot().getAbsolutePath(),
//                    "-outdir", outDir.getRoot().getAbsolutePath(),
//                    "-username", "user1",
//                    "-threads", "3");
//
//            assertOutFilesSignatures(files);
//        } catch (CommandFailureException expected) {
//            assertEquals("calls to readPassword", 4, calls.size());
//        }
//    }

//    /**
//     * Tests that output files are removed and input files are renamed with failed extension in case of command failure.
//     */
//    @Test
//    public void test05cleanUpWhenFailure() throws Exception {
//        LOG.info("test05cleanUpWhenFailure");
//
//        File file1 = inDir.newFile("doc1.xml");
//        FileUtils.writeStringToFile(file1, "InvalidXML1", StandardCharsets.UTF_8);
//        File file2 = inDir.newFile("doc2.xml");
//        FileUtils.writeStringToFile(file2, "InvalidXML2", StandardCharsets.UTF_8);
//
//        try {
//            execute("signdocument",
//                    "-workername", "TestXMLSigner",
//                    "-indir", inDir.getRoot().getAbsolutePath(),
//                    "-outdir", outDir.getRoot().getAbsolutePath());
//            fail("This should have failed");
//        } catch (CommandFailureException ex) {
//            // output files should have been deleted
//            File outFile1 = new File(outDir.getRoot().getAbsolutePath(), "doc1.xml");
//            File outFile2 = new File(outDir.getRoot().getAbsolutePath(), "doc2.xml");
//            assertFalse("Output file1 exists: ", outFile1.exists());
//            assertFalse("Output file2 exists: ", outFile2.exists());
//            // input files with original names should be present
//            assertTrue("Input file1 not exists: ", file1.exists());
//            assertTrue("Input file2 not exists: ", file2.exists());
//        }
//    }
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

    private ArrayList<File> createInputFiles(int count) throws IOException {
        final ArrayList<File> result = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            File f = inDir.newFile("file" + i + ".xml");
            FileUtils.writeStringToFile(f, "<doc" + i + "/>", StandardCharsets.UTF_8);
            result.add(f);
        }
        return result;
    }

    private Set<String> getExpectedNames(ArrayList<File> inputFiles) {
        final HashSet<String> results = new HashSet<>();
        for (File file : inputFiles) {
            results.add(file.getName());
        }
        return results;
    }

    // Assert that input file has an equivalent of output file by name
    private void assertOutFilesMatchInputFiles(final ArrayList<File> inputFiles) {
        assertEquals("outfiles", getExpectedNames(inputFiles), new HashSet<>(
                Arrays.asList(Objects.requireNonNull(outDir.getRoot().list())))
        );
    }

    private void assertOutFilesSignatures(final ArrayList<File> files) throws IOException {
        // Check the collection first
        assertOutFilesMatchInputFiles(files);

        for (int i = 0; i < files.size(); i++) {
            final File file = files.get(i);
            String content = FileUtils.readFileToString(new File(outDir.getRoot(), file.getName()), StandardCharsets.UTF_8);
            assertTrue(file.getName() + " contains signature tag: "
                    + content, content.contains("<doc" + i + "><Signature"));
        }
    }
}
