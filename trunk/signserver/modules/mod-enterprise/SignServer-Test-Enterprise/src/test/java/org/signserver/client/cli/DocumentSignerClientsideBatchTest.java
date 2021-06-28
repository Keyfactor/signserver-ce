/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
import net.jsign.pe.PEFile;
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests for the signdocument command of Client CLI using the batch mode where
 * an input and output directory is specified and optionally the number of
 * threads to run in parallel etc. Using the -clientside option
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DocumentSignerClientsideBatchTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DocumentSignerClientsideBatchTest.class);

    /** WORKERID used in this test case as defined in
     * junittest-part-config.properties for XMLSigner. */
    private static final int WORKERID = 5676;

    private static final int WORKERID_AUTH = 8000;

    private static final int[] WORKERS = new int[] { WORKERID, WORKERID_AUTH };

    private static File sampleFile1;
    private static File sampleFile2;

    private static File signedPE;
    private static File signedMSI;

    @Rule
    public TemporaryFolder inDir = new TemporaryFolder();

    @Rule
    public TemporaryFolder outDir = new TemporaryFolder();

    @Before
    public void setUp() throws Exception {
        final String SIGNSERVER_HOME = System.getenv("SIGNSERVER_HOME");
        assertNotNull("Please set SIGNSERVER_HOME environment variable", SIGNSERVER_HOME);
        SignServerUtil.installBCProvider();
        TestingSecurityManager.install();
        setupSSLKeystores();
        sampleFile1 = new File(SIGNSERVER_HOME + File.separator + "res" +
                               File.separator + "test" + File.separator +
                               "HelloPE.exe");
        sampleFile2 = new File(SIGNSERVER_HOME + File.separator + "res" +
                               File.separator + "test" + File.separator +
                               "sample.msi");
        signedPE = new File(SIGNSERVER_HOME + File.separator + "res" +
                               File.separator + "test" + File.separator +
                               "HelloPE-signed.exe");
        signedMSI = new File(SIGNSERVER_HOME + File.separator + "res" +
                               File.separator + "test" + File.separator +
                               "sample-signed.msi");
        assertTrue("Sample file not found: " + sampleFile1.getAbsolutePath(),
                   sampleFile1.isFile());
        assertTrue("Sample file not found: " + sampleFile2.getAbsolutePath(),
                   sampleFile2.isFile());
        assertTrue("Sample signed PE file not found: " + signedPE.getAbsolutePath(),
                   signedPE.isFile());
        assertTrue("Sample signed MSI file not found: " + signedMSI.getAbsolutePath(),
                   signedMSI.isFile());
    }

    @After
    public void tearDown() {
        TestingSecurityManager.remove();
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        LOG.info("test00SetupDatabase");
        // Worker 1
        addMSAuthCodeCMSSigner(WORKERID, "TestMSAuthCodeCMSSigner", true);

        // Worker with password auth
        addMSAuthCodeCMSSigner(WORKERID_AUTH, "TestMSAuthCodeCMSSignerAuth", true);
        getWorkerSession().setWorkerProperty(WORKERID_AUTH, "AUTHTYPE", "org.signserver.server.UsernamePasswordAuthorizer");
        getWorkerSession().setWorkerProperty(WORKERID_AUTH, "USER.USER1", "foo123");
        getWorkerSession().reloadConfiguration(WORKERID_AUTH);
    }

    /**
     * Tests that values for threads must be larger than 0.
     */
    @Test
    public void test01incorrectOptionThreads() throws Exception {
        LOG.info("test01incorrectOptionThreads");
        inDir.create();
        FileUtils.copyFileToDirectory(sampleFile1, inDir.getRoot());
        FileUtils.copyFileToDirectory(sampleFile2, inDir.getRoot());
        outDir.create();

        try {
            execute("signdocument", "-workername", "TestMSAuthCodeCMSSigner",
                            "-clientside", "-digestalgorithm", "SHA-256",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath(),
                            "-threads", "0");
            fail("Should have thrown exception threads");
        } catch (IllegalCommandArgumentsException e) {
            assertTrue("exception about threads: " + e.getMessage(),
                    e.getMessage().contains("threads"));
        }

        try {
            execute("signdocument", "-workername", "TestMSAuthCodeCMSSigner",
                            "-clientside", "-digestalgorithm", "SHA-256",
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
     */
    @Test
    public void test01incorrectOptionData() throws Exception {
        LOG.info("test01incorrectOptionData");
        inDir.create();
        FileUtils.copyFileToDirectory(sampleFile1, inDir.getRoot());
        FileUtils.copyFileToDirectory(sampleFile2, inDir.getRoot());
        outDir.create();

        try {
            execute("signdocument", "-workername", "TestMSAuthCodeCMSSigner",
                            "-clientside", "-digestalgorithm", "SHA-256",
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
     */
    @Test
    public void test01incorrectOptionSameDirs() throws Exception {
        LOG.info("test01incorrectOptionSameDirs");
        inDir.create();
        FileUtils.copyFileToDirectory(sampleFile1, inDir.getRoot());
        FileUtils.copyFileToDirectory(sampleFile2, inDir.getRoot());

        try {
            execute("signdocument", "-workername", "TestMSAuthCodeCMSSigner",
                            "-clientside", "-digestalgorithm", "SHA-256",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", inDir.getRoot().getAbsolutePath()); // Note: indir==outdir
            fail("Should have thrown exception about indir & outdir");
        } catch (IllegalCommandArgumentsException e) {
            assertTrue("exception about indir & outdir: " + e.getMessage(),
                    e.getMessage().contains("indir") && e.getMessage().contains("outdir"));
        }
    }

    /**
     * Tests that it is not allowed to specify both -infile and -outdir.
     */
    @Test
    public void test08Both_infile_And_outdir_NotAllowed() throws Exception {
        LOG.info("test08Both_infile_And_outdir_NotAllowed");
        outDir.create();

        try {
            execute("signdocument", "-workername", "TestMSAuthCodeCMSSigner",
                    "-clientside", "-digestalgorithm", "SHA-256",
                    "-infile", sampleFile1.getAbsolutePath(),
                    "-outdir", outDir.getRoot().getAbsolutePath());
            fail("Should have thrown exception about infile & outdir");
        } catch (IllegalCommandArgumentsException e) {
            assertTrue("exception about infile & outdir: " + e.getMessage(),
                    e.getMessage().contains("infile") && e.getMessage().contains("outdir"));
        }
    }

    /**
     * Tests that it is not allowed to specify both -onefirst and -startall
     */
    @Test
    public void test01incorrectOptionBothOneFirstAndStartAll() throws Exception {
        LOG.info("test01incorrectOptionBothOneFirstAndStartAll");
        inDir.create();
        FileUtils.copyFileToDirectory(sampleFile1, inDir.getRoot());
        FileUtils.copyFileToDirectory(sampleFile2, inDir.getRoot());
        outDir.create();

        try {
            execute("signdocument", "-workername", "TestMSAuthCodeCMSSigner",
                            "-clientside", "-digestalgorithm", "SHA-256",
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
     */
    @Test
    public void test02sign1DocumentFromInDir() throws Exception {
        LOG.info("test02sign1DocumentFromInDir");
        inDir.create();
        FileUtils.copyFileToDirectory(sampleFile1, inDir.getRoot());
        outDir.create();

        try {

            execute("signdocument",
                            "-clientside", "-digestalgorithm", "SHA-256",
                            "-workername", "TestMSAuthCodeCMSSigner",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath());

            Set<String> expectedOutFiles = Collections.singleton("HelloPE.exe");

            assertEquals("outfiles", expectedOutFiles, new HashSet<>(Arrays.asList(outDir.getRoot().list())));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Tests of signing already signed MSI file.
     * <pre>
     * signdocument -workername XMLSigner -indir /tmp/input -outdir /tmp/output
     * </pre>
     */
    @Test
    public void test06sign1DocumentFromInDir_Signed_MSI() throws Exception {
        LOG.info("test06sign1DocumentFromInDir_Signed_MSI");
        inDir.create();
        FileUtils.copyFileToDirectory(signedMSI, inDir.getRoot());
        outDir.create();

        try {
            execute("signdocument",
                            "-clientside", "-digestalgorithm", "SHA-256",
                            "-workername", "TestMSAuthCodeCMSSigner",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath());
            Set<String> expectedOutFiles = Collections.singleton("sample-signed.msi");
            assertEquals("outfiles", expectedOutFiles, new HashSet<>(Arrays.asList(outDir.getRoot().list())));
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
     */
    @Test
    public void test02sign2DocumentsFromInDir() throws Exception {
        LOG.info("test02sign2DocumentsFromInDir");
        inDir.create();
        FileUtils.copyFileToDirectory(sampleFile1, inDir.getRoot());
        FileUtils.copyFileToDirectory(sampleFile2, inDir.getRoot());
        outDir.create();

        try {

            execute("signdocument",
                            "-clientside", "-digestalgorithm", "SHA-256",
                            "-workername", "TestMSAuthCodeCMSSigner",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath());

            Set<String> expectedOutFiles = new HashSet<>(Arrays.asList("HelloPE.exe", "sample.msi"));

            assertEquals("outfiles", expectedOutFiles, new HashSet<>(Arrays.asList(outDir.getRoot().list())));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Create input files by duplicating the sample PE file.
     *
     * @param count number of files
     */
    private ArrayList<File> createInputFiles(int count) throws IOException {
        ArrayList<File> result = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            File f = inDir.newFile("file" + i + ".exe");
            FileUtils.copyFile(sampleFile1, f);
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

        for (final File file : files) {
            final PEFile peFile = new PEFile(new File(outDir.getRoot(),
                    file.getName()));

            assertEquals("Has signature", 1, peFile.getSignatures().size());
        }
    }

    /**
     * Tests signing 13 documents from the input directory using 3 threads.
     * <pre>
     * signdocument -workername XMLSigner -indir /tmp/input -outdir /tmp/output
     * </pre>
     */
    @Test
    public void test02sign13DocumentsFromInDirWith3Threads() throws Exception {
        LOG.info("test02sign13DocumentsFromInDirWith3Threads");
        // Create 13 input files
        inDir.create();
        outDir.create();
        final ArrayList<File> files = createInputFiles(13);

        try {
            execute("signdocument",
                            "-clientside", "-digestalgorithm", "SHA-256",
                            "-workername", "TestMSAuthCodeCMSSigner",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath(),
                            "-threads", "3");

            assertOutfilesSignatures(files);

        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Test for asking for user password with single thread.
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
                return () -> {
                    called.add(true);
                    return "foo123".toCharArray();
                };
            }
        };

        // Sign anything and check that the readPassword was called once
        try {
            execute(instance, "signdocument",
                    "-clientside", "-digestalgorithm", "SHA-256",
                    "-workername", "TestMSAuthCodeCMSSignerAuth",
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
                return () -> {
                    called.add(true);
                    return "foo123".toCharArray();
                };
            }
        };

        // Sign anything and check that the readPassword was called once
        try {
            execute(instance, "signdocument",
                    "-clientside", "-digestalgorithm", "SHA-256",
                    "-workername", "TestMSAuthCodeCMSSigner",
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
                return () -> {
                    synchronized (calls) {
                        final String password = passwords[calls.size()];
                        calls.add(true);
                        return password.toCharArray();
                    }
                };
            }
        };

        // Sign anything and check that the readPassword was called 2 times
        try {
            execute(instance, "signdocument",
                    "-clientside", "-digestalgorithm", "SHA-256",
                    "-workername", "TestMSAuthCodeCMSSignerAuth",
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
                return () -> {
                    synchronized (calls) {
                        calls.add(true);
                        return "anything".toCharArray();
                    }
                };
            }
        };

        // Sign anything and check that the readPassword was not called
        try {
            execute(instance, "signdocument",
                    "-clientside", "-digestalgorithm", "SHA-256",
                    "-workername", "TestMSAuthCodeCMSSignerAuth",
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
                return () -> {
                    synchronized (calls) {
                        final String password = passwords[calls.size()];
                        calls.add(true);
                        return password.toCharArray();
                    }
                };
            }
        };

        // Sign anything and check that the readPassword was called 2 times
        try {
            execute(instance, "signdocument",
                    "-clientside", "-digestalgorithm", "SHA-256",
                    "-workername", "TestMSAuthCodeCMSSignerAuth",
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
                return () -> {
                    synchronized (calls) {
                        final String password = passwords[calls.size()];
                        calls.add(true);
                        return password.toCharArray();
                    }
                };
            }
        };

        // Sign anything and check that the readPassword was called 2 times
        try {
            execute(instance, "signdocument",
                    "-clientside", "-digestalgorithm", "SHA-256",
                    "-workername", "TestMSAuthCodeCMSSignerAuth",
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
                return () -> {
                    synchronized (calls) {
                        final String password = passwords[calls.size()];
                        calls.add(true);
                        return password.toCharArray();
                    }
                };
            }
        };

        // Sign anything and check that the readPassword was called 2 times
        try {
            execute(instance, "signdocument",
                    "-clientside", "-digestalgorithm", "SHA-256",
                    "-workername", "TestMSAuthCodeCMSSignerAuth",
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
     * Tests that the digest algorithm parameter can be formatted in a different way.
     */
    @Test
    public void test07digestAlgorithmFormatting_PE() throws Exception {
        LOG.info("test07digestAlgorithmFormatting_PE");
        inDir.create();
        FileUtils.copyFileToDirectory(sampleFile1, inDir.getRoot());
        outDir.create();

        try {
            execute("signdocument",
                            "-clientside", "-digestalgorithm", "sha256",
                            "-workername", "TestMSAuthCodeCMSSigner",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath());

            Set<String> expectedOutFiles = Collections.singleton("HelloPE.exe");

            assertEquals("outfiles", expectedOutFiles, new HashSet<>(Arrays.asList(outDir.getRoot().list())));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Tests that the digest algorithm parameter can be formatted in a different way.
     */
    @Test
    public void test07digestAlgorithmFormatting_MSI() throws Exception {
        LOG.info("test07digestAlgorithmFormatting_MSI");
        inDir.create();
        FileUtils.copyFileToDirectory(sampleFile2, inDir.getRoot());
        outDir.create();

        try {
            execute("signdocument",
                            "-clientside", "-digestalgorithm", "sha256",
                            "-workername", "TestMSAuthCodeCMSSigner",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath());

            Set<String> expectedOutFiles = Collections.singleton("sample.msi");

            assertEquals("outfiles", expectedOutFiles, new HashSet<>(Arrays.asList(outDir.getRoot().list())));
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error("Execution failed", ex);
            fail(ex.getMessage());
        }
    }

    @Test
    public void test99TearDownDatabase() {
        LOG.info("test99TearDownDatabase");
        for (int workerId : WORKERS) {
            removeWorker(workerId);
        }
    }

    private void execute(String... args) throws IOException, IllegalCommandArgumentsException, CommandFailureException {
        execute(new SignDocumentCommand(), args);
    }

    private void execute(SignDocumentCommand instance, String... args) throws IOException, IllegalCommandArgumentsException, CommandFailureException {
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
    }
}
