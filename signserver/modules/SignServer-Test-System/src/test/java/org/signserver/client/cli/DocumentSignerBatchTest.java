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
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import org.signserver.cli.spi.*;
import org.signserver.client.cli.defaultimpl.ConsolePasswordReader;
import org.signserver.client.cli.defaultimpl.SignDocumentCommand;
import org.signserver.common.SignServerUtil;
import org.signserver.test.conf.SignerConfigurationBuilder;
import org.signserver.test.conf.WorkerPropertiesBuilder;
import org.signserver.testutils.ModulesTestCase;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

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
public class DocumentSignerBatchTest extends ModulesTestCase {

    // Logger for this class.
    private static final Logger LOG = Logger.getLogger(DocumentSignerBatchTest.class);

    // WORKER_ID used in this test case as defined in junittest-part-config.properties for XMLSigner.
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

    @BeforeClass
    public static void beforeClass() throws Exception {
        assertNotNull("Please set SIGNSERVER_HOME environment variable", SIGNSERVER_HOME);
        // Configure
        SignServerUtil.installBCProvider();
        initSSLKeystore();
        // Worker 1
        addTestXMLSigner(
                SignerConfigurationBuilder.builder()
                        .withSignerId(WORKER_ID)
                        .withSignerName("TestXMLSigner")
                        .withAutoActivate(true)
        );
        // Worker with password auth
        addTestXMLSigner(
                SignerConfigurationBuilder.builder()
                        .withSignerId(WORKER_ID_AUTH)
                        .withSignerName("TestXMLSignerAuth")
                        .withAutoActivate(true)
        );
        // Apply Worker's (password auth) properties
        applyWorkerPropertiesAndReload(
                WorkerPropertiesBuilder.builder()
                        .withWorkerId(WORKER_ID_AUTH)
                        .withAuthType("org.signserver.server.UsernamePasswordAuthorizer")
                        .withUser1("foo123")
        );
    }

    @AfterClass
    public static void afterClass() {
        for (int workerId : WORKERS) {
            removeWorkerById(workerId);
        }
    }

    // Tests that values for threads must be larger than 0.
    @Test
    public void failOnIncorrectOptionsThreadsZero() throws Exception {
        LOG.info(">failOnIncorrectOptionsThreadsZero");
        // given
        expectedException.expect(IllegalCommandArgumentsException.class);
        expectedException.expectMessage("threads");
        // when
        execute("signdocument", "-workername", "TestXMLSigner",
                "-indir", inDir.getRoot().getAbsolutePath(),
                "-outdir", outDir.getRoot().getAbsolutePath(),
                "-threads", "0");
    }

    // Tests that values for threads must be larger than 0.
    @Test
    public void failOnIncorrectOptionsThreadsNegative() throws Exception {
        LOG.info(">failOnIncorrectOptionsThreadsNegative");
        // given
        expectedException.expect(IllegalCommandArgumentsException.class);
        expectedException.expectMessage("threads");
        // when
        execute("signdocument", "-workername", "TestXMLSigner",
                "-indir", inDir.getRoot().getAbsolutePath(),
                "-outdir", outDir.getRoot().getAbsolutePath(),
                "-threads", "-1");
    }

    // Tests that it is not allowed to specify both -indir and -data.
    @Test
    public void failOnIncorrectOptionsBothInDirAndDataSpecified() throws Exception {
        LOG.info("failOnIncorrectOptionsBothInDirAndDataSpecified");
        // given
        expectedException.expect(IllegalCommandArgumentsException.class);
        expectedException.expectMessage("Can not specify both -data and -indir");
        // when
        execute("signdocument", "-workername", "TestXMLSigner",
                        "-indir", inDir.getRoot().getAbsolutePath(),
                        "-outdir", outDir.getRoot().getAbsolutePath(),
                        "-data", "<data/>");
    }

    // Tests that it is not allowed to specify the same -indir and -outdir.
    @Test
    public void failOnIncorrectOptionsInDirAndOutDirAreEqual() throws Exception {
        LOG.info("failOnIncorrectOptionsInDirAndOutDirAreEqual");
        // given
        expectedException.expect(IllegalCommandArgumentsException.class);
        expectedException.expectMessage("Can not specify the same directory as -indir and -outdir");
        // when
        execute("signdocument", "-workername", "TestXMLSigner",
                        "-indir", inDir.getRoot().getAbsolutePath(),
                        "-outdir", inDir.getRoot().getAbsolutePath());
    }

    // Tests that it is not allowed to specify both -onefirst and -startall
    @Test
    public void failOnIncorrectOptionsBothOneFirstAndStartAll() throws Exception {
        LOG.info("failOnIncorrectOptionsBothOneFirstAndStartAll");
        // given
        expectedException.expect(IllegalCommandArgumentsException.class);
        expectedException.expectMessage("Can not specify both -onefirst and -startall");
        // when
        execute("signdocument", "-workername", "TestXMLSigner",
                        "-indir", inDir.getRoot().getAbsolutePath(),
                        "-outdir", outDir.getRoot().getAbsolutePath(),
                        "-onefirst", "-startall");
    }

    /**
     * Tests the simple case of signing 1 document from the input directory.
     * <pre>
     * signdocument -workername XMLSigner -indir /tmp/input -outdir /tmp/output
     * </pre>
     */
    @Test
    public void signOneDocumentFromInDir() throws Exception {
        LOG.info("signOneDocumentFromInDir");
        // given
        final ArrayList<File> inputFiles = createInputFiles(1);
        // when
        final String res = new String(
                execute("signdocument",
                        "-workername", "TestXMLSigner",
                        "-indir", inDir.getRoot().getAbsolutePath(),
                        "-outdir", outDir.getRoot().getAbsolutePath())
        );
        // then
        assertFalse("should not contain the document: " + res, res.contains("<document1"));
        assertOutFilesSignatures(inputFiles);
    }

    /**
     *  Tests that one subdirectory are ignored and that it returns status code 1.
     */
    @Test
    public void signOneDirectoryFromInDir() throws Exception {
        LOG.info("signOneDirectoryFromInDir");
        inDir.newFolder("temp");
        int result = executeReturnStatus("signdocument", "-workername", "TestXMLSigner", "-indir", inDir.getRoot().getAbsolutePath(), "-outdir", outDir.getRoot().getAbsolutePath());
        assertEquals("return code: ", 1, result);
    }

    /**
     * Tests that two subdirectories are ignored and that it returns status code 1.
     */
    @Test
    public void signTwoDirectoriesFromInDir() throws Exception {
        LOG.info("signTwoDirectoriesFromInDir");
        inDir.newFolder("tempOne");
        inDir.newFolder("tempTwo");
        int result = executeReturnStatus("signdocument", "-workername", "TestXMLSigner", "-indir", inDir.getRoot().getAbsolutePath(), "-outdir", outDir.getRoot().getAbsolutePath());
        assertEquals("return code: ", 1, result);
    }

    /**
     * Tests that signing one document with a directory present returns status code 0.
     */
    @Test
    public void signDocumentFromInDirWithOneDirectoryPresent() throws Exception {
        LOG.info("signDocumentFromInDirWithOneDirectoryPresent");
        File tempFile = null;
        try {
            inDir.newFolder("tempDir");
            tempFile = inDir.newFile("tempFile.xml");
            FileUtils.writeStringToFile(tempFile, "<root/>", StandardCharsets.UTF_8);
            int result = executeReturnStatus("signdocument", "-workername", "TestXMLSigner", "-indir", inDir.getRoot().getAbsolutePath(), "-outdir", outDir.getRoot().getAbsolutePath());
            assertEquals("return code: ", 0, result);
        } finally {
            FileUtils.deleteQuietly(tempFile);
        }
    }

    /**
     * Tests the simple case of siging 2 documents from the input directory.
     * <pre>
     * signdocument -workername XMLSigner -indir /tmp/input -outdir /tmp/output
     * </pre>
     */
    @Test
    public void signTwoDocumentsFromInDir() throws Exception {
        LOG.info("signTwoDocumentsFromInDir");
        // given
        final ArrayList<File> files = createInputFiles(2);
        final Set<String> expectedOutFiles = new HashSet<>(Arrays.asList("file1.xml", "file0.xml")); // As generated
        // when
        final String res = new String(
                execute("signdocument",
                        "-workername", "TestXMLSigner",
                        "-indir", inDir.getRoot().getAbsolutePath(),
                        "-outdir", outDir.getRoot().getAbsolutePath())
        );
        // then
        assertFalse("should not contain the document: " + res, res.contains("<document"));
        assertEquals("outfiles", expectedOutFiles, new HashSet<>(Arrays.asList(outDir.getRoot().list())));
        assertOutFilesSignatures(files);
    }

    /**
     * Tests signing 13 documents from the input directory using 3 threads.
     * <pre>
     * signdocument -workername XMLSigner -indir /tmp/input -outdir /tmp/output
     * </pre>
     */
    @Test
    public void sign13DocumentsFromInDirWith3Threads() throws Exception {
        LOG.info("sign13DocumentsFromInDirWith3Threads");
        // given
        final ArrayList<File> files = createInputFiles(13);
        // when
        final String res = new String(
                execute("signdocument",
                        "-workername", "TestXMLSigner",
                        "-indir", inDir.getRoot().getAbsolutePath(),
                        "-outdir", outDir.getRoot().getAbsolutePath(),
                        "-threads", "3")
        );
        // then
        assertFalse("should not contain any document: " + res, res.contains("<doc"));
        assertOutFilesSignatures(files);
    }

    /**
     * Tests signing 50 documents from the input directory using 30 threads and load-balancing as ROUND_ROBIN.
     * <pre>
     * signdocument -workername XMLSigner -indir /tmp/input -outdir /tmp/output
     * </pre>
     */
    @Test
    public void sign50DocumentsFromInDirWith30ThreadsAndLoadBalancingAsRoundRobin() throws Exception {
        LOG.info("sign50DocumentsFromInDirWith30ThreadsAndLoadBalancingAsRoundRobin");
        // given
        final ArrayList<File> files = createInputFiles(50);
        // when
        final String res = new String(
                execute("signdocument",
                        "-workername", "TestXMLSigner",
                        "-indir", inDir.getRoot().getAbsolutePath(),
                        "-outdir", outDir.getRoot().getAbsolutePath(),
                        "-threads", "30", "-loadbalancing", "ROUND_ROBIN",
                        "-hosts", "invalidhost1,invalidhost2,localhost")
        );
        // then
        assertFalse("should not contain any document: " + res, res.contains("<doc"));
        assertOutFilesSignatures(files);
    }

    /**
     * Tests signing 200 documents from the input directory using 100 threads and load-balancing as ROUND_ROBIN.
     * <pre>
     * signdocument -workername XMLSigner -indir /tmp/input -outdir /tmp/output
     * </pre>
     */
    @Test
    public void sign200DocumentsFromInDirWith100ThreadsAndLoadBalancingAsRoundRobin() throws Exception {
        LOG.info("sign200DocumentsFromInDirWith100ThreadsAndLoadBalancingAsRoundRobin");
        // given
        final ArrayList<File> files = createInputFiles(200);
        // Disabling KEYUSAGECOUNTER is required currently to avoid an issue JBAS014516 (Failed to acquire a permit within 5 MINUTES)
        applyWorkerPropertiesAndReload(WorkerPropertiesBuilder.builder().withWorkerId(WORKER_ID).withDisableKeyUsageCounter(true));
        // when
        final String res = new String(
                execute("signdocument",
                        "-workername", "TestXMLSigner",
                        "-indir", inDir.getRoot().getAbsolutePath(),
                        "-outdir", outDir.getRoot().getAbsolutePath(),
                        "-threads", "100", "-loadbalancing", "ROUND_ROBIN",
                        "-hosts", "primekey.com, localhost,localhost,localhost",
                        "-timeout", "1000")
        );
        // then
        assertFalse("should not contain any document: " + res, res.contains("<doc"));
        assertOutFilesSignatures(files);
    }

    // Test for asking user password with a single thread.
    @Test
    public void sign5DocumentFromInDirWith1ThreadAndPasswordAsk() throws Exception {
        LOG.info("signOneDocumentFromInDirWith1ThreadAndPasswordAsk");
        // given
        final ArrayList<File> files = createInputFiles(5);
        // Override the password reading
        final ArrayList<Boolean> called = new ArrayList<>();
        final SignDocumentCommand instance = new SignDocumentCommand() {
            @Override
            public ConsolePasswordReader createConsolePasswordReader() {
                return () -> {
                    called.add(true);
                    return "foo123".toCharArray();
                };
            }
        };
        // when
        execute(instance, "signdocument",
                "-workername", "TestXMLSignerAuth",
                "-indir", inDir.getRoot().getAbsolutePath(),
                "-outdir", outDir.getRoot().getAbsolutePath(),
                "-username", "user1",
                "-threads", "1");
        // then
        assertEquals("calls to readPassword", 1, called.size());
        assertOutFilesSignatures(files);
    }

    // Test for asking user password with multiple threads.
    @Test
    public void sign5DocumentsFromInDirWith3ThreadsAndPasswordAsk() throws Exception {
        LOG.info("sign5DocumentsFromInDirWith3ThreadsAndPasswordAsk");
        // given
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
        // when
        execute(instance, "signdocument",
                "-workername", "TestXMLSignerAuth",
                "-indir", inDir.getRoot().getAbsolutePath(),
                "-outdir", outDir.getRoot().getAbsolutePath(),
                "-username", "user1",
                "-threads", "3");
        // then
        assertEquals("calls to readPassword", 1, called.size());
        assertOutFilesSignatures(files);
    }

    // Test for re-asking user password with single thread + check that it is only asked 1 more time.
    @Test
    public void sign5DocumentsFromInDirWith1ThreadAndPasswordReAsk() throws Exception {
        LOG.info("sign5DocumentsFromInDirWith1ThreadAndPasswordReAsk");
        // given
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
        // when
        execute(instance, "signdocument",
                "-workername", "TestXMLSignerAuth",
                "-indir", inDir.getRoot().getAbsolutePath(),
                "-outdir", outDir.getRoot().getAbsolutePath(),
                "-username", "user1",
                "-threads", "1");
        // then
        assertEquals("calls to readPassword", 2, calls.size());
        assertOutFilesSignatures(files);
    }

    // Test that one password is specified in command line we do not re-ask.
    @Test
    public void failSigning5DocumentsFromInDirWith1ThreadAndWrongPassword() throws Exception {
        LOG.info("failSigning5DocumentsFromInDirWith1ThreadAndWrongPassword");
        // given
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
        // when
        try {
            execute(instance, "signdocument",
                    "-workername", "TestXMLSignerAuth",
                    "-indir", inDir.getRoot().getAbsolutePath(),
                    "-outdir", outDir.getRoot().getAbsolutePath(),
                    "-username", "user1",
                    "-password", "incorrect123",
                    "-threads", "1");
            fail("This should fail.");
        } catch (CommandFailureException ex) {
            // then
            assertEquals("calls to readPassword", 0, calls.size());
        }
    }

    // Test for re-asking for user password with multiple threads + check that it is only asked 1 more time.
    @Test
    public void sign5DocumentsFromInDirWith3ThreadsAndPasswordReAsk() throws Exception {
        LOG.info("sign5DocumentsFromInDirWith3ThreadsAndPasswordReAsk");
        // given
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
        // when
        execute(instance, "signdocument",
                "-workername", "TestXMLSignerAuth",
                "-indir", inDir.getRoot().getAbsolutePath(),
                "-outdir", outDir.getRoot().getAbsolutePath(),
                "-username", "user1",
                "-threads", "3");
        // then
        assertEquals("calls to readPassword", 2, calls.size());
        assertOutFilesSignatures(files);
    }

    // Test for re-asking user password with multiple threads + check that it is only asked 2 more times.
    @Test
    public void sign5DocumentsFromInDirWith3ThreadsAndPasswordReAsk2() throws Exception {
        LOG.info("sign5DocumentsFromInDirWith3ThreadsAndPasswordReAsk2");
        // given
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
        // when
        execute(instance, "signdocument",
                "-workername", "TestXMLSignerAuth",
                "-indir", inDir.getRoot().getAbsolutePath(),
                "-outdir", outDir.getRoot().getAbsolutePath(),
                "-username", "user1",
                "-threads", "3");
        // then
        assertEquals("calls to readPassword", 3, calls.size());
        assertOutFilesSignatures(files);
    }

    // Test for re-asking user password with multiple threads + check that it stops asking for password.
    @Test
    public void failSigning5DocumentsFromInDirWith3ThreadsAndWrongPassword4Times() throws Exception {
        LOG.info("failSigning5DocumentsFromInDirWith3ThreadsAndWrongPassword4Times");
        // given
        createInputFiles(5);
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
        // when
        try {
            execute(instance, "signdocument",
                    "-workername", "TestXMLSignerAuth",
                    "-indir", inDir.getRoot().getAbsolutePath(),
                    "-outdir", outDir.getRoot().getAbsolutePath(),
                    "-username", "user1",
                    "-threads", "3");
            fail("This should fail.");
        } catch (CommandFailureException expected) {
            // then
            assertEquals("calls to readPassword", 4, calls.size());
        }
    }

    // Tests that output files are removed and input files are renamed with failed extension in case of command failure.
    @Test
    public void shouldCleanupOutputFilesUponFailureAndKeepInput() throws Exception {
        LOG.info("test05cleanUpWhenFailure");
        // given
        final File file1 = inDir.newFile("doc1.xml");
        FileUtils.writeStringToFile(file1, "InvalidXML1", StandardCharsets.UTF_8);
        final File file2 = inDir.newFile("doc2.xml");
        FileUtils.writeStringToFile(file2, "InvalidXML2", StandardCharsets.UTF_8);
        // when
        try {
            execute("signdocument",
                    "-workername", "TestXMLSigner",
                    "-indir", inDir.getRoot().getAbsolutePath(),
                    "-outdir", outDir.getRoot().getAbsolutePath());
            fail("This should fail.");
        } catch (CommandFailureException ex) {
            // then
            // output files should have been deleted
            final File outFile1 = new File(outDir.getRoot().getAbsolutePath(), "doc1.xml");
            final File outFile2 = new File(outDir.getRoot().getAbsolutePath(), "doc2.xml");
            assertFalse("Output file1 exists: ", outFile1.exists());
            assertFalse("Output file2 exists: ", outFile2.exists());
            // input files with original names should be present
            assertTrue("Input file1 does not exist: ", file1.exists());
            assertTrue("Input file2 does not exist: ", file2.exists());
        }
    }

    private byte[] execute(
            String... args
    ) throws IOException, IllegalCommandArgumentsException, CommandFailureException {
        return execute(new SignDocumentCommand(), args);
    }

    private byte[] execute(
            SignDocumentCommand instance, String... args
    ) throws IOException, IllegalCommandArgumentsException, CommandFailureException {
        byte[] output;
        final ByteArrayOutputStream bout = new ByteArrayOutputStream();
        final PrintStream out = new PrintStream(bout);
        System.setOut(out);
        instance.init(
                new CommandContext(
                        "group1",
                        "signdocument",
                        new CommandFactoryContext(new Properties(), out, System.err)
                )
        );
        try {
            instance.execute(args);
        } finally {
            output = bout.toByteArray();
            System.setOut(System.out);
            System.out.write(output);
        }
        return output;
    }

    private int executeReturnStatus(String... args) throws CommandFailureException, IllegalCommandArgumentsException {
        return executeReturnStatus(new SignDocumentCommand(), args);
    }

    private int executeReturnStatus(SignDocumentCommand instance, String... args) throws CommandFailureException, IllegalCommandArgumentsException {
        final ByteArrayOutputStream bout = new ByteArrayOutputStream();
        final PrintStream out = new PrintStream(bout);
        System.setOut(out);
        instance.init(
                new CommandContext(
                        "group1",
                        "signdocument",
                        new CommandFactoryContext(new Properties(), out, System.err)
                )
        );

        return instance.execute(args);
    }

    private ArrayList<File> createInputFiles(final int count) throws IOException {
        final ArrayList<File> result = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            File f = inDir.newFile("file" + i + ".xml");
            FileUtils.writeStringToFile(f, "<doc" + i + "/>", StandardCharsets.UTF_8);
            result.add(f);
        }
        return result;
    }

    private Set<String> getExpectedNames(final ArrayList<File> inputFiles) {
        final HashSet<String> results = new HashSet<>();
        for (File file : inputFiles) {
            results.add(file.getName());
        }
        return results;
    }

    // Assert that input file has an equivalent of output file by name
    private void assertOutFilesMatchInputFiles(final ArrayList<File> inputFiles) {
        assertEquals("out files mismatch",
                getExpectedNames(inputFiles),
                new HashSet<>(Arrays.asList(Objects.requireNonNull(outDir.getRoot().list())))
        );
    }

    private void assertOutFilesSignatures(final ArrayList<File> files) throws IOException {
        // Check the collection first
        assertOutFilesMatchInputFiles(files);
        // Check one by one
        for (int i = 0; i < files.size(); i++) {
            final File file = files.get(i);
            String content = FileUtils.readFileToString(
                    new File(outDir.getRoot(), file.getName()),
                    StandardCharsets.UTF_8
            );
            assertTrue(
                    file.getName() + " contains signature tag: " + content,
                    content.contains("<doc" + i + "><Signature")
            );
        }
    }
}
