/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.msauthcode.signer;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.Properties;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.signserver.common.util.PathUtil;
import org.signserver.server.FixedTimeSource;
import org.signserver.testutils.ComplianceTestUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * A parameterized system test signing each file provided in
 * SIGNSERVER_HOME/authenticode-test-files and executes signtool.exe to check
 * that they can be verified correctly.
 * 
 * Note 1: This test requires portable executable files to manually be put in
 * the test folder.
 * Note 2: This test requires Windows (because of signtool.exe).
 *
 * @author Markus Kilås
 * @version $Id$
 */
@SuppressWarnings("PMD.UnusedFormalParameter") // JUnit requires parameter in constructor
@RunWith(Parameterized.class)
public class MSAuthCodeWinSigntoolComplianceTest {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(MSAuthCodeWinSigntoolComplianceTest.class);
    private static final String SIGNTOOL_PATH = "test.signtool.path";

    private final File inputFile;
    private final String digestAlgorithm;

    private static final int WORKER_ID = 8901;
    private static final String WORKER_NAME = "TestAuthenticodeSigner";
    private static final String WORKER_NAME_CMS = "TestAuthenticodeCMSSigner";
    private static final int TS_ID = 8902;
    private static final String TS_NAME = "TestAuthenticodeTimeStampSigner";

    private final ModulesTestCase helper = new ModulesTestCase();

    private static String signtoolCommand;

    public MSAuthCodeWinSigntoolComplianceTest(final String title, final File inputFile, final String digestAlgorithm) {
        this.inputFile = inputFile;
        this.digestAlgorithm = digestAlgorithm;
    }

    @BeforeClass
    public static void setUpClass() {
        final Properties config = new ModulesTestCase().getConfig();
        final String signtoolPath = config.getProperty(SIGNTOOL_PATH);
        signtoolCommand = StringUtils.isNotBlank(signtoolPath) ? signtoolPath : "signtool.exe";
    }

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> generateData() throws FileNotFoundException {
        final LinkedList<Object[]> data = new LinkedList<>();
        
        File folder = new File(PathUtil.getAppHome(), "authenticode-test-files");
        final String[] digestAlgorithms = new String[] { "SHA-256", "SHA-384", "SHA-512" };
        final String[] digestAlgorithmsMSI = new String[] { "SHA-256" }; // DSS-1840/DSS-1995: Remove after DSS-1995
        
        if (folder.exists()) {
            for (File file : folder.listFiles()) {

                // DSS-1840/DSS-1995: Temporarily disable SHA-384/SHA-512 for MSI files until DSS-1995 has been fixed
                final String[] algs = file.getName().endsWith(".msi") ? digestAlgorithmsMSI : digestAlgorithms;

                for (String algorithm : algs) {
                    data.add(new Object[] {
                       file.getName() + "-" + algorithm, file, algorithm
                    });
                }
            }
        } else {
            LOG.error("Folder with portable executable does not exist so not running any tests: " + folder.getAbsolutePath());
        }
        
        return data;
    }
    
    private void signThenVerifyInternal(final boolean useRFCTimestamper,
                                        final boolean doResign)
            throws Exception {
        LOG.info("========= Testing signThenVerifyInternal(" + useRFCTimestamper + "): " + inputFile + " =========");

        File signedBinary = null;
        try {

            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            if (useRFCTimestamper) {
                helper.addTimeStampSigner(TS_ID, TS_NAME, true);
            } else {
                helper.addMSTimeStampSigner(TS_ID, TS_NAME, true);
            }
            helper.addMSAuthCodeSigner(WORKER_ID, WORKER_NAME, true);
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "DIGESTALGORITHM", digestAlgorithm);
            if (useRFCTimestamper) {
                helper.getWorkerSession().setWorkerProperty(WORKER_ID, "TIMESTAMP_FORMAT", "RFC3161");
            }
            helper.getWorkerSession().setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            helper.getWorkerSession().setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            helper.getWorkerSession().reloadConfiguration(TS_ID);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);

            if (inputFile.getName().endsWith(".msi")) {
                if (doResign) {
                    signedBinary =
                            MSAuthCodeSignerTest.signAndResignAssertOkMSI(inputFile,
                                    WORKER_ID, TS_ID,
                                    time,
                                    useRFCTimestamper,
                                    false, 1);
                } else {
                    signedBinary = MSAuthCodeSignerTest.signAndAssertOkMSI(inputFile,
                            WORKER_ID,
                            TS_ID, time,
                            useRFCTimestamper,
                            false, 1);
                }
            } else if (inputFile.getName().endsWith(".ps1")
                    || inputFile.getName().endsWith(".psd1")
                    || inputFile.getName().endsWith(".psm1")) {
                signedBinary = MSAuthCodeSignerTest.signAndAssertOkPs1(inputFile,
                        WORKER_ID,
                        TS_ID, time,
                        useRFCTimestamper,
                        false, 1);
            } else {
                if (doResign) {
                    signedBinary =
                            MSAuthCodeSignerTest.signAndResignAssertOkPE(
                                    inputFile, WORKER_ID, TS_ID, time,
                                    useRFCTimestamper, false, 1);
                } else {
                    signedBinary =
                            MSAuthCodeSignerTest.signAndAssertOk(inputFile,
                                    WORKER_ID,
                                    TS_ID, time,
                                    useRFCTimestamper,
                                    false, 1);
                }
            }

            // Execute signtool.exe
            ComplianceTestUtils.ProcResult res =
                    ComplianceTestUtils.execute(signtoolCommand, "verify", "/pa", "/v", signedBinary.getAbsolutePath());
            LOG.debug("Result:\n" + ComplianceTestUtils.toString(res.getOutput()));
            LOG.debug("Errors:\n" + res.getErrorMessage());
            Assert.assertEquals("result: " + res.getErrorMessage(), 0, res.getExitValue());
        } finally {
            if (signedBinary != null) {
                signedBinary.delete();
            }
            helper.removeWorker(WORKER_ID);
            helper.removeWorker(TS_ID);

            LOG.info("=========================================\n\n");
        }
    }

    private void signThenVerifyInternalClientHashing(final boolean doResign)
            throws Exception {
        LOG.info("========= Testing signThenVerifyInternalClientHashing: " + inputFile + " =========");

        File signedBinary = null;
        File tempReSignedBinary = null;
        try {

            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            helper.addTimeStampSigner(TS_ID, TS_NAME, true);
            helper.addMSAuthCodeCMSSigner(WORKER_ID, WORKER_NAME_CMS, true);
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "ALLOW_CLIENTSIDEHASHING_OVERRIDE", "true");
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256");
            helper.getWorkerSession().setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            helper.getWorkerSession().setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            helper.getWorkerSession().reloadConfiguration(TS_ID);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);

            if (inputFile.getName().endsWith(".msi")) {
                /* as a work-around for a POI bug when using Java 9+ on
                 * Windows, fork a new process to avoid stale file handles.
                 */
                signedBinary = File.createTempFile("signed", "msi");
                final String signClientCmd =
                        PathUtil.getAppHome().getAbsolutePath() + File.separator +
                                "bin" + File.separator + "signclient.cmd";
                ComplianceTestUtils.ProcResult res =
                        ComplianceTestUtils.execute(signClientCmd,
                                "signdocument",
                                "-workerid",
                                Integer.toString(WORKER_ID),
                                "-clientside",
                                "-digestalgorithm",
                                digestAlgorithm,
                                "-infile",
                                inputFile.getAbsolutePath(),
                                "-outfile",
                                signedBinary.getAbsolutePath());
                LOG.debug("SignClient Result:\n" + ComplianceTestUtils.toString(res.getOutput()));
                Assert.assertEquals("result: " + res.getErrorMessage(), 0, res.getExitValue());

                if (doResign){
                    tempReSignedBinary = File.createTempFile("resigned", "msi");
                    res = ComplianceTestUtils.execute(signClientCmd,
                            "signdocument",
                            "-workerid",
                            Integer.toString(WORKER_ID),
                            "-clientside",
                            "-digestalgorithm",
                            digestAlgorithm,
                            "-infile",
                            signedBinary.getAbsolutePath(),
                            "-outfile",
                            tempReSignedBinary.getAbsolutePath());
                    Assert.assertEquals("result: " + res.getErrorMessage(),0, res.getExitValue());
                    signedBinary = tempReSignedBinary;
                }

            } else if (inputFile.getName().endsWith(".ps1")
                    || inputFile.getName().endsWith(".psd1")
                    || inputFile.getName().endsWith(".psm1")) {
                signedBinary = MSAuthCodeSignerTest.signAndAssertOkPs1(inputFile,
                        WORKER_ID,
                        TS_ID, time,
                        true,
                        true, 1);
            } else {
                if (doResign) {
                    signedBinary =
                            MSAuthCodeSignerTest.signAndResignAssertOkPE(
                                    inputFile, WORKER_ID, TS_ID, time, true,
                                    true, 1);
                } else {
                    signedBinary =
                            MSAuthCodeSignerTest.signAndAssertOk(inputFile,
                                    WORKER_ID,
                                    TS_ID, time,
                                    true,
                                    true, 1);
                }
            }

            // Execute signtool.exe
            ComplianceTestUtils.ProcResult res =
                    ComplianceTestUtils.execute(signtoolCommand, "verify", "/pa", "/v", signedBinary.getAbsolutePath());
            LOG.debug("Result:\n" + ComplianceTestUtils.toString(res.getOutput()));
            LOG.debug("Errors:\n" + res.getErrorMessage());
            Assert.assertEquals("result: " + res.getErrorMessage(), 0, res.getExitValue());
        } finally {
            if (signedBinary != null) {
                signedBinary.delete();
            }
            helper.removeWorker(WORKER_ID);
            helper.removeWorker(TS_ID);
            
            LOG.info("=========================================\n\n");
        }
    }

    /**
     * First signs and checks a binary and then invokes "signtool.exe verify"
     * on it.
     * The test succeeds if the exist code from the process is 0.
     * @throws Exception 
     */
    @Test
    public void signThenVerify() throws Exception {
        signThenVerifyInternal(false, false);
    }

    /**
     * First signs and checks a binary and then invokes "signtool.exe verify"
     * on it.
     * The test succeeds if the exist code from the process is 0.
     * This test uses an RFC#3161-compliant time stamp signer.
     *
     * @throws Exception 
     */
    @Test
    public void signThenVerifyRFCTimestamp() throws Exception {
        signThenVerifyInternal(true, false);
    }
 
    /**
     * First signs and checks a binary, then resigns the signed binary
     * with a new signature, and then invokes "signtool.exe verify"
     * on it.
     * The test succeeds if the exist code from the process is 0.
     * This test uses an RFC#3161-compliant time stamp signer.
     *
     * @throws Exception 
     */
    @Test
    public void resignThenVerifyRFCTimestamp() throws Exception {
        signThenVerifyInternal(true, true);
    }
    
    /**
     * First hashes on client side and signs and then invokes "signtool.exe verify
     * on it.
     * 
     * @throws Exception 
     */
    @Test
    public void signThenVerifyClientHashing() throws Exception {
        signThenVerifyInternalClientHashing(false);
    }

    /**
     * First hashes on client side and signs, then resigns the resulting binary
     * again to add a second signature (also using clien-side),
     * and then invokes "signtool.exe verify on it.
     * 
     * @throws Exception 
     */
    @Test
    public void resignThenVerifyClientHashing() throws Exception {
        signThenVerifyInternalClientHashing(true);
    }
}
