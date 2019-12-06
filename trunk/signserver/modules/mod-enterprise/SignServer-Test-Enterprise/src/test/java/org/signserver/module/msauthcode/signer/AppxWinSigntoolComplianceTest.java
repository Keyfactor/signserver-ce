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
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.util.PathUtil;
import org.signserver.server.FixedTimeSource;
import org.signserver.testutils.ComplianceTestUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * A parameterized system test signing each file provided in
 * SIGNSERVER_HOME/appx-test-files and executes signtool.exe to check that they
 * can be verified correctly.
 *
 * Note 1: This test requires appx files to manually be put in the test folder.
 * Note 2: This test requires Windows (because of signtool.exe).
 *
 * @author Vinay Singh
 * @version $Id$
 */
@SuppressWarnings("PMD.UnusedFormalParameter") // JUnit requires parameter in constructor
@RunWith(Parameterized.class)
public class AppxWinSigntoolComplianceTest {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(AppxWinSigntoolComplianceTest.class);

    private final File inputFile;
    private final String digestAlgorithm;

    private static final int WORKER_ID = 10901;
    private static final String WORKER_NAME = "TestAppxSigner";
    private static final String WORKER_NAME_CMS = "TestAppxCMSSigner";
    private static final int TS_ID = 10902;
    private static final String TS_NAME = "TestAppxTimeStampSigner";

    private final ModulesTestCase helper = new ModulesTestCase();

    public AppxWinSigntoolComplianceTest(final String title, final File inputFile, final String digestAlgorithm) {
        this.inputFile = inputFile;
        this.digestAlgorithm = digestAlgorithm;
    }

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> generateData() throws FileNotFoundException {
        final LinkedList<Object[]> data = new LinkedList<>();

        File folder = new File(PathUtil.getAppHome(), "appx-test-files");
        // final String[] digestAlgorithms = new String[] { "SHA-256", "SHA-384", "SHA-512" }; 
        final String[] digestAlgorithms = new String[]{"SHA-256"};   // As of now, test with SHA-256 only

        if (folder.exists()) {
            for (File file : folder.listFiles()) {

                for (String algorithm : digestAlgorithms) {
                    data.add(new Object[]{
                        file.getName() + "-" + algorithm, file, algorithm
                    });
                }
            }
        } else {
            LOG.error("Folder with appx files does not exist so not running any tests: " + folder.getAbsolutePath());
        }

        return data;
    }

    private void signThenVerifyInternal(final boolean useRFCTimestamper)
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
            helper.addAppxSigner(WORKER_ID, WORKER_NAME, true);
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

            signedBinary = MSAuthCodeSignerTest.signAndAssertOkAPPX(inputFile,
                    WORKER_ID,
                    TS_ID, time,
                    useRFCTimestamper,
                    false,
                    helper.getWorkerSession().getSignerCertificate(new WorkerIdentifier(WORKER_ID)));

            // Execute signtool.exe
            ComplianceTestUtils.ProcResult res
                    = ComplianceTestUtils.execute("signtool.exe", "verify", "/pa", "/v", signedBinary.getAbsolutePath());
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

    private void signThenVerifyInternalClientHashing()
            throws Exception {
        LOG.info("========= Testing signThenVerifyInternalClientHashing: " + inputFile + " =========");

        File signedBinary = null;
        try {

            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            helper.addTimeStampSigner(TS_ID, TS_NAME, true);
            helper.addAppxCMSSigner(WORKER_ID, WORKER_NAME_CMS, true);
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "ALLOW_CLIENTSIDEHASHING_OVERRIDE", "true");
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256");
            helper.getWorkerSession().setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            helper.getWorkerSession().setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            helper.getWorkerSession().reloadConfiguration(TS_ID);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);

            signedBinary = MSAuthCodeSignerTest.signAndAssertOkAPPX(inputFile,
                    WORKER_ID,
                    TS_ID, time,
                    true,
                    true,
                    helper.getWorkerSession().getSignerCertificate(new WorkerIdentifier(WORKER_ID)));

            // Execute signtool.exe
            ComplianceTestUtils.ProcResult res
                    = ComplianceTestUtils.execute("signtool.exe", "verify", "/pa", "/v", signedBinary.getAbsolutePath());
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
     * First signs and checks a binary and then invokes "signtool.exe verify" on
     * it. The test succeeds if the exist code from the process is 0.
     *
     * @throws Exception
     */
    @Test
    public void signThenVerify() throws Exception {
        signThenVerifyInternal(false);
    }

    /**
     * First signs and checks a binary and then invokes "signtool.exe verify" on
     * it. The test succeeds if the exist code from the process is 0. This test
     * uses an RFC#3161-compliant time stamp signer.
     *
     * @throws Exception
     */
    @Test
    public void signThenVerifyRFCTimestamp() throws Exception {
        signThenVerifyInternal(true);
    }

    /**
     * First hashes on client side and signs and then invokes "signtool.exe
     * verify on it.
     *
     * @throws Exception
     */
    @Test
    public void signThenVerifyClientHashing() throws Exception {
        signThenVerifyInternalClientHashing();
    }
}
