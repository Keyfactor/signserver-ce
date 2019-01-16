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
    
    private final File inputFile;
    
    private static final int WORKER_ID = 8901;
    private static final String WORKER_NAME = "TestAuthenticodeSigner";
    private static final String WORKER_NAME_CMS = "TestAuthenticodeCMSSigner";
    private static final int TS_ID = 8902;
    private static final String TS_NAME = "TestAuthenticodeTimeStampSigner";
    
    private final ModulesTestCase helper = new ModulesTestCase();
    
    public MSAuthCodeWinSigntoolComplianceTest(final File inputFile, final String title) {
        this.inputFile = inputFile;
    }
    
    @Parameterized.Parameters(name = "{1}")
    public static Collection<Object[]> generateData() throws FileNotFoundException {
        final LinkedList<Object[]> data = new LinkedList<>();
        
        File folder = new File(PathUtil.getAppHome(), "authenticode-test-files");
        
        if (folder.exists()) {
            for (File file : folder.listFiles()) {
                data.add(new Object[] {
                   file, file.getName()
                });
            }
        } else {
            LOG.error("Folder with portable executable does not exist so not running any tests: " + folder.getAbsolutePath());
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
            helper.addMSAuthCodeSigner(WORKER_ID, WORKER_NAME, true);
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            if (useRFCTimestamper) {
                helper.getWorkerSession().setWorkerProperty(WORKER_ID, "TIMESTAMP_FORMAT", "RFC3161");
            }
            helper.getWorkerSession().setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            helper.getWorkerSession().setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            helper.getWorkerSession().reloadConfiguration(TS_ID);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);
            
            if (inputFile.getName().endsWith(".msi")) {
                signedBinary =
                        MSAuthCodeSignerTest.signAndAssertOkMSI(inputFile,
                                                                WORKER_ID, TS_ID,
                                                                time,
                                                                useRFCTimestamper,
                                                                false);
            } else {
                signedBinary = MSAuthCodeSignerTest.signAndAssertOk(inputFile,
                                                                    WORKER_ID,
                                                                    TS_ID, time,
                                                                    useRFCTimestamper,
                                                                    false);
            }

            // Execute signtool.exe
            ComplianceTestUtils.ProcResult res =
                    ComplianceTestUtils.execute("signtool.exe", "verify", "/pa", "/v", signedBinary.getAbsolutePath());
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
                signedBinary =
                        MSAuthCodeSignerTest.signAndAssertOkMSI(inputFile,
                                                                WORKER_ID, TS_ID,
                                                                time,
                                                                true,
                                                                true);
            } else {
                signedBinary = MSAuthCodeSignerTest.signAndAssertOk(inputFile,
                                                                    WORKER_ID,
                                                                    TS_ID, time,
                                                                    true,
                                                                    true);
            }

            // Execute signtool.exe
            ComplianceTestUtils.ProcResult res =
                    ComplianceTestUtils.execute("signtool.exe", "verify", "/pa", "/v", signedBinary.getAbsolutePath());
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
        signThenVerifyInternal(false);
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
        signThenVerifyInternal(true);
    }
    
    /**
     * First hashes on client side and signs and then invokes "signtool.exe verify
     * on it.
     * 
     * @throws Exception 
     */
    @Test
    public void signThenVerifyClientHashing() throws Exception {
        signThenVerifyInternalClientHashing();
    }
}
