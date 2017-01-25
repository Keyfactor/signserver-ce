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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.signserver.common.util.PathUtil;
import org.signserver.server.FixedTimeSource;
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
        LOG.info("========= Testing: " + inputFile + " =========");
        
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
                                                                useRFCTimestamper);
            } else {
                signedBinary = MSAuthCodeSignerTest.signAndAssertOk(inputFile,
                                                                    WORKER_ID,
                                                                    TS_ID, time,
                                                                    useRFCTimestamper);
            }

            // Execute signtool.exe
            ProcResult res = execute("signtool.exe", "verify", "/pa", "/v", signedBinary.getAbsolutePath());
            LOG.debug("Result:\n" + toString(res.getOutput()));
            LOG.debug("Errors:\n" + res.errorMessage);
            Assert.assertEquals("result: " + res.errorMessage, 0, res.exitValue);
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
    
    private String toString(List<String> output) {
        final StringBuilder sb = new StringBuilder();
        for (String s : output) {
            sb.append(s).append("\n");
        }
        return sb.toString();
    }
    
    private class ProcResult {
        private final int exitValue;
        private final String errorMessage;
        private final List<String> output;
        
        public ProcResult(int exitValue, String errorMessage, List<String> output) {
            this.exitValue = exitValue;
            this.errorMessage = errorMessage;
            this.output = output;
        }
        
        public int getExitValue() {
            return exitValue;
        }
        
        public String getErrorMessage() {
            return errorMessage;
        }
        
        public List<String> getOutput() {
            return output;
        }
    }
    
    private ProcResult execute(String... arguments) throws IOException {
        Process proc;
        BufferedReader stdIn = null;
        BufferedReader errIn = null;
        OutputStream stdOut = null;

        try {
            Runtime runtime = Runtime.getRuntime();

            proc = runtime.exec(arguments);
            stdIn = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            errIn = new BufferedReader(new InputStreamReader(proc.getErrorStream()));
            stdOut = proc.getOutputStream();

            List<String> lines = new LinkedList<>();
            String line;
            while ((line = stdIn.readLine()) != null) {
                lines.add(line);
            }

            StringBuilder errBuff = new StringBuilder();
            while ((line = errIn.readLine()) != null) {
                errBuff.append(line).append("\n");
            }
            try {
                proc.waitFor();
                return new ProcResult(proc.exitValue(), errBuff.toString(), lines);
            } catch (InterruptedException ex) {
                LOG.error("Command interrupted", ex);
                return new ProcResult(-1, errBuff.toString(), lines);
            }
        } finally {
            if (stdOut != null) {
                try {
                    stdOut.close();
                } catch (IOException ignored) {} // NOPMD
            }
            if (stdIn != null) {
                try {
                    stdIn.close();
                } catch (IOException ignored) {} // NOPMD
            }
            if (errIn != null) {
                try {
                    errIn.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }
    
}
