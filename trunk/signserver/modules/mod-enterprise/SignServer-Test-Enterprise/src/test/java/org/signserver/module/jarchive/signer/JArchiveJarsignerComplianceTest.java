/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.jarchive.signer;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;
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
 * SIGNSERVER_HOME/jarsigner-test-files and executes jarsigner to check
 * that they can be verified correctly.
 * 
 * Note 1: This test requires signed jar files manually be put in
 * the test folder.
 * Note 2: This test requires a JDK (because of jarsigner).
 *
 * @author Markus Kilås
 * @version $Id$
 */
@SuppressWarnings("PMD.UnusedFormalParameter") // JUnit requires parameter in constructor
@RunWith(Parameterized.class)
public class JArchiveJarsignerComplianceTest {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(JArchiveJarsignerComplianceTest.class);
    
    private static final int WORKER_ID = 8909;
    private static final int WORKER_CMS_ID = 8910;
    private static final String WORKER_NAME = "TestJArchiveSigner";
    private static final String WORKER_CMS_NAME = "TestJArchiveCMSSigner";
    private static final int TS_ID = 8908;
    private static final String TS_NAME = "TestTimeStampSigner";

    private final File inputFile;
    private final boolean useClientSide;
    private final String signatureAlgorithm;
    
    private final ModulesTestCase helper = new ModulesTestCase();
    
    public JArchiveJarsignerComplianceTest(final String title, final File inputFile, boolean useClientSide, final String signatureAlgorithm) {
        this.inputFile = inputFile;
        this.useClientSide = useClientSide;
        this.signatureAlgorithm = signatureAlgorithm;
    }
    
    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> generateData() throws FileNotFoundException {
        final LinkedList<Object[]> data = new LinkedList<>();
        
        File folder = new File(PathUtil.getAppHome(), "jarsigner-test-files");
        
        final ArrayList<String> signatureAlgoritms = new ArrayList<>();
        signatureAlgoritms.add("SHA1withRSA");
        signatureAlgoritms.add("SHA256withRSA");
        signatureAlgoritms.add("SHA1withECDSA");
        signatureAlgoritms.add("SHA256withECDSA");
        
        if (folder.exists()) {
            for (File file : folder.listFiles()) {
                for (String signatureAlgorithm : signatureAlgoritms) {
                    data.add(new Object[] {
                       file.getName() + "-serverSide-" + signatureAlgorithm, file, false, signatureAlgorithm
                    });
                    data.add(new Object[] {
                       file.getName() + "-clientSide-" + signatureAlgorithm, file, true, signatureAlgorithm
                    });
                }
            }
        } else {
            LOG.error("Folder with signed jars does not exist so not running any tests: " + folder.getAbsolutePath());
        }
        
        return data;
    }
    
    @Test
    public void testSignThenVerify() throws Exception {
        if (useClientSide) {
            signThenVerifyClientHashing();
        } else {
            signThenVerify();
        }
    }

    /**
     * First signs and checks a jar and then invokes "jarsigner verify -strict"
     * on it.
     * The test succeeds if the exist code from the process is 0.
     * @throws Exception 
     */
    private void signThenVerify() throws Exception {
        LOG.info("========= Testing signThenVerify: " + inputFile + " =========");
        final boolean clientSide = false;
        
        File signedFile = null;
        try {

            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            helper.addTimeStampSigner(TS_ID, TS_NAME, true);
            if (signatureAlgorithm.contains("withECDSA")) {
                helper.addJArchiveSignerECDSA(WORKER_ID, WORKER_NAME, true);
            } else {
                helper.addJArchiveSigner(WORKER_ID, WORKER_NAME, true);
            }
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "SIGNATUREALGORITHM", signatureAlgorithm);
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "TSA_DIGESTALGORITHM", "SHA-1");
            helper.getWorkerSession().setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            helper.getWorkerSession().setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            helper.getWorkerSession().setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            helper.getWorkerSession().reloadConfiguration(TS_ID);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);
            
            byte[] signedBinary = JArchiveSignerTest.signAndAssertOk(FileUtils.readFileToByteArray(inputFile),
                                                                     WORKER_ID,
                                                                     TS_ID, time,
                                                                     clientSide,
                                                                     new AlgorithmIdentifier(TSPAlgorithms.SHA1));
        
            signedFile = File.createTempFile("test-file", ".signed");
            FileUtils.writeByteArrayToFile(signedFile, signedBinary);
            
            // Execute signtool.exe
            ComplianceTestUtils.ProcResult res =
                    ComplianceTestUtils.execute("jarsigner", "-verify", "-strict", "-verbose", "-certs", signedFile.getAbsolutePath());
            String output = ComplianceTestUtils.toString(res.getOutput());
            LOG.debug("Result:\n" + output);
            LOG.debug("Errors:\n" + res.getErrorMessage());
            LOG.debug("Output:\n" + output);
            Assert.assertEquals("result: " + res.getErrorMessage() + "\n" + output, 0, res.getExitValue());
        Assert.assertFalse("Warning in output:\n" + output, output.contains("Warning"));
        } finally {
            if (signedFile != null) {
                signedFile.delete();
            }
            helper.removeWorker(WORKER_ID);
            helper.removeWorker(TS_ID);
            
            LOG.info("=========================================\n\n");
        }
    }
    
    /**
     * First signs and checks a jar and then invokes "jarsigner verify -strict"
     * on it.
     * The test succeeds if the exist code from the process is 0.
     * @throws Exception 
     */
    private void signThenVerifyClientHashing() throws Exception {
        LOG.info("========= Testing signThenVerifyClientHashing: " + inputFile + " =========");
        final boolean clientSide = true;
        
        File signedFile = null;
        try {

            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            helper.addTimeStampSigner(TS_ID, TS_NAME, true);
            if (signatureAlgorithm.contains("withECDSA")) {
                helper.addJArchiveCMSSignerECDSA(WORKER_CMS_ID, WORKER_CMS_NAME, true);
            } else {
                helper.addJArchiveCMSSigner(WORKER_CMS_ID, WORKER_CMS_NAME, true);
            }
            helper.getWorkerSession().setWorkerProperty(WORKER_CMS_ID, "TSA_WORKER", TS_NAME);
            helper.getWorkerSession().setWorkerProperty(WORKER_CMS_ID, "TSA_DIGESTALGORITHM", "SHA-1");
            helper.getWorkerSession().setWorkerProperty(WORKER_CMS_ID, "SIGNATUREALGORITHM", signatureAlgorithm);
            helper.getWorkerSession().setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            helper.getWorkerSession().setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            helper.getWorkerSession().setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            helper.getWorkerSession().reloadConfiguration(TS_ID);
            helper.getWorkerSession().reloadConfiguration(WORKER_CMS_ID);
            
            byte[] signedBinary = JArchiveSignerTest.signAndAssertOk(FileUtils.readFileToByteArray(inputFile),
                                                                     WORKER_CMS_ID,
                                                                     TS_ID, time,
                                                                     clientSide,
                                                                     new AlgorithmIdentifier(TSPAlgorithms.SHA1));
        
            signedFile = File.createTempFile("test-file", ".signed");
            FileUtils.writeByteArrayToFile(signedFile, signedBinary);
            
            // Execute signtool.exe
            ComplianceTestUtils.ProcResult res =
                    ComplianceTestUtils.execute("jarsigner", "-verify", "-strict", "-verbose", "-certs", signedFile.getAbsolutePath());
            String output = ComplianceTestUtils.toString(res.getOutput());
            LOG.debug("Result:\n" + output);
            LOG.debug("Errors:\n" + res.getErrorMessage());
            LOG.debug("Output:\n" + output);
            Assert.assertEquals("result: " + res.getErrorMessage() + "\n" + output, 0, res.getExitValue());
            Assert.assertFalse("Warning in output:\n" + output, output.contains("Warning"));
        } finally {
            if (signedFile != null) {
                signedFile.delete();
            }
            helper.removeWorker(WORKER_CMS_ID);
            helper.removeWorker(TS_ID);
            
            LOG.info("=========================================\n\n");
        }
    }
}
