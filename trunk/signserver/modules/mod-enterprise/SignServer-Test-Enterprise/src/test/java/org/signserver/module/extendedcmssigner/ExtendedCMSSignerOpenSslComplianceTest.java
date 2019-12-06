/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.extendedcmssigner;

import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Date;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import org.junit.Assume;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.client.cli.ClientCLI;
import org.signserver.common.util.PathUtil;
import org.signserver.server.FixedTimeSource;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ComplianceTestUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * Compliance test running OpenSSL to verify PKCS#7 signed with the
 * ExtendedCMSSigner.
 * These tests can be disabled by setting the test.openssl.enabled test
 * configuration parameter to false for test environments where the openssl
 * CLI tool is not available.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ExtendedCMSSignerOpenSslComplianceTest {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(ExtendedCMSSignerOpenSslComplianceTest.class);
    
    private static final int WORKER_ID = 8901;
    private static final String WORKER_NAME = "TestExtendedCMSSigner";
    private static final int TS_ID = 8902;
    private static final String TS_NAME = "TestTimeStampSigner";
    
    private static final String OPENSSL_ENABLED = "test.openssl.enabled";
    
    private final ModulesTestCase helper = new ModulesTestCase();
    private static final CLITestHelper cli = new CLITestHelper(ClientCLI.class);

    @Before
    public void setUpTest() {
        final boolean enabled = Boolean.valueOf(helper.getConfig().getProperty(OPENSSL_ENABLED));
        Assume.assumeTrue("OpenSSL enabled", enabled);
    }
    
    @Test
    public void testSignAndVerifyServerside() throws Exception {
        signAndVerifyServerside(false);
    }
    
    @Test
    public void testSignAndVerifyServersideTimestamping() throws Exception {
        signAndVerifyServerside(true);
    }
    
    @Test
    public void testSignAndVerifyClientside() throws Exception {
        signAndVerifyClientside(false);
    }
    
    @Test
    public void testSignAndVerifyClientsideTimestamping() throws Exception {
        signAndVerifyClientside(true);
    }
    
    private void signAndVerifyServerside(final boolean timestamping)
            throws Exception {
        LOG.info("========= Testing signAndVerifyServerside =========");
        signAndVerify(timestamping, false);
    }
    
    private void signAndVerifyClientside(final boolean timestamping)
            throws Exception {
        LOG.info("========= Testing signAndVerifyClientsside =========");
        signAndVerify(timestamping, true);
    }
    
    private void signAndVerify(final boolean timestamping,
                               final boolean clientside) throws Exception {
        try {
            final File signedFile = File.createTempFile("test-file", ".signed");
            final File contentFile = File.createTempFile("content", ".txt");

            helper.addExtendedCMSSigner(WORKER_ID, WORKER_NAME, true);
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "SIGNATUREALGORITHM", "SHA256withRSA");

            if (timestamping) {
                final Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out

                helper.addTimeStampSigner(TS_ID, TS_NAME, true);
                helper.getWorkerSession().setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
                helper.getWorkerSession().setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
                helper.getWorkerSession().setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
                helper.getWorkerSession().reloadConfiguration(TS_ID);
            }

            helper.getWorkerSession().reloadConfiguration(WORKER_ID);

            if (clientside) {
                final MessageDigest md = MessageDigest.getInstance("SHA-256");
                final byte[] hashData = md.digest("foo".getBytes());
                final File inputFile = File.createTempFile("hash", ".data");

                FileUtils.writeByteArrayToFile(inputFile, hashData);
                FileUtils.writeByteArrayToFile(contentFile, "foo".getBytes());

                helper.getWorkerSession().setWorkerProperty(WORKER_ID, "CLIENTSIDEHASHING", "true");
                helper.getWorkerSession().setWorkerProperty(WORKER_ID, "ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256");
                helper.getWorkerSession().reloadConfiguration(WORKER_ID);

                assertEquals("Status code", ClientCLI.RETURN_SUCCESS,
                             cli.execute("signdocument", "-workerid",
                                         Integer.toString(WORKER_ID),
                                         "-infile", inputFile.getAbsolutePath(),
                                         "-outfile", signedFile.getAbsolutePath(),
                                         "-metadata", "CLIENTSIDE_HASHDIGESTALGORITHM=SHA-256"));
            } else {
                assertEquals("Status code", ClientCLI.RETURN_SUCCESS,
                             cli.execute("signdocument", "-workerid",
                                         Integer.toString(WORKER_ID), "-data", "foo",
                                         "-outfile", signedFile.getAbsolutePath()));
            }

            // execute openssl
            try {
                final ComplianceTestUtils.ProcResult res;
                final String signerCertPath = PathUtil.getAppHome() + "/res/test/dss10/dss10_signer1.pem";
                final String caCertPath = PathUtil.getAppHome() + "/res/test/dss10/DSSRootCA10.cacert.pem";

                if (clientside) {
                    res = ComplianceTestUtils.execute("openssl", "cms", "-verify",
                                                      "-in", signedFile.getAbsolutePath(),
                                                      "-inform", "DER",
                                                      "-content", contentFile.getAbsolutePath(),
                                                      "-signer", signerCertPath,
                                                      "-CAfile", caCertPath);
                } else {
                    res = ComplianceTestUtils.execute("openssl", "cms", "-verify",
                                                      "-in", signedFile.getAbsolutePath(),
                                                      "-inform", "DER",
                                                      "-signer", signerCertPath,
                                                      "-CAfile", caCertPath);
                }

                final String output = ComplianceTestUtils.toString(res.getOutput());
                final String error = res.getErrorMessage();

                LOG.debug("Result:\n" + output);
                LOG.debug("Errors:\n" + error);
                assertEquals("result", 0, res.getExitValue());
                // status is printed on stderr
                assertEquals("Verified", "Verification successful\n", error);
                // ComplianceTestUtils.toString appends newlines after each output line
                assertEquals("Content", "foo\n", output);
            } catch (IOException e) {
                fail("Could not execute openssl, disable running the tests by setting test.openssl.enabled=false in test-config.properties");
            }

        } finally {
            helper.removeWorker(WORKER_ID);
            if (timestamping) {
                helper.removeWorker(TS_ID);
            }
        }
    }
}
