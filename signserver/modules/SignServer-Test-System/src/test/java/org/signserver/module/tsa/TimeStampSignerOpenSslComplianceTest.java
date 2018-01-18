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
package org.signserver.module.tsa;

import java.io.File;
import static junit.framework.TestCase.assertTrue;
import org.apache.log4j.Logger;
import static org.junit.Assert.assertEquals;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.signserver.client.cli.ClientCLI;
import org.signserver.common.util.PathUtil;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ComplianceTestUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * Compliance test running OpenSSL to verify timestamps signed by SignServer.
 * These tests can be disabled by setting the test.openssl.enabled test
 * configuration parameter to false for test environments where the openssl
 * CLI tool is not available.
 * OpenSSL doesn't support RFC#5816, so for the time being run these tests
 * with CERTIFICATE_DIGEST_ALGORITHM=SHA1.
 * https://github.com/openssl/openssl/issues/2119
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class TimeStampSignerOpenSslComplianceTest {
    /** Logger for this class */
    private static final Logger LOG =
            Logger.getLogger(TimeStampSignerOpenSslComplianceTest.class);
    private static final String OPENSSL_ENABLED = "test.openssl.enabled";
    
    private final ModulesTestCase helper = new ModulesTestCase();
    private static final CLITestHelper cli = new CLITestHelper(ClientCLI.class);
    
    private static final String ALIAS_RSA_ROOT = "ts00001";
    private static final String ALIAS_ECDSA_ROOT = "ts00002";
    private static final String ALIAS_RSA_SUB = "ts00003";
    
    @Before
    public void setUpTest() {
        final boolean enabled = Boolean.valueOf(helper.getConfig().getProperty(OPENSSL_ENABLED));
        Assume.assumeTrue("OpenSSL enabled", enabled);
    }
    
    /**
     * Test that the command "openssl version" prints a reasonable message.
     * And log the version string, so that it's visible in the stdout from the
     * test.
     * 
     * @throws Exception 
     */
    @Test
    public void testOpenSSLVersion() throws Exception {
        final ComplianceTestUtils.ProcResult res = 
                ComplianceTestUtils.execute("openssl", "version");
        final String output = ComplianceTestUtils.toString(res.getOutput());
        
        assertTrue("Contains OpenSSL message", output.startsWith("OpenSSL"));
        LOG.info("OpenSSL version output: " + output);
    }
    
    /**
     * Test verifying a timestamp signed using a certificate issued directly
     * by a root CA using RSA.
     * 
     * @throws Exception 
     */
    @Test
    public void testVerificationRSAIssuedByRoot() throws Exception {
        verifyInternal(ALIAS_RSA_ROOT, "SHA256withRSA",
                       PathUtil.getAppHome() + "/res/test/dss10/DSSRootCA10.cacert.pem",
                       null);
    }
    
    /**
     * Test verifying a timestamp signed using a certificate issued directly
     * by a root CA using ECDS.
     * 
     * @throws Exception 
     */
    @Test
    public void testVerificationECDSAIssuedByRoot() throws Exception {
        verifyInternal(ALIAS_ECDSA_ROOT, "SHA256withECDSA",
                       PathUtil.getAppHome() + "/res/test/dss10/DSSRootCA10.cacert.pem",
                       null);
    }
    
    /**
     * Test verifying a timestamp signed using a certificate issued from
     * a sub CA using RSA.
     * 
     * @throws Exception 
     */
    @Test
    public void testVerificationRSAIssuedBySub() throws Exception {
        verifyInternal(ALIAS_RSA_SUB, "SHA256withRSA",
                       PathUtil.getAppHome() + "/res/test/dss10/DSSRootCA10.cacert.pem",
                       PathUtil.getAppHome() + "/res/test/dss10/DSSSubCA11.cacert.pem");
    }
        
    private void verifyInternal(final String alias, final String signatureAlgorithm,
                                final String caCertPath,
                                final String intermediateCaCertPath) throws Exception {    
        final int workerId = 42;
        final String workerName = "TimeStampSignerRSA";
        final File query = File.createTempFile("ts-query", "tsq");
        final File response = File.createTempFile("ts-response", "tsr");
        
        try {
            helper.addTimeStampSigner(workerId, workerName, alias, true);
            helper.getWorkerSession().setWorkerProperty(workerId, "SIGNATUREALGORITHM", signatureAlgorithm);
            helper.getWorkerSession().setWorkerProperty(workerId, "CERTIFICATE_DIGEST_ALGORITHM", "SHA1");
            helper.getWorkerSession().reloadConfiguration(workerId);
            
            assertEquals("Status code", ClientCLI.RETURN_SUCCESS,
                         cli.execute("timestamp", "-url",
                                     "http://localhost:8080/signserver/tsa?workerId=" +
                                     Integer.toString(workerId),
                                     "-instr", "foo",
                                     "-outreq", query.getAbsolutePath(),
                                     "-outrep", response.getAbsolutePath(),
                                     "-certreq"));

            final ComplianceTestUtils.ProcResult res;
            
            if (intermediateCaCertPath != null) {
                /* for some reason, OpenSSL fails to verify with the sub CA
                 * certificate as -CAfile and needs the root CA cert and the
                 * sub CA cert as "-untrusted"
                 */
                res = ComplianceTestUtils.execute("openssl", "ts", "-verify",
                                                  "-in", response.getAbsolutePath(),
                                                  "-queryfile", query.getAbsolutePath(),
                                                  "-CAfile", caCertPath,
                                                  "-untrusted", intermediateCaCertPath);
            } else {
                res = ComplianceTestUtils.execute("openssl", "ts", "-verify",
                                                  "-in", response.getAbsolutePath(),
                                                  "-queryfile", query.getAbsolutePath(),
                                                  "-CAfile", caCertPath);
            }
            final String output = ComplianceTestUtils.toString(res.getOutput());
            
            assertTrue("Verified: " + output, output.contains("Verification: OK"));
        } finally {
            helper.removeWorker(workerId);
        }
    }
}
