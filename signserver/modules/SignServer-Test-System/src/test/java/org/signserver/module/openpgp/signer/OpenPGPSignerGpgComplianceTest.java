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
package org.signserver.module.openpgp.signer;

import static junit.framework.TestCase.assertTrue;
import org.apache.log4j.Logger;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.signserver.client.cli.ClientCLI;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ComplianceTestUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * Compliance test running GPG to verify signatures created by the 
 * OpenPGPSigner.
 *
 * These tests can be disabled by setting the test.gpg.enabled test
 * configuration parameter to false for test environments where the gpg2
 * CLI tool is not available.
 *
 * @author Markus Kilås
 * @author Marcus Lundblad
 * @version $Id: TimeStampSignerOpenSslComplianceTest.java 9042 2018-01-18 10:16:57Z malu9369 $
 */
public class OpenPGPSignerGpgComplianceTest {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(OpenPGPSignerGpgComplianceTest.class);
    private static final String GPG_ENABLED = "test.gpg.enabled";
    
    private final ModulesTestCase helper = new ModulesTestCase();
    private static final CLITestHelper CLI = new CLITestHelper(ClientCLI.class);

    @Before
    public void setUpTest() {
        final boolean enabled = Boolean.valueOf(helper.getConfig().getProperty(GPG_ENABLED));
        Assume.assumeTrue("GPG enabled", enabled);
    }
    
    /**
     * Test that the command "gpg2 --version" prints a reasonable message.
     * And log the version string, so that it's visible in the stdout from the
     * test.
     * 
     * @throws Exception 
     */
    @Test
    public void testGpgVersion() throws Exception {
        final ComplianceTestUtils.ProcResult res = 
                ComplianceTestUtils.execute("gpg2", "--version");
        final String output = ComplianceTestUtils.toString(res.getOutput());
        
        assertTrue("Contains GPG message", output.startsWith("gpg (GnuPG)"));
        LOG.info("GPG version output: " + output);
    }
    
}
