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
import java.util.Date;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.signserver.common.util.PathUtil;
import org.signserver.server.FixedTimeSource;
import org.signserver.testutils.ComplianceTestUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests timestamping a portable executable using MS SDK's signtool command
 * using a TSA provided by SignServer.
 * 
 * Note: this test requires Windows to run.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class MSAuthCodeWinSigntoolTimestampingTest {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(MSAuthCodeWinSigntoolTimestampingTest.class);
    
    private static final int TS_ID = 8902;
    private static final String TS_NAME = "TestAuthenticodeTimeStampSigner";
    
    private final ModulesTestCase helper = new ModulesTestCase();
    
    /**
     * Try timestamping an already-signed binary using MS SDK signtool and
     * an Authenticode time stamp signer in SignServer.
     * 
     * @throws Exception 
     */
    @Test
    public void timestampAuthenticode() throws Exception {
        Assume.assumeTrue("Only runs on Windows",
                          System.getProperty("os.name").startsWith("Windows"));
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out
            
            helper.addMSTimeStampSigner(TS_ID, TS_NAME, true);
            helper.getWorkerSession().setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            helper.getWorkerSession().setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            helper.getWorkerSession().reloadConfiguration(TS_ID);
            
            // Execute signtool.exe
            final String exePath = PathUtil.getAppHome() + File.separator + "res" +
                                File.separator + "test" + File.separator +
                                "HelloPE-signed.exe";
            final String tsaUrl = "http://localhost:8080/signserver/tsa?workerName=" + TS_NAME;
            ComplianceTestUtils.ProcResult res = 
                    ComplianceTestUtils.execute("signtool.exe", "timestamp", "/t", tsaUrl, exePath);
            LOG.debug("Result:\n" + ComplianceTestUtils.toString(res.getOutput()));
            LOG.debug("Errors:\n" + res.getErrorMessage());
            Assert.assertEquals("result: " + res.getErrorMessage(), 0, res.getExitValue());
        } finally {
            helper.removeWorker(TS_ID);
        }
    }
}
