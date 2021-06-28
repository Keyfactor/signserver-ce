/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.test.platform;

import java.io.File;
import org.apache.log4j.Logger;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.signserver.common.util.PathUtil;
import org.signserver.testutils.ComplianceTestUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests to verify that the SignServer application has been started.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class BasicStartupAdminCliTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(BasicStartupAdminCliTest.class);
    
    /**
     * Invokes "bin/signserver getstatus brief all" and checks that the CLI
     * was able to connect to the server.
     * @throws Exception 
     */
    @Test
    public void testGetStatusFromAdminCLI() throws Exception{
        LOG.info("testGetStatusFromAdminCLI");
        
        String signServerCLI;
        if (ModulesTestCase.isWindows()) {
            signServerCLI = PathUtil.getAppHome() + File.separator + "bin" + File.separator + "signserver.cmd";
        } else {
            signServerCLI = PathUtil.getAppHome() + File.separator + "bin" + File.separator + "signserver";
        }
        
        ComplianceTestUtils.ProcResult result = ComplianceTestUtils.execute(signServerCLI, "getstatus", "brief", "all");
        LOG.debug("Process Error message: " + result.getErrorMessage());
        LOG.debug("Process Output:" + String.join("\n", result.getOutput()));
        
        assertTrue("Version of server printed: " + result.getOutput(), result.getOutput().stream().anyMatch((s) -> {
            return s.startsWith("Current version of server is"); 
        }));
        
    }
}
