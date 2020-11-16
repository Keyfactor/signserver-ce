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
package org.signserver.server.signers;

import java.nio.charset.StandardCharsets;
import java.util.List;import static junit.framework.TestCase.assertEquals;
import org.apache.log4j.Logger;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.StaticWorkerStatus;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatusInfo.Entry;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionRemote;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests for the QosStatusWorker.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class QoSStatusWorkerTest {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(QoSStatusWorkerTest.class);

    private static final int WORKERID = 1000;
    private static final String WORKERNAME = "TestQoSStatusWorker";

    private static final ModulesTestCase modulesTestCase = new ModulesTestCase();
    private static final CLITestHelper clientCLI = modulesTestCase.getClientCLI();
    private static final WorkerSessionRemote workerSession =
            modulesTestCase.getWorkerSession();
    private static final GlobalConfigurationSessionRemote globalSession =
            modulesTestCase.getGlobalSession();
    private static final ProcessSessionRemote processSession =
            modulesTestCase.getProcessSession();

    @BeforeClass
    public static void setupClass() throws Exception {
        modulesTestCase.addDummySigner("org.signserver.server.signers.QoSStatusWorker",
                                       null, WORKERID, WORKERNAME, null, null,
                                       null);
        // unset enabled and max priority level parameters to get default behaviour
        globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                     "QOS_FILTER_ENABLED");
        globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                     "QOS_MAX_PRIORITY");
    }

    /**
     * Test that default behavior is shown that the filter is not enabled.
     *
     * @throws Exception 
     */
    @Test
    public void testDefaultEnabledFalse() throws Exception {
        // check the getStatus() output
        final StaticWorkerStatus status =
                (StaticWorkerStatus) workerSession.getStatus(new WorkerIdentifier(WORKERID));
        final List<Entry> briefEntries = status.getInfo().getBriefEntries();

        // there should only be one entry indicating the filter is not enabled
        assertEquals("One status entry", 1, briefEntries.size());
        assertEquals("Status entry" , new Entry("Filter enabled", "false"),
                     briefEntries.get(0));

        // check the parsable process output
        GenericSignRequest request = new GenericSignRequest(200, new byte[0]);
        final RemoteRequestContext context = new RemoteRequestContext();

        GenericSignResponse response =
                    (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKERID), request, context);
        final byte[] data = response.getProcessedData();

        final String output = new String(data, StandardCharsets.UTF_8);
        final String[] lines = output.split("\n");
        
        assertEquals("One line in the response: " + output, 1, lines.length);
        assertEquals("Output: " + output, "FILTER_ENABLED=false", lines[0]);
    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        modulesTestCase.removeWorker(WORKERID);
        globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                     "QOS_FILTER_ENABLED");
        globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                     "QOS_MAX_PRIORITY");
    }
}
