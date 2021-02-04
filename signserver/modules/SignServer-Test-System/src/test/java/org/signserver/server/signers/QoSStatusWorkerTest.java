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
import java.util.List;
import static junit.framework.TestCase.assertEquals;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.StaticWorkerStatus;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionRemote;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests for the QosStatusWorker.
 *
 * This only includes a test for the default, disabled case, due to synchronization /
 * timing issues with global configuration making it hard to get reliable
 * deterministic tests setting run-time behavior.
 * See QoSStatusWorkerUnitTest for tests excersizing the status and response
 * generations.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class QoSStatusWorkerTest {
    private static final int WORKERID = 1000;
    private static final String WORKERNAME = "TestQoSStatusWorker";

    private static final ModulesTestCase modulesTestCase = new ModulesTestCase();
    private static final WorkerSessionRemote workerSession =
            modulesTestCase.getWorkerSession();
    private static final GlobalConfigurationSessionRemote globalSession =
            modulesTestCase.getGlobalSession();
    private static final ProcessSessionRemote processSession =
            modulesTestCase.getProcessSession();

    static private final int CONFIG_CACHE_TIMEOUT = 10;
    
    @BeforeClass
    public static void setupClass() {
        modulesTestCase.addDummySigner("org.signserver.server.signers.QoSStatusWorker",
                                       null, WORKERID, WORKERNAME, null, null,
                                       null);
        // unset enabled and max priority level parameters to get default behaviour
        globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                     "QOS_FILTER_ENABLED");
        globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                     "QOS_MAX_REQUESTS");
        globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                     "QOS_MAX_PRIORITY");
    }

    /**
     * Test that default behavior is shown that the filter is not enabled.
     *
     * @throws Exception if an unexpected error occurs, such as failing to
     *                   set up dummy signer, or issues with EJB communication
     *                   sending requests to the app server
     */
    @Test
    public void defaultEnabledFalse() throws Exception {
        // given
        final boolean expectedEnabled = false;
        final int expectedEntries = 1;
        final int expectedMaxRequests = 0;
        final int expectedMaxPrio = 0;
        final int[] expectedQueueSizes = new int[0];

        // when
        final StaticWorkerStatus status =
                (StaticWorkerStatus) workerSession.getStatus(new WorkerIdentifier(WORKERID));
        final WorkerStatusInfo statusInfo = status.getInfo();

        // then
        assertWorkerStatusInfo(statusInfo, expectedEnabled, expectedEntries,
                expectedMaxRequests, expectedMaxPrio,
                expectedQueueSizes);

        // when
        final GenericSignRequest request = new GenericSignRequest(200, new byte[0]);
        final RemoteRequestContext context = new RemoteRequestContext();
        final GenericSignResponse response =
                    (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKERID), request, context);
        final byte[] data = response.getProcessedData();

        // then
        assertProcessOutput(data, expectedEnabled, expectedEntries,
                            expectedMaxRequests, expectedMaxPrio,
                            expectedQueueSizes);
    }

    /**
     * Test that enabling the filter gives expected status and process output
     * listing max requests, max priority level, and queue sizes.
     *
     * @throws Exception if an unexpected error occurs, such as failing to
     *                   set up dummy signer, or issues with EJB communication
     *                   sending requests to the app server
     */
    @Test
    public void filterEnabledDefaultMax() throws Exception {
        try {
            // given
            final boolean expectedEnabled = true;
            final int expectedEntries = 11;
            final int expectedMaxRequests = 10;
            final int expectedMaxPrio = 5;
            /* expect the queues should be empty, since we only send a single
             * request, but they should still be reported in the output
             */
            final int[] expectedQueueSizes = new int[] {0, 0, 0, 0, 0, 0};

            // when
            globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                      "QOS_FILTER_ENABLED", "true");
            // wait until old cached filter config has expired (with some margin)
            Thread.sleep(CONFIG_CACHE_TIMEOUT * 1000 + 1000);

            final StaticWorkerStatus status =
                    (StaticWorkerStatus) workerSession.getStatus(new WorkerIdentifier(WORKERID));
            final WorkerStatusInfo statusInfo = status.getInfo();

            // then
            assertWorkerStatusInfo(statusInfo, expectedEnabled,
                    expectedEntries, expectedMaxRequests,
                    expectedMaxPrio, expectedQueueSizes);
            
            // when
            final GenericSignRequest request = new GenericSignRequest(200, new byte[0]);
            final RemoteRequestContext context = new RemoteRequestContext();

            final GenericSignResponse response =
                        (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKERID), request, context);
            final byte[] data = response.getProcessedData();

            // then
            assertProcessOutput(data, expectedEnabled, expectedEntries,
                                expectedMaxRequests, expectedMaxPrio,
                                expectedQueueSizes);
        } finally {
            globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                        "QOS_FILTER_ENABLED");
            // wait until old cached filter config has expired (with some margin)
            Thread.sleep(CONFIG_CACHE_TIMEOUT * 1000 + 1000);
        }
    }
    
    @AfterClass
    public static void afterClass() {
        modulesTestCase.removeWorker(WORKERID);
        globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                     "QOS_FILTER_ENABLED");
        globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                     "QOS_MAX_REQUESTS");
        globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                     "QOS_MAX_PRIORITY");
    }

    /**
     * TODO: DSS-2247
     * For now keep these as helper methods duplicates in the system and unit
     * tests, as for now SignServer-Test-Utils already has a depency back to
     * this module, so moving it there to share them would introduce a
     * dependency loop.
     */

    /**
     * Assert worker status info matches expected values.
     *
     * @param status Worker status info given
     * @param expectedEnabled True if QoS status is expected to be enabled
     * @param expectedEntries Number of expected status entries
     * @param expectedMaxRequests Expected value for maximum requests status
     * @param expectedMaxPrio Expected value for maxium priority level status
     * @param expectedQueueSizes Array of expected queue sizes for subsequent
     *                           priority levels 0..max prio
     */
    private void assertWorkerStatusInfo(final WorkerStatusInfo status,
                                       final boolean expectedEnabled,
                                       final int expectedEntries,
                                       final int expectedMaxRequests,
                                       final int expectedMaxPrio,
                                       final int[] expectedQueueSizes) {
        final List<WorkerStatusInfo.Entry> briefEntries = status.getBriefEntries();

        assertEquals("Entries", expectedEntries, briefEntries.size());
        assertEquals("Enabled" ,
                     new WorkerStatusInfo.Entry("Filter enabled",
                                                expectedEnabled ?
                                                "true" : "false"),
                     briefEntries.get(0));

        if (expectedEnabled) {
            int position = 1;
            assertEquals("Max requests",
                         new WorkerStatusInfo.Entry("Maximum requests",
                                   Integer.toString(expectedMaxRequests)),
                         briefEntries.get(position));
            position++;
            assertEquals("Max prio",
                         new WorkerStatusInfo.Entry("Maximum priority level",
                                   Integer.toString(expectedMaxPrio)),
                         briefEntries.get(position));
            position++;
            
            assertEquals("Semaphore Queue Size Title", "Semaphore Queue Size", 
                    briefEntries.get(position).getTitle());
            position++;
            
            assertEquals("Semaphore Available Permits Title", 
                    "Semaphore Available Permits", briefEntries.get(position).getTitle());
            position++;

            for (int i = 0; i <= expectedMaxPrio; i++) {
                final WorkerStatusInfo.Entry entry = briefEntries.get(position + i);
                assertEquals("Title", "Queue size(" + i + ")", entry.getTitle());
                assertEquals("Value", Integer.toString(expectedQueueSizes[i]),
                             entry.getValue());
            }
        }
    }

    /**
     * Assert process output conforms to expected values.
     *
     * @param data Output from processData() called on a QoSStatusWorker instance
     * @param expectedEnabled True if QoS status is expected to be indicated
     *                        as enabled in the output
     * @param expectedEntries Expected number of entries (lines) in the output
     * @param expectedMaxRequests Expected maximum number of requests to be
     *                            specified in the output
     * @param expectedMaxPrio Expected maxiumum priority to be expected in
     *                        the output
     * @param expectedQueueSizes Array of expected queue sizes for subsequent
     *                           priority levels 0..max prio
     */
    private void assertProcessOutput(final byte[] data,
                                    final boolean expectedEnabled,
                                    final int expectedEntries,
                                    final int expectedMaxRequests,
                                    final int expectedMaxPrio,
                                    final int[] expectedQueueSizes) {
        final String output = new String(data, StandardCharsets.UTF_8);
        final String[] lines = output.split("\n");

        assertEquals("Lines in the output: " + output, expectedEntries,
                     lines.length);
        assertEquals("Enabled",
                     "FILTER_ENABLED=" + expectedEnabled,
                     lines[0]);

        if (expectedEnabled) {
            assertEquals("Max requests",
                         "MAX_REQUESTS=" + expectedMaxRequests,
                         lines[1]);
            assertEquals("Max prio", 
                         "MAX_PRIORITY_LEVEL=" + expectedMaxPrio,
                         lines[2]);

            for (int i = 0; i <= expectedMaxPrio; i++) {
                assertEquals("Queue size",
                             "QUEUE_SIZE(" + i + ")=" + expectedQueueSizes[i],
                             lines[i + 3]);
            }
        }
    }
}
