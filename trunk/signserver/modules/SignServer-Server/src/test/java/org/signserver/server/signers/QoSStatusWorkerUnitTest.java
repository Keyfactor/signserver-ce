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
import org.junit.Test;
import org.signserver.common.qos.AbstractStatistics;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.WritableData;
import org.signserver.server.data.impl.ByteArrayReadableData;
import org.signserver.server.data.impl.TemporarlyWritableData;
import org.signserver.server.data.impl.UploadConfig;

/**
 * Unit tests for the QoSStatusWorker.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class QoSStatusWorkerUnitTest {

    private static final int WORKER_ID = 42;
    private static final int REQUEST_ID = 43;
    private static final String TRANSACTION_ID = "0000-100-1";

    /**
     * Test expected status and process output when QoS is disabled.
     *
     * @throws Exception 
     */
    @Test
    public void disabled() throws Exception {
        // given
        final boolean expectedEnabled = false;
        final int expectedMaxRequests = 0;
        final int expectedEntries = 1;
        final int expectedMaxPrio = 0;
        final int[] expectedQueueSizes = new int[0];
        final int expectedSemaphoreQueueLength = 6;
        final int expectedSemaphoreAvailablePermits = 2;

        final QoSStatusWorker instance = new QoSStatusWorker() {
            @Override
            AbstractStatistics getFilterStatistics() {
                return new MockedStatistics(expectedEnabled, 
                        expectedQueueSizes,
                        expectedMaxRequests,
                        expectedSemaphoreQueueLength,
                        expectedSemaphoreAvailablePermits);
            }  
        };

        instance.init(WORKER_ID, new WorkerConfig(), null, null);

        // when
        final WorkerStatusInfo status = instance.getStatus(null, null);

        // then
        assertWorkerStatusInfo(status, expectedEnabled, expectedEntries, 
                expectedMaxRequests, expectedMaxPrio,
                expectedQueueSizes,
                expectedSemaphoreQueueLength,
                expectedSemaphoreAvailablePermits);

        // when
        final ReadableData readable =
                new ByteArrayReadableData("".getBytes(),
                                          new UploadConfig().getRepository());
        final WritableData writable =
                new TemporarlyWritableData(false,
                                           new UploadConfig().getRepository());
        final RequestContext requestContext = new RequestContext();

        requestContext.put(RequestContext.TRANSACTION_ID, TRANSACTION_ID);
        instance.processData(new SignatureRequest(REQUEST_ID, readable, writable),
                             requestContext);

        // then
        assertProcessOutput(writable.toReadableData().getAsByteArray(),
                            expectedEnabled, expectedEntries,
                            expectedMaxRequests, expectedMaxPrio,
                            expectedQueueSizes);
    }

    /**
     * Test expected status and process output with enabled QoS.
     *
     * @throws Exception 
     */
    @Test
    public void enabled() throws Exception {
        // given
        final boolean expectedEnabled = true;
        final int expectedMaxRequests = 10;
        final int expectedEntries = 11;
        final int expectedMaxPrio = 5;
        final int[] expectedQueueSizes = new int[] {42, 3, 4, 5, 0, 0};
        final int expectedSemaphoreQueueLength = 7;
        final int expectedSemaphoreAvailablePermits = 1;

        final QoSStatusWorker instance = new QoSStatusWorker() {
            @Override
            AbstractStatistics getFilterStatistics() {
                return new MockedStatistics(expectedEnabled, 
                        expectedQueueSizes,
                        expectedMaxRequests,
                        expectedSemaphoreQueueLength,
                        expectedSemaphoreAvailablePermits);
            }  
        };

        instance.init(WORKER_ID, new WorkerConfig(), null, null);

        // when
        final WorkerStatusInfo status = instance.getStatus(null, null);

        // then
        assertWorkerStatusInfo(status, expectedEnabled, expectedEntries,
                expectedMaxRequests, expectedMaxPrio,
                expectedQueueSizes,
                expectedSemaphoreQueueLength,
                expectedSemaphoreAvailablePermits);

        // when
        final ReadableData readable =
                new ByteArrayReadableData("".getBytes(),
                                          new UploadConfig().getRepository());
        final WritableData writable =
                new TemporarlyWritableData(false,
                                           new UploadConfig().getRepository());
        final RequestContext requestContext = new RequestContext();

        requestContext.put(RequestContext.TRANSACTION_ID, TRANSACTION_ID);
        instance.processData(new SignatureRequest(REQUEST_ID, readable, writable),
                             requestContext);

        // then
        assertProcessOutput(writable.toReadableData().getAsByteArray(),
                            expectedEnabled, expectedEntries,
                            expectedMaxRequests, expectedMaxPrio,
                            expectedQueueSizes);
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
     * @param expectedSemaphoreQueueLength Queue length of semaphore
     * @param expectedSemaphoreAvailablePermits Available permits of semaphore
     */
    private void assertWorkerStatusInfo(final WorkerStatusInfo status,
                                       final boolean expectedEnabled,
                                       final int expectedEntries,
                                       final int expectedMaxRequests,
                                       final int expectedMaxPrio,
                                       final int[] expectedQueueSizes,
                                       final int expectedSemaphoreQueueLength,
                                       final int expectedSemaphoreAvailablePermits) {
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
            
            assertEquals("Semaphore Queue Size", 
                    new WorkerStatusInfo.Entry("Semaphore Queue Size", 
                            Integer.toString(expectedSemaphoreQueueLength)),
                    briefEntries.get(position));
            position++;
            
            assertEquals("Semaphore Available Permits", 
                    new WorkerStatusInfo.Entry("Semaphore Available Permits", 
                            Integer.toString(expectedSemaphoreAvailablePermits)),
                    briefEntries.get(position));
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
    
    private static class MockedStatistics extends AbstractStatistics {

        private final boolean enabled;
        private final int[] queueSizes;
        private final int maxRequests;
        private final int semaphoreQueueLength;
        private final int semaphoreAvailablePermits;

        public MockedStatistics(final boolean enabled,
                                       final int[] queueLengths,
                                       final int maxRequests,
                                       final int semaphoreQueueLength,
                                       final int semaphoreAvailablePermits) {
            this.enabled = enabled;
            this.queueSizes = queueLengths;
            this.maxRequests = maxRequests;
            this.semaphoreQueueLength = semaphoreQueueLength;
            this.semaphoreAvailablePermits = semaphoreAvailablePermits;
        }
        
        @Override
        public int getMaxPriorityLevel() {
            return queueSizes.length - 1;
        }

        @Override
        public int getMaxRequests() {
            return maxRequests;
        }

        @Override
        public int getQueueSizeForPriorityLevel(int priorityLevel) {
            return queueSizes[priorityLevel];
        }

        @Override
        public boolean isEnabled() {
            return enabled;
        }

        @Override
        public int getSemaphoreQueueLength() {
            return semaphoreQueueLength;
        }

        @Override
        public int getSemaphoreAvailablePermits() {
            return semaphoreAvailablePermits;
        }
    }
}

