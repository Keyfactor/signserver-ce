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
import junit.framework.TestCase;
import static junit.framework.TestCase.assertEquals;
import org.signserver.common.AbstractQoSFilterStatistics;
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
public class QoSStatusWorkerUnitTest extends TestCase {

    public void test01Disabled() throws Exception {
        final QoSStatusWorker instance = new QoSStatusWorker() {
            @Override
            AbstractQoSFilterStatistics getFilterStatistics() {
                return new MockQoSFilterStatistics();
            }  
        };

        instance.init(42, new WorkerConfig(), null, null);

        final WorkerStatusInfo status = instance.getStatus(null, null);

        checkWorkerStatusInfo(status, false, 1, 0, 0, null);

        final ReadableData readable =
                new ByteArrayReadableData("".getBytes(),
                                          new UploadConfig().getRepository());
        final WritableData writable =
                new TemporarlyWritableData(false,
                                           new UploadConfig().getRepository());
        final RequestContext requestContext = new RequestContext();

        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");
        instance.processData(new SignatureRequest(42, readable, writable),
                             requestContext);
        checkProcessOutput(writable.toReadableData().getAsByteArray(), false,
                           1, 0, 0, null);
    }

    public void test02Enabled() throws Exception {
        final int[] queueSizes = new int[]{42, 3, 4, 5, 0, 0};
        final QoSStatusWorker instance = new QoSStatusWorker() {
            @Override
            AbstractQoSFilterStatistics getFilterStatistics() {
                return new MockQoSFilterStatistics(queueSizes, 10);
            }  
        };

        instance.init(42, new WorkerConfig(), null, null);

        final WorkerStatusInfo status = instance.getStatus(null, null);

        checkWorkerStatusInfo(status, true, 9, 10, 5, queueSizes);

        final ReadableData readable =
                new ByteArrayReadableData("".getBytes(),
                                          new UploadConfig().getRepository());
        final WritableData writable =
                new TemporarlyWritableData(false,
                                           new UploadConfig().getRepository());
        final RequestContext requestContext = new RequestContext();

        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");
        instance.processData(new SignatureRequest(42, readable, writable),
                             requestContext);
        checkProcessOutput(writable.toReadableData().getAsByteArray(),
                           true, 9, 10, 5, queueSizes);
    }

    private void checkWorkerStatusInfo(final WorkerStatusInfo status,
                                       final boolean expectedEnabled,
                                       final int expectedEntries,
                                       final int expectedMaxRequests,
                                       final int expectedMaxPrio,
                                       final int[] expectedQueueSizes)
            throws Exception {
        final List<WorkerStatusInfo.Entry> briefEntries = status.getBriefEntries();

        assertEquals("Entries", expectedEntries, briefEntries.size());
        assertEquals("Enabled" ,
                     new WorkerStatusInfo.Entry("Filter enabled", expectedEnabled ? "true" : "false"),
                     briefEntries.get(0));

        if (expectedEnabled) {
            assertEquals("Max requests",
                         new WorkerStatusInfo.Entry("Maximum requests",
                                   Integer.toString(expectedMaxRequests)),
                         briefEntries.get(1));
            assertEquals("Max prio",
                         new WorkerStatusInfo.Entry("Maximum priority level",
                                   Integer.toString(expectedMaxPrio)),
                         briefEntries.get(2));

            for (int i = 0; i <= expectedMaxPrio; i++) {
                final WorkerStatusInfo.Entry entry = briefEntries.get(i + 3);
                assertEquals("Title", "Queue size(" + i + ")", entry.getTitle());
                assertEquals("Value", Integer.toString(expectedQueueSizes[i]), entry.getValue());
            }
        }
    }

    private void checkProcessOutput(final byte[] data,
                                    final boolean expectedEnabled,
                                    final int expectedEntries,
                                    final int expectedMaxRequests,
                                    final int expectedMaxPrio,
                                    final int[] expectedQueueSizes)
            throws Exception {
        final String output = new String(data, StandardCharsets.UTF_8);
        final String[] lines = output.split("\n");

        assertEquals("Lines in the output: " + output, expectedEntries,
                     lines.length);
        assertEquals("Enabled",
                     "FILTER_ENABLED=" + Boolean.toString(expectedEnabled),
                     lines[0]);

        if (expectedEnabled) {
            assertEquals("Max requests",
                         "MAX_REQUESTS=" + Integer.toString(expectedMaxRequests),
                         lines[1]);
            assertEquals("Max prio", 
                         "MAX_PRIORITY_LEVEL=" + Integer.toString(expectedMaxPrio),
                         lines[2]);

            for (int i = 0; i <= expectedMaxPrio; i++) {
                assertEquals("Queue size",
                             "QUEUE_SIZE(" + i + ")=" + expectedQueueSizes[i],
                             lines[i + 3]);
            }
        }
    }
    
    private static class MockQoSFilterStatistics extends AbstractQoSFilterStatistics {

        private final boolean enabled;
        private final int[] queueLengths;
        private final int maxRequests;

        public MockQoSFilterStatistics() {
            queueLengths = null;
            maxRequests = 10;
            enabled = false;
        }
        
        public MockQoSFilterStatistics(final int[] queueLengths,
                                       final int maxRequests) {
            this.queueLengths = queueLengths;
            this.maxRequests = maxRequests;
            enabled = true;
        }
        
        @Override
        public int getMaxPriorityLevel() {
            return queueLengths.length - 1;
        }

        @Override
        public int getMaxRequests() {
            return maxRequests;
        }

        @Override
        public int getQueueSizeForPriorityLevel(int priorityLevel) {
            return queueLengths[priorityLevel];
        }

        @Override
        public boolean getFilterEnabled() {
            return enabled;
        }
    }
}

