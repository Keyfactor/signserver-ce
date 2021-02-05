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

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.signserver.common.qos.AbstractStatistics;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.common.WorkerStatusInfo.Entry;
import org.signserver.server.BaseProcessable;
import org.signserver.server.IServices;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.WritableData;

/**
 * Diagnostics worker giving status for the QoSFilter in the process response.
 *
 * @author Macus Lundblad
 * @version $Id$
 */
public class QoSStatusWorker extends BaseProcessable {
    // Content types
    private static final String REQUEST_CONTENT_TYPE = "text/plain";
    private static final String RESPONSE_CONTENT_TYPE = "text/plain";

    @Override
    public Response processData(final Request signRequest,
                                final RequestContext requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
                   SignServerException {
        if (!(signRequest instanceof SignatureRequest)) {
            throw new IllegalRequestException("Unexpected request type");
        }
        final SignatureRequest request = (SignatureRequest) signRequest;

        // Get the data from request
        final ReadableData requestData = request.getRequestData();
        final WritableData responseData = request.getResponseData();

        try (OutputStream out = responseData.getAsOutputStream()) {
            // Produce the result
            final String result = generateResponseMessage();
            out.write(result.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ex) {
            throw new SignServerException("Unable to read/write data", ex);
        }

        // Suggest new file name
        suggestNewFileName(requestContext);

        // As everyting went well, the client can be charged for the request
        requestContext.setRequestFulfilledByWorker(true);

        // Return the response
        return createBasicSignatureResponse(requestContext, request,
                                            REQUEST_CONTENT_TYPE,
                                            RESPONSE_CONTENT_TYPE, null);
    }

    @Override
    public WorkerStatusInfo getStatus(final List<String> additionalFatalErrors,
                                      final IServices services) {
        return new WorkerStatusInfo(workerId, config.getProperty("NAME"),
                                    "Worker", WorkerStatus.STATUS_ACTIVE,
                                    generateBriefEntries(),
                                    additionalFatalErrors,
                                    Collections.emptyList(),
                                    config);
    }

    /**
     * Generate a list of brief status entries for the queue statuses.
     *
     * @return list of status entries
     */
    private List<Entry> generateBriefEntries() {
        final List<Entry> results = new LinkedList<>();
        final AbstractStatistics statistics = getFilterStatistics();
        if (statistics != null) {
            final boolean enabled = statistics.isEnabled();

            results.add(new Entry("Filter enabled", Boolean.toString(enabled)));

            if (enabled) {
                final int maxRequests = statistics.getMaxRequests();
                final int maxPriorityLevel = statistics.getMaxPriorityLevel();
                final int semaphoreQueueLength = statistics.getSemaphoreQueueLength();
                final int semaphoreAvailablePermits = statistics.getSemaphoreAvailablePermits();
                final Entry maxRequestsEntry =
                        new Entry("Maximum requests",
                                  Integer.toString(maxRequests));
                final Entry maxPriorityEntry =
                        new Entry("Maximum priority level",
                                  Integer.toString(maxPriorityLevel));

                final Entry semaphoreQueueLengthEntry =
                        new Entry("Semaphore Queue Size",
                                  Integer.toString(semaphoreQueueLength));
                final Entry semaphoreAvailablePermitsEntry =
                        new Entry("Semaphore Available Permits",
                                  Integer.toString(semaphoreAvailablePermits));

                results.add(maxRequestsEntry);
                results.add(maxPriorityEntry);
                results.add(semaphoreQueueLengthEntry);
                results.add(semaphoreAvailablePermitsEntry);

                for (int i = 0; i <= maxPriorityLevel; i++) {
                    final Entry queueSizeEntry =
                            new Entry("Queue size(" + i + ")",
                                      Integer.toString(statistics.getQueueSizeForPriorityLevel(i)));

                    results.add(queueSizeEntry);
                }
            }
        }

        return results;
    }

    /**
     * Generate a response text body for the process response.
     *
     * @return textual response with queue statuses
     */
    private String generateResponseMessage() {
        final StringBuilder sb = new StringBuilder();
        final AbstractStatistics statistics = getFilterStatistics();
        if (statistics != null) {
            final boolean enabled = statistics.isEnabled();

            sb.append("FILTER_ENABLED=").append(enabled).append("\n");

            if (enabled) {
                final int maxRequests = statistics.getMaxRequests();
                final int maxPriorityLevel =
                        statistics.getMaxPriorityLevel();
                final int semaphoreQueueLength = statistics.getSemaphoreQueueLength();
                final int semaphoreAvailablePermits = statistics.getSemaphoreAvailablePermits();

                sb.append("MAX_REQUESTS=").append(maxRequests).append("\n");
                sb.append("MAX_PRIORITY_LEVEL=").append(maxPriorityLevel).append("\n");

                for (int i = 0; i <= maxPriorityLevel; i++) {
                    sb.append("QUEUE_SIZE(").append(i).append(")=");
                    sb.append(statistics.getQueueSizeForPriorityLevel(i));
                    sb.append("\n");
                }

                sb.append("SEMAPHORE_QUEUE_SIZE=").append(semaphoreQueueLength).append("\n");
                sb.append("SEMAPHORE_AVAILABLE_PERMITS=").append(semaphoreAvailablePermits).append("\n");
            }
        }

        return sb.toString();
    }

    AbstractStatistics getFilterStatistics() {
        return AbstractStatistics.getDefaultInstance();
    }
}
