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
import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.BaseProcessable;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.WritableData;
import org.signserver.server.log.LogMap;

/**
 * Debug worker imposing a sleep pause (using Thread.sleep()).
 * <p>
 * The worker has two worker properties:
 * </p>
 * <ul>
 *    <li>
 *        <b>SLEEP_TIME</b> = Time to sleep in milliseconds (Required).
 *    </li>
 * </ul>
 * <p>
 * The worker will pause the request's thread for the specified number of
 * milliseconds and reply with a message containing the input data and the
 * time it spent in sleep.
 * </p>
 * @author Macus Lundblad
 * @version $Id$
 */
public class SleepWorker extends BaseProcessable {

    private static final Logger LOG = Logger.getLogger(SleepWorker.class);

    // Worker properties
    public static final String PROPERTY_SLEEP_TIME = "SLEEP_TIME";

    // Log fields
    public static final String LOG_NAME = "HELLO_NAME";

    // Content types
    private static final String REQUEST_CONTENT_TYPE = "text/plain";
    private static final String RESPONSE_CONTENT_TYPE = "text/plain";

    // Priority log field
    private static final String QOS_PRIORITY = "QOS_PRIORITY";

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    private int sleepTime;

    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Sleep time
        final String sleepTimeString = config.getProperty(PROPERTY_SLEEP_TIME);
        if (sleepTimeString != null) {
            sleepTime = Integer.parseInt(sleepTimeString);
        } else {
            configErrors.add("Missing required property: " + PROPERTY_SLEEP_TIME);
        }
    }

    @Override
    public Response processData(
            Request signRequest, RequestContext requestContext
    ) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }
        if (!(signRequest instanceof SignatureRequest)) {
            throw new IllegalRequestException("Unexpected request type");
        }
        final SignatureRequest request = (SignatureRequest) signRequest;

        // Get the data from request
        final ReadableData requestData = request.getRequestData();
        final WritableData responseData = request.getResponseData();

        try (OutputStream out = responseData.getAsOutputStream()) {
            // Get the name from request (We don't expect it to be large)
            final byte[] data = requestData.getAsByteArray();
            final String name = new String(data, StandardCharsets.UTF_8);
            if (name.isEmpty()) {
                // This is a client error
                throw new IllegalRequestException("Supplying a name as input is required.");
            }

            // Log anything interesting from the request to the worker logger
            LogMap.getInstance(requestContext).put(LOG_NAME, name);

            // Log priority level if available
            final Integer qosPriority = (Integer) requestContext.get(QOS_PRIORITY);

            LogMap.getInstance(requestContext).put(
                    QOS_PRIORITY, qosPriority != null ? qosPriority.toString() : "not set");

            // Additional debug logging using Log4j
            if (LOG.isDebugEnabled()) {
                LOG.debug("Will produce a greeting for: " + name);
            }

            Thread.sleep(sleepTime);

            // Produce the result, ie doing the work
            final String result = "Hi " + name + ", I've slept for " + sleepTime + " milliseconds!";
            out.write(result.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ex) {
            throw new SignServerException("Unable to read/write data", ex);
        } catch (InterruptedException ex) {
            throw new SignServerException("Unable to sleep", ex);
        }

        // Suggest new file name
        suggestNewFileName(requestContext);

        // As everything went well, the client can be charged for the request
        requestContext.setRequestFulfilledByWorker(true);

        // Return the response
        return createBasicSignatureResponse(requestContext, request,
                                            REQUEST_CONTENT_TYPE,
                                            RESPONSE_CONTENT_TYPE, null);
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        // Add our errors to the list of errors
        final LinkedList<String> errors = new LinkedList<>(super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }

}
