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
package org.signserver.module.sample.workers;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
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
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.server.log.LogMap;

/**
 * Sample greeting worker demonstrating the basic operations of a worker.
 * <p>
 * The worker has two worker properties:
 * </p>
 * <ul>
 *    <li>
 *        <b>GREETING</b> = The greeting phrase to use, ie "Hello" (Required)
 *    </li>
 *    <li><b>SUFFIX</b> = Characters to add at end of greeting
 *        (Optional, default: "!")
 *    </li>
 * </ul>
 * <p>
 * The worker expects the input document to contain a name and will respond
 * with:<br/>
 * GREETING NAME SUFFIX, ie "Hello Markus !"
 * </p>
 * @author Markus Kilås
 * @version $Id$
 */
public class HelloWorker extends BaseProcessable {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(HelloWorker.class);

    // Worker properties
    public static final String PROPERTY_GREETING = "GREETING";
    public static final String PROPERTY_SUFFIX = "SUFFIX";

    // Log fields
    public static final String LOG_NAME = "HELLO_NAME";

    // Default values
    private static final String DEFAULT_SUFFIX = "!";

    // Content types
    private static final String REQUEST_CONTENT_TYPE = "text/plain";
    private static final String RESPONSE_CONTENT_TYPE = "text/plain";

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    private String greeting;
    private String suffix;

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        // Required property GREETING
        greeting = config.getProperty(PROPERTY_GREETING);
        if (greeting == null || greeting.trim().isEmpty()) {
            configErrors.add("Missing required property: " + PROPERTY_GREETING);
        }
        
        // Optional property SUFFIX
        suffix = config.getProperty(PROPERTY_SUFFIX, DEFAULT_SUFFIX);
    }

    @Override
    public Response processData(Request signRequest,
            RequestContext requestContext) throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException {
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
                throw new IllegalRequestException(
                        "Supplying a name as input is required.");
            }

            // Log anything interesting from the request to the worker logger
            LogMap.getInstance(requestContext).put(LOG_NAME, name);

            // Additional debug logging using Log4j
            if (LOG.isDebugEnabled()) {
                LOG.debug("Will produce a greeting for: " + name);
            }

            // Produce the result, ie doing the work
            final String result = (greeting + " " + name + suffix);
            out.write(result.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ex) {
            throw new SignServerException("Unable to read/write data", ex);
        }

        // Create the archivables (request and response)
        final String archiveId = createArchiveId(new byte[0], 
                (String) requestContext.get(RequestContext.TRANSACTION_ID));
        final Collection<? extends Archivable> archivables = Arrays.asList(
                new DefaultArchivable(Archivable.TYPE_REQUEST, 
                        REQUEST_CONTENT_TYPE, requestData, archiveId), 
                new DefaultArchivable(Archivable.TYPE_RESPONSE, 
                        RESPONSE_CONTENT_TYPE, responseData.toReadableData(), archiveId));

        // Suggest new file name
        final Object fileNameOriginal
                = requestContext.get(RequestContext.FILENAME);
        if (fileNameOriginal instanceof String) {
            requestContext.put(RequestContext.RESPONSE_FILENAME,
                    fileNameOriginal + "");
        }

        // As everyting went well, the client can be charged for the request
        requestContext.setRequestFulfilledByWorker(true);

        // Return the response
        return new SignatureResponse(
                request.getRequestID(), responseData, null, archiveId,
                archivables, RESPONSE_CONTENT_TYPE);
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        // Add our errors to the list of errors
        final LinkedList<String> errors = new LinkedList<>(
                super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }

}
