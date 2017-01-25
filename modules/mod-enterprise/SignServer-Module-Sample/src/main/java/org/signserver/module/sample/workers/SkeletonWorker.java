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

/**
 * Skeleton worker...
 * <p>
 * The worker has the following worker properties:
 * </p>
 * <ul>
 *    <li>
 *       <b>PROPERTY_NAME...</b> = Description...
 *       (Optional/required, default: ...)
 *    </li>
 * </ul>
 * @author ...
 * @version $Id$
 */
public class SkeletonWorker extends BaseProcessable {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SkeletonWorker.class);

    // Worker properties
    //...

    // Log fields
    //...

    // Default values
    //...

    // Content types
    private static final String REQUEST_CONTENT_TYPE = ""; //...
    private static final String RESPONSE_CONTENT_TYPE = ""; //...

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    //...

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        // Read properties
        //...
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
        //...

        // Log anything interesting from the request to the worker logger
        //...

        // Produce the result, ie doing the work
        try (OutputStream out = responseData.getAsOutputStream()) {
            final String result = "Hello world!"; // ...
            out.write(result.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ex) {
            throw new SignServerException("Unable to write data", ex);
        }

        // Create the archivables (request and response)
        final String archiveId = createArchiveId(new byte[0],
                (String) requestContext.get(RequestContext.TRANSACTION_ID));
        final Collection<? extends Archivable> archivables = Arrays.asList(
                new DefaultArchivable(Archivable.TYPE_REQUEST,
                        REQUEST_CONTENT_TYPE, requestData, archiveId), 
                new DefaultArchivable(Archivable.TYPE_RESPONSE,
                        RESPONSE_CONTENT_TYPE, responseData.toReadableData(),
                        archiveId));

        // Suggest new file name
        final Object fileNameOriginal = requestContext.get(
                RequestContext.FILENAME);
        if (fileNameOriginal instanceof String) {
            requestContext.put(RequestContext.RESPONSE_FILENAME,
                    fileNameOriginal + "");
        }

        // As everyting went well, the client can be charged for the request
        requestContext.setRequestFulfilledByWorker(true);

        // Return the response
        return new SignatureResponse(request.getRequestID(), responseData, 
                null, archiveId, archivables, RESPONSE_CONTENT_TYPE);
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
