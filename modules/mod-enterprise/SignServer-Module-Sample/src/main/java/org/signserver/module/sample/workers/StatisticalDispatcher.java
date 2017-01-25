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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.ejb.interfaces.DispatcherProcessSessionLocal;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.dispatchers.BaseDispatcher;
import org.signserver.server.log.AdminInfo;

/**
 * Sample dispatcher trying to spread the usage between the configured workers
 * by for each request randomizing which worker gets to serve it.
 * <p>
 *    The dispatcher has the following worker properties:
 * </p>
 * <ul>
 *    <li>
 *        <b>WORKERS</b> = Comma separated list of worker names (Required)
 *    </li>
 * </ul>
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class StatisticalDispatcher extends BaseDispatcher {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            StatisticalDispatcher.class);

    // Worker properties
    /** Set of workers to dispatch to. */
    public static final String PROPERTY_WORKERS = "WORKERS";

    // Log fields

    // Default values

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    private ArrayList<String> workers;

    private String name;
    
    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        name = config.getProperty("NAME");

        // Required property WORKERS
        workers = new ArrayList<>();
        final String workersValue = config.getProperty(PROPERTY_WORKERS);
        if (workersValue == null || workersValue.trim().isEmpty()) {
            configErrors.add("Property " + PROPERTY_WORKERS
                    + " must contain at least one worker");
        } else {
            workers.addAll(Arrays.asList(workersValue.split(",")));
        }
    }

    @Override
    public Response processData(Request signRequest,
            RequestContext requestContext) throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException {
        if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }

        // Mark request comming from a dispatcher so the DispatchedAuthorizer
        // can be used
        requestContext.put(RequestContext.DISPATCHER_AUTHORIZED_CLIENT, true);

        // Pick a worker to dispatch to
        final String workerName = workers.get(ThreadLocalRandom.current().nextInt(workers.size()));
    
        if (name.equalsIgnoreCase(workerName)) {
            throw new SignServerException(
                    "Ignoring dispatching to itself (worker " + workerName + ")");
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Dispatching to worker: " + workerName);
            }

            // Do the dispatching
            return requestContext.getServices().get(DispatcherProcessSessionLocal.class).process(new AdminInfo("Client user", null, null), new WorkerIdentifier(workerName), signRequest, requestContext);
        }
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
