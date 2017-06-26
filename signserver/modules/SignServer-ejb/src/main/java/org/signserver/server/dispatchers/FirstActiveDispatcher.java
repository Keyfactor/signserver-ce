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
package org.signserver.server.dispatchers;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.ejb.interfaces.DispatcherProcessSessionLocal;
import org.signserver.server.WorkerContext;
import org.signserver.server.log.AdminInfo;

/**
 * Dispatching requests to the first active worker found.
 *
 * Properties:<br/>
 * WORKERS = Comma separated list of worker names
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class FirstActiveDispatcher extends BaseDispatcher {

    /** Log4j instance for this class. */
    private static final Logger LOG = Logger.getLogger(
            FirstActiveDispatcher.class);

    /** Property WORKERS. */
    private static final String PROPERTY_WORKERS = "WORKERS";

    /** List of workers. */
    private List<String> workers = new LinkedList<>();

    private String name;

    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        name = config.getProperty("NAME");

        workers = new LinkedList<>();
        final String workersValue = config.getProperty(PROPERTY_WORKERS);
        if (workersValue == null) {
            LOG.error("Property WORKERS missing!");
        } else {
            workers.addAll(Arrays.asList(workersValue.split(",")));
        }
    }

    @Override
    public Response processData(final Request signRequest,
            final RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {

        Response response = null;

        // TODO: Look for loops

        final RequestContext nextContext = requestContext.copyWithNewLogMap();
        int id = 0;
        
        // Mark request comming from a dispatcher so the DispatchedAuthorizer can be used
        nextContext.put(RequestContext.DISPATCHER_AUTHORIZED_CLIENT, true);

        for (String workerName : workers) {
            workerName = workerName.trim();
            try {
                if (name.equals(workerName)) {
                    LOG.warn("Ignoring dispatching to it self (worker "
                            + name + ")");
                } else {
                    response = requestContext.getServices().get(DispatcherProcessSessionLocal.class).process(new AdminInfo("Client user", null, null), 
                            new WorkerIdentifier(workerName), signRequest,
                            nextContext);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Dispatched to worker: "
                                + workerName + " (" + id + ")");
                    }
                    break;
                }
            } catch (CryptoTokenOfflineException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Skipping offline worker: " + id + " ("
                            + ex.getMessage() + ")");
                }
            }
        }
        if (response == null) {
            throw new CryptoTokenOfflineException("No active worker found");
        }

        return response;
    }

}
