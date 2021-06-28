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

import java.util.LinkedList;
import java.util.List;
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
 * Skeleton dispatcher...
 * <p>
 *    The dispatcher has the following worker properties:
 * </p>
 * <ul>
 *    <li>
 *        <b>PROPERTY...</b> = Description (Required/Optional, default: ...)
 *    </li>
 * </ul>
 *
 * @author ...
 * @version $Id$
 */
public class SkeletonDispatcher extends BaseDispatcher {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SkeletonDispatcher.class);

    // Worker properties
    //...

    // Log fields
    //...

    // Default values
    //...

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    //...

    private DispatcherProcessSessionLocal processSession;
    
    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
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

        // Mark request comming from a dispatcher so the DispatchedAuthorizer
        // can be used
        requestContext.put(RequestContext.DISPATCHER_AUTHORIZED_CLIENT, true);

        // Select worker to dispatch to
        final WorkerIdentifier wi = new WorkerIdentifier("Worker1"); // ...

        // Do the dispatching
        return requestContext.getServices().get(DispatcherProcessSessionLocal.class).process(new AdminInfo("Client user", null, null), wi, signRequest, requestContext);
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
