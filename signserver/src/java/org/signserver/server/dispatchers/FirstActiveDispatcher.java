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

import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.WorkerContext;

/**
 * Dispatching requests to the first active worker found.
 *
 * @author markus
 * @version $Id$
 */
public class FirstActiveDispatcher extends BaseDispatcher {

    /** Log4j instance for this class. */
    private static final Logger LOG = Logger.getLogger(
            FirstActiveDispatcher.class);

    private IWorkerSession.IRemote workerSession;

    private List<String> workers = new LinkedList<String>();

    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        try {
            super.init(workerId, config, workerContext, workerEM);

            workers = new LinkedList<String>();
            final String workersValue = config.getProperty("WORKERS");
            if (workersValue == null) {
                LOG.error("Property WORKERS missing!");
            } else {
                for (String worker : workersValue.split(",")) {
                    workers.add(worker);
                }
            }
            final Context context = getInitialContext();
            workerSession = (IWorkerSession.IRemote)
                    context.lookup(IWorkerSession.IRemote.JNDI_NAME);
        } catch (NamingException ex) {
            LOG.error("Unable to lookup worker session", ex);
        }
    }

    public ProcessResponse processData(final ProcessRequest signRequest,
            final RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {

        ProcessResponse response = null;

        // TODO: Look for loops

        // TODO: Perhaps clone or something because there are already values
        // put in or add some indication of dispatching
        final RequestContext nextContext = requestContext;
        int id = 0;

        for (String workerName : workers) {
            try {
                id = workerSession.getWorkerId(workerName);
                if (id == 0) {
                    LOG.warn("Non existing worker: \"" + workerName + "\"");
                } else if (id == workerId) {
                    LOG.warn("Ignoring dispatching to it self (worker "
                            + id + ")");
                } else {
                    response = workerSession.process(id, signRequest,
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

    /**
     * Get the initial naming context.
     */
    private Context getInitialContext() throws NamingException {
        final Hashtable<String, String> props =
                new Hashtable<String, String>();
        props.put(Context.INITIAL_CONTEXT_FACTORY,
                "org.jnp.interfaces.NamingContextFactory");
        props.put(Context.URL_PKG_PREFIXES,
                "org.jboss.naming:org.jnp.interfaces");
        props.put(Context.PROVIDER_URL, "jnp://localhost:1099");
        return new InitialContext(props);
    }

}
