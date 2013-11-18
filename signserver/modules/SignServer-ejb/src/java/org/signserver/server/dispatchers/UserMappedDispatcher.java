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

import java.util.HashMap;
import java.util.Map;
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
import org.signserver.common.ServiceLocator;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.WorkerContext;
import org.signserver.server.UsernamePasswordClientCredential;

/**
 * Dispatching requests based on username with mapping in config.
 *
 * Properties:<br/>
 * USERNAME_MAPPING = Comma separated list of mappings from username:workername.
 * 
 * user1:worker1, user2:worker2
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class UserMappedDispatcher extends BaseDispatcher {

    /** Log4j instance for this class. */
    private static final Logger LOG = Logger.getLogger(
            UserMappedDispatcher.class);

    /** Property WORKERS. */
    private static final String PROPERTY_USERNAME_MAPPING = "USERNAME_MAPPING";

    /** Workersession. */
    private IWorkerSession workerSession;

    /** Mapping. */
    private Map<String, String> mappings;


    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        try {
            super.init(workerId, config, workerContext, workerEM);

            mappings = new HashMap<String, String>();
            final String workersValue = config.getProperty(PROPERTY_USERNAME_MAPPING);
            if (workersValue == null) {
                LOG.error("Property " + PROPERTY_USERNAME_MAPPING + " missing!");
            } else {
                for (String mapping : workersValue.split(",")) {
                    final String[] item = mapping.split(":");
                    mappings.put(item[0].trim(), item[1].trim());
                    // TODO: Handle failures
                }
            }
            workerSession = ServiceLocator.getInstance().lookupLocal(
                        IWorkerSession.class);
        } catch (NamingException ex) {
            LOG.error("Unable to lookup worker session", ex);
        }
    }

    @Override
    public ProcessResponse processData(final ProcessRequest signRequest,
            final RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {

        ProcessResponse response = null;

        // TODO: Look for loops

        // TODO: Perhaps clone or something because there are already values
        // put in or add some indication of dispatching
        final RequestContext nextContext = requestContext;
        int id = 0;

        final String username = ((UsernamePasswordClientCredential) requestContext.get(RequestContext.CLIENT_CREDENTIAL)).getUsername();
        final String workerName = mappings.get(username);
        
        if (workerName == null) {
            LOG.info("No worker for username: " + username);
            throw new IllegalRequestException("No worker for the specified username");
        }
        
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
                return response;
            }
        } catch (CryptoTokenOfflineException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Skipping offline worker: " + id + " ("
                        + ex.getMessage() + ")");
            }
        }

        if (response == null) {
            throw new CryptoTokenOfflineException("No active worker found");
        }

        return response;
    }

}
