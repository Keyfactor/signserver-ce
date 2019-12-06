/** ***********************************************************************
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
 ************************************************************************ */
package org.signserver.ejb;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.ejb.interfaces.ProcessTransactionSessionLocal;
import org.signserver.ejb.worker.impl.WorkerManagerSingletonBean;
import org.signserver.server.entities.FileBasedKeyUsageCounterDataService;
import org.signserver.server.entities.IKeyUsageCounterDataService;
import org.signserver.server.entities.KeyUsageCounterDataService;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.nodb.FileBasedDatabaseManager;

/**
 * Session Bean handling the worker process requests when transaction is needed.
 *
 * @author Vinay Singh
 * @version $Id$
 */
@Stateless
public class ProcessTransactionSessionBean implements ProcessTransactionSessionLocal {

    /**
     * Log4j instance for this class.
     */
    private static final Logger LOG = Logger.getLogger(ProcessTransactionSessionBean.class);

    private IKeyUsageCounterDataService keyUsageCounterDataService;

    private WorkerProcessImpl processImpl;

    @EJB
    private SecurityEventsLoggerSessionLocal logSession;

    @EJB
    private WorkerManagerSingletonBean workerManagerSession;

    EntityManager em;

    @PostConstruct
    public void create() {
        if (em == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No EntityManager injected. Running without database.");
            }
            keyUsageCounterDataService = new FileBasedKeyUsageCounterDataService(FileBasedDatabaseManager.getInstance());
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("EntityManager injected. Running with database.");
            }
            keyUsageCounterDataService = new KeyUsageCounterDataService(em);
        }
        processImpl = new WorkerProcessImpl(em, keyUsageCounterDataService, workerManagerSession, logSession);
    }

    /**
     *
     * @param info
     * @param wi
     * @param request
     * @param requestContext
     * @return
     * @throws IllegalRequestException
     * @throws CryptoTokenOfflineException
     * @throws SignServerException
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public Response processWithTransaction(final AdminInfo info,
            final WorkerIdentifier wi,
            final Request request,
            final RequestContext requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        if (LOG.isDebugEnabled()) {
            LOG.debug(">process in transaction: " + wi);
        }

        return processImpl.process(info, wi, request, requestContext);
    }

}
