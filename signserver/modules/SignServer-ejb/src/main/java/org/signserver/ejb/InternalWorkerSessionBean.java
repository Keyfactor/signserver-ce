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
package org.signserver.ejb;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IInternalWorkerSession;
import org.signserver.ejb.worker.impl.IWorkerManagerSessionLocal;
import org.signserver.server.entities.FileBasedKeyUsageCounterDataService;
import org.signserver.server.entities.IKeyUsageCounterDataService;
import org.signserver.server.entities.KeyUsageCounterDataService;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.nodb.FileBasedDatabaseManager;

/**
 * Session bean implementing the process and getWorkerId methods in the same way
 * as the WorkerSessionBean. This bean is intended to be used from workers and 
 * not directly through any of the client interfaces.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@Stateless
public class InternalWorkerSessionBean implements IInternalWorkerSession.ILocal, IInternalWorkerSession.IRemote {

    /** Log4j instance for this class. */
    private static final Logger LOG = Logger.getLogger(InternalWorkerSessionBean.class);

    private IKeyUsageCounterDataService keyUsageCounterDataService;

    @EJB
    private IGlobalConfigurationSession.ILocal globalConfigurationSession;

    @EJB
    private IWorkerManagerSessionLocal workerManagerSession;

    @EJB
    private SecurityEventsLoggerSessionLocal logSession;

    /** Injected by ejb-jar.xml. */
    EntityManager em;

    private WorkerProcessImpl processImpl;

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
        processImpl = new WorkerProcessImpl(em, keyUsageCounterDataService, globalConfigurationSession, workerManagerSession, logSession);
    }

    @Override
    public ProcessResponse process(final int workerId,
            final ProcessRequest request, final RequestContext requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {
        return processImpl.process(workerId, request, requestContext);
    }

    @Override
    public ProcessResponse process(final AdminInfo adminInfo, final int workerId,
            final ProcessRequest request, final RequestContext requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {
        return processImpl.process(adminInfo, workerId, request, requestContext);
    }

    @Override
    public int getWorkerId(String workerName) {
        return processImpl.getWorkerId(workerName);
    }

}
