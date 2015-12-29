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
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.naming.NamingException;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.RequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.DispatcherProcessSessionLocal;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.ejb.worker.impl.WorkerManagerSingletonBean;
import org.signserver.server.entities.FileBasedKeyUsageCounterDataService;
import org.signserver.server.entities.IKeyUsageCounterDataService;
import org.signserver.server.entities.KeyUsageCounterDataService;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.nodb.FileBasedDatabaseManager;
import org.signserver.statusrepo.IStatusRepositorySession;
import org.signserver.ejb.interfaces.ProcessSessionLocal;
import org.signserver.ejb.interfaces.ProcessSessionRemote;

/**
 * Session Bean handling the worker process requests.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@Stateless
public class ProcessSessionBean implements ProcessSessionRemote, ProcessSessionLocal {

    /** Log4j instance for this class. */
    private static final Logger LOG = Logger.getLogger(WorkerSessionBean.class);
    
    private IKeyUsageCounterDataService keyUsageCounterDataService;

    @EJB
    private IGlobalConfigurationSession.ILocal globalConfigurationSession;
    
    @EJB
    private WorkerManagerSingletonBean workerManagerSession;
    
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;
    
    @Resource
    private SessionContext ctx;
    
    EntityManager em;

    private WorkerProcessImpl processImpl;
    private final AllServicesImpl servicesImpl = new AllServicesImpl();

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

        // XXX The lookups will fail on GlassFish V2
        // When we no longer support GFv2 we can refactor this code
        InternalProcessSessionLocal internalSession = null;
        DispatcherProcessSessionLocal dispatcherSession = null;
        IStatusRepositorySession.ILocal statusSession = null;
        try {
            internalSession = ServiceLocator.getInstance().lookupLocal(InternalProcessSessionLocal.class);
            dispatcherSession = ServiceLocator.getInstance().lookupLocal(DispatcherProcessSessionLocal.class);
            statusSession = ServiceLocator.getInstance().lookupLocal(IStatusRepositorySession.ILocal.class);
        } catch (NamingException ex) {
            LOG.error("Lookup services failed. This is expected on GlassFish V2: " + ex.getExplanation());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Lookup services failed", ex);
            }
        }
        try {
            // Add all services
            servicesImpl.putAll(
                    em,
                    ServiceLocator.getInstance().lookupLocal(IWorkerSession.ILocal.class),
                    ctx.getBusinessObject(ProcessSessionLocal.class),
                    globalConfigurationSession,
                    logSession,
                    internalSession, dispatcherSession, statusSession);
        } catch (NamingException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Lookup services failed", ex);
            }
        }
    }
    
    @Override
    public ProcessResponse process(final WorkerIdentifier wi,
            final ProcessRequest request, final RemoteRequestContext remoteContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {
        return processImpl.process(wi, request, remoteContext, servicesImpl);
    }
    
    @Override
    public ProcessResponse process(final AdminInfo adminInfo, final WorkerIdentifier wi,
            final ProcessRequest request, final RequestContext requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {
        requestContext.setServices(servicesImpl);
        if (LOG.isDebugEnabled()) {
            LOG.debug(">process: " + wi);
        }
        return processImpl.process(adminInfo, wi, request, requestContext);
    }
    
    
    // Add business logic below. (Right-click in editor and choose
    // "Insert Code > Add Business Method")
}
