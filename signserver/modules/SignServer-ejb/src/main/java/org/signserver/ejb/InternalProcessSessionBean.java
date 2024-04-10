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
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.naming.NamingException;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.ejb.interfaces.DispatcherProcessSessionLocal;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.ejb.interfaces.ProcessSessionLocal;
import org.signserver.ejb.worker.impl.WorkerManagerSingletonBean;
import org.signserver.server.entities.FileBasedKeyUsageCounterDataService;
import org.signserver.server.entities.IKeyUsageCounterDataService;
import org.signserver.server.entities.KeyUsageCounterDataService;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.nodb.FileBasedDatabaseManager;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.ejb.interfaces.InternalProcessTransactionSessionLocal;
import org.signserver.statusrepo.StatusRepositorySessionLocal;

/**
 * Session bean implementing the process methods in the same way as the
 * WorkerSessionBean. This bean is intended to be used from workers and 
 * not directly through any of the client interfaces.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class InternalProcessSessionBean implements InternalProcessSessionLocal {

    /** Log4j instance for this class. */
    private static final Logger LOG = Logger.getLogger(InternalProcessSessionBean.class);

    private IKeyUsageCounterDataService keyUsageCounterDataService;

    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @EJB
    private WorkerManagerSingletonBean workerManagerSession;

    @EJB
    private SecurityEventsLoggerSessionLocal logSession;
    
    @EJB
    InternalProcessTransactionSessionLocal internalProcessTransSession;
    
    /** Injected by ejb-jar.xml. */
    EntityManager em;
    
    @Resource
    private SessionContext ctx;

    private WorkerProcessImpl processImpl;
    private final AllServicesImpl servicesImpl = new AllServicesImpl();
    private InternalProcessSessionLocal session;

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
        session = ctx.getBusinessObject(InternalProcessSessionLocal.class);
        
        // XXX The lookups will fail on GlassFish V2
        // When we no longer support GFv2 we can refactor this code
        ProcessSessionLocal processSession = null;
        DispatcherProcessSessionLocal dispatcherSession = null;
        StatusRepositorySessionLocal statusSession = null;
        try {
            processSession = ServiceLocator.getInstance().lookupLocal(ProcessSessionLocal.class);
            dispatcherSession = ServiceLocator.getInstance().lookupLocal(DispatcherProcessSessionLocal.class);
            statusSession = ServiceLocator.getInstance().lookupLocal(StatusRepositorySessionLocal.class);
        } catch (NamingException ex) {
            LOG.error("Lookup services failed. This is expected on GlassFish V2: " + ex.getExplanation());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Lookup services failed", ex);
            }
        }
        try {
            // Add all services
            servicesImpl.putAll(em,
                    ServiceLocator.getInstance().lookupLocal(WorkerSessionLocal.class),
                    processSession,
                    globalConfigurationSession,
                    logSession,
                    session, dispatcherSession, statusSession,
                    keyUsageCounterDataService);
        } catch (NamingException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Lookup services failed", ex);
            }
        }
    }

    @Override
    public Response process(final AdminInfo adminInfo, final WorkerIdentifier wi,
            final Request request, final RequestContext requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {
        requestContext.setServices(servicesImpl);
        if (SessionUtils.needsTransaction(workerManagerSession, wi)) {
            // use separate transaction bean to avoid deadlock
            return internalProcessTransSession.processWithTransaction(adminInfo, wi, request, requestContext);
        } else {
            return processImpl.process(adminInfo, wi, request, requestContext);
        }
    }    
    
}
