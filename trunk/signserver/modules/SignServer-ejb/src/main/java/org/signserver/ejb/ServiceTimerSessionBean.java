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

import java.io.Serializable;
import java.util.*;
import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.*;
import javax.ejb.Timer;
import javax.naming.NamingException;
import javax.persistence.EntityManager;
import javax.transaction.*;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.ServiceConfig;
import org.signserver.common.ServiceContext;
import org.signserver.common.ServiceLocator;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.ejb.interfaces.DispatcherProcessSessionLocal;
import org.signserver.ejb.worker.impl.WorkerManagerSingletonBean;
import org.signserver.server.IWorker;
import org.signserver.server.ServiceExecutionFailedException;
import org.signserver.server.log.SignServerEventTypes;
import org.signserver.server.log.SignServerModuleTypes;
import org.signserver.server.log.SignServerServiceTypes;
import org.signserver.server.timedservices.ITimedService;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.ejb.interfaces.ProcessSessionLocal;
import org.signserver.ejb.interfaces.ServiceTimerSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.server.entities.FileBasedKeyUsageCounterDataService;
import org.signserver.server.entities.IKeyUsageCounterDataService;
import org.signserver.server.entities.KeyUsageCounterDataService;
import org.signserver.server.nodb.FileBasedDatabaseManager;
import org.signserver.statusrepo.StatusRepositorySessionLocal;

/**
 * Timed service session bean running services on a timely basis.
 */
@Stateless
@TransactionManagement(TransactionManagementType.BEAN)
public class ServiceTimerSessionBean implements ServiceTimerSessionLocal {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ServiceTimerSessionBean.class);
    
    @Resource
    private SessionContext sessionCtx;
    
    private IKeyUsageCounterDataService keyUsageCounterDataService;
    
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    
    @EJB
    private WorkerManagerSingletonBean workerManagerSession;
    
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;

    /** Injected by ejb-jar.xml. */
    EntityManager em;
    
    private final AllServicesImpl servicesImpl = new AllServicesImpl();
    
    /**
     * Constant indicating the Id of the "service loader" service.
     * Used in a clustered environment to periodically load available
     * services
     */
    private static final Integer SERVICELOADER_ID = 0;
    private static final long SERVICELOADER_PERIOD = 5 * 60 * 1000;
    
    // Don't persist the timer
    private static final TimerConfig SERVICELOADER_CONFIG = new TimerConfig(SERVICELOADER_ID, false);

    /**
     * Default create for SessionBean without any creation Arguments.
     */
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
        
        // XXX The lookups will fail on GlassFish V2
        // When we no longer support GFv2 we can refactor this code
        InternalProcessSessionLocal internalSession = null;
        ProcessSessionLocal processSession = null;
        StatusRepositorySessionLocal statusSession = null;
        try {
            internalSession = ServiceLocator.getInstance().lookupLocal(InternalProcessSessionLocal.class);
            processSession = ServiceLocator.getInstance().lookupLocal(ProcessSessionLocal.class);
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
                    internalSession, ServiceLocator.getInstance().lookupLocal(DispatcherProcessSessionLocal.class), statusSession,
                    keyUsageCounterDataService);
        } catch (NamingException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Lookup services failed", ex);
            }
        }
    }
    
    /**
     * Method implemented from the TimerObject and is the main method of this
     * session bean. It calls the work object for each object.
     * 
     * @param timer
     */
    @Timeout
    public void ejbTimeout(Timer timer) {
        Integer timerInfo = (Integer) timer.getInfo();

        if (timerInfo.equals(SERVICELOADER_ID)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Running the internal Service loader.");
            }
            sessionCtx.getTimerService().createSingleActionTimer(SERVICELOADER_PERIOD, SERVICELOADER_CONFIG);
            load(0);
        } else {
            ServiceConfig serviceConfig = null;
            ITimedService timedService = null;
            boolean run = false;
            boolean isSingleton = false;
            UserTransaction ut = sessionCtx.getUserTransaction();
            try {
                ut.begin();
                IWorker worker = workerManagerSession.getWorker(new WorkerIdentifier(timerInfo));
                serviceConfig = new ServiceConfig(worker.getConfig());
                timedService = (ITimedService) worker;
                sessionCtx.getTimerService().createSingleActionTimer(timedService.getNextInterval(), new TimerConfig(timerInfo, false));
                isSingleton = timedService.isSingleton();
                if (!isSingleton) {
                    run = true;
                } else {
                    GlobalConfiguration gc = globalConfigurationSession.getGlobalConfiguration();
                    Date nextRunDate = new Date(0);
                    if (gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "SERVICENEXTRUNDATE" + timerInfo) != null) {
                        nextRunDate = new Date(Long.parseLong(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "SERVICENEXTRUNDATE" + timerInfo)));
                    }
                    Date currentDate = new Date();
                    if (currentDate.after(nextRunDate)) {
                        nextRunDate = new Date(currentDate.getTime() + timedService.getNextInterval());
                        globalConfigurationSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "SERVICENEXTRUNDATE" + timerInfo, "" + nextRunDate.getTime());
                        run = true;
                    }
                }
            } catch (NotSupportedException | SystemException | SecurityException | IllegalStateException e) {
                LOG.error(e);
            } catch (NoSuchWorkerException ex) {
                LOG.error(ex.getMessage());
            } finally {
                try {
                    ut.commit();
                } catch (RollbackException | HeuristicMixedException | HeuristicRollbackException | SystemException e) {
                    LOG.error(e);
                }
            }

            if (run) {
                if (serviceConfig != null && timedService != null) {
                    try {
                        if (timedService.isActive() && timedService.getNextInterval() != ITimedService.DONT_EXECUTE) {
                            timedService.work(new ServiceContext(servicesImpl));
                            serviceConfig.setLastRunTimestamp(new Date());
                            for (final ITimedService.LogType logType :
                                    timedService.getLogTypes()) {
                                switch (logType) {
                                    case INFO_LOGGING:
                                        LOG.info("Service " +
                                                timerInfo +
                                                " executed successfully.");
                                        break;
                                    case SECURE_AUDITLOGGING:
                                        logSession.log(
                                                SignServerEventTypes.TIMED_SERVICE_RUN,
                                                EventStatus.SUCCESS,
                                                SignServerModuleTypes.SERVICE,
                                                SignServerServiceTypes.SIGNSERVER,
                                                "Service invocation", null, null,
                                                timerInfo.toString(),
                                                Collections.<String, Object>emptyMap());
                                        break;
                                    default:
                                        LOG.warn("Unknown log type: " + logType);
                                }
                            }
                            
                        }
                    } catch (ServiceExecutionFailedException e) {
                        // always log to error log, regardless of log types
                        // setup for service run logging
                        LOG.error("Service" + timerInfo + " execution failed. ", e);
                        
                        if (timedService.getLogTypes().contains(ITimedService.LogType.SECURE_AUDITLOGGING)) {
                            logSession.log(
                                    SignServerEventTypes.TIMED_SERVICE_RUN,
                                    EventStatus.FAILURE,
                                    SignServerModuleTypes.SERVICE,
                                    SignServerServiceTypes.SIGNSERVER,
                                    "Service invocation", null, null,
                                    timerInfo.toString(),
                                    Collections.<String, Object>singletonMap("Message", e.getMessage()));
                        }
                    } catch (RuntimeException e) {
                        /*
                         * DSS-377:
                         * If the service worker fails with a RuntimeException we need to
                         * swallow this here. If we allow it to propagate outside the
                         * ejbTimeout method it is up to the application server config how it
                         * should be retried, but we have already scheduled a new try
                         * previously in this method. We still want to log this as an ERROR
                         * since it is some kind of catastrophic failure..
                         */
                        LOG.error("Service worker execution failed.", e);
                    }
                } else {
                    LOG.error("Service with ID " + timerInfo + " not found.");
                }
            } else {
                if (isSingleton) {
                    LOG.info("Service " + timerInfo + " have been executed on another node in the cluster, waiting.");
                }
            }
        }
    }

    /**
     * Loads and activates one or all the services from database that are active
     *
     * @param serviceId 0 indicates all services otherwise is just the specified service loaded.
     */
    @Override
    public void load(int serviceId) {
        // Get all services
        TimerService timerService = sessionCtx.getTimerService();
        Collection<?> currentTimers = timerService.getTimers();
        Iterator<?> iter = currentTimers.iterator();
        HashSet<Serializable> existingTimers = new HashSet<>();
        while (iter.hasNext()) {
            Timer timer = (Timer) iter.next();
            existingTimers.add(timer.getInfo());
        }

        final Collection<Integer> serviceIds;
        if (serviceId == 0) {
            serviceIds = workerManagerSession.getAllWorkerIDs(WorkerType.TIMED_SERVICE);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found " + serviceIds.size() + " timed services");
            }
        } else {
            serviceIds = new ArrayList<>();
            serviceIds.add(serviceId);
        }
        iter = serviceIds.iterator();
        while (iter.hasNext()) {
            Integer nextId = (Integer) iter.next();
            if (!existingTimers.contains(nextId)) {
                ITimedService timedService;
                try {
                    IWorker worker = workerManagerSession.getWorker(new WorkerIdentifier(nextId));
                    if (worker instanceof ITimedService) {
                        timedService = (ITimedService) worker;
                        if (timedService.isActive() && timedService.getNextInterval() != ITimedService.DONT_EXECUTE) {
                            sessionCtx.getTimerService().createSingleActionTimer(timedService.getNextInterval(), new TimerConfig(nextId, false));
                        }
                    } else {
                        LOG.error("Worker implementation is not a timed service. Wrong worker TYPE? for worker " + nextId);
                    }
                } catch (NoSuchWorkerException ex) {
                    LOG.error("Worker no longer exists: " + ex.getMessage());
                }
            }
        }

        if (!existingTimers.contains(SERVICELOADER_ID)) {
            // load the service timer
            sessionCtx.getTimerService().createSingleActionTimer(SERVICELOADER_PERIOD, SERVICELOADER_CONFIG);
        }
    }

    /**
     * Cancels one or all existing timers 
     *
     * @param serviceId indicates all services otherwise is just the specified service unloaded.
     */
    @Override
    public void unload(int serviceId) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Unloading");
        }
        // Get all services
        for (Object o : sessionCtx.getTimerService().getTimers()) {
            if (o instanceof Timer) {
                final Timer timer = (Timer) o;
                try {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Cancelling timer: " + timer);
                    }
                    if (serviceId == 0) {
                        timer.cancel();
                    } else {
                        if (timer.getInfo() instanceof Integer) {
                            if (((Integer) timer.getInfo()) == serviceId) {
                                timer.cancel();
                            }
                        }
                    }
                } catch (Exception e) {
                    /*
                     * EJB 2.1 only?: We need to catch this because Weblogic 10
                     * throws an exception if we have not scheduled this timer, so
                     * we don't have anything to cancel. Only weblogic though...
                     */
                    LOG.info("Caught exception canceling timer: " + e.getMessage());
                }
            }
        }
    }
    
    /**
     * Adds a timer to the bean.
     * 
     * @param interval Interval of the timer
     * @param id ID of the timer
     */
    @Override
    public void addTimer(long interval, Integer id) {
        sessionCtx.getTimerService().createSingleActionTimer(interval, new TimerConfig(id, false));
    }

    /**
     * Cancels a timer with the given ID.
     *
     * @param id ID of timer to cancel
     */
    @Override
    public void cancelTimer(Integer id) {
        Collection<?> timers = sessionCtx.getTimerService().getTimers();
        Iterator<?> iter = timers.iterator();
        while (iter.hasNext()) {
            Timer next = (Timer) iter.next();
            if (id.equals(next.getInfo())) {
                next.cancel();
            }
        }
    }
}
