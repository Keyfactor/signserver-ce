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
import javax.transaction.*;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ServiceConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IServiceTimerSession;
import org.signserver.ejb.worker.impl.IWorkerManagerSessionLocal;
import org.signserver.server.IWorker;
import org.signserver.server.ServiceExecutionFailedException;
import org.signserver.server.log.SignServerEventTypes;
import org.signserver.server.log.SignServerModuleTypes;
import org.signserver.server.log.SignServerServiceTypes;
import org.signserver.server.timedservices.ITimedService;

/**
 * Timed service session bean running services on a timely basis.
 */
@Stateless
@TransactionManagement(TransactionManagementType.BEAN)
public class ServiceTimerSessionBean implements IServiceTimerSession.ILocal, IServiceTimerSession.IRemote {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ServiceTimerSessionBean.class);
    
    @Resource
    private SessionContext sessionCtx;
    
    @EJB
    private IGlobalConfigurationSession.ILocal globalConfigurationSession;
    
    @EJB
    private IWorkerManagerSessionLocal workerManagerSession;
    
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;

    /**
     * Constant indicating the Id of the "service loader" service.
     * Used in a clustered environment to periodically load available
     * services
     */
    private static final Integer SERVICELOADER_ID = new Integer(0);
    private static final long SERVICELOADER_PERIOD = 5 * 60 * 1000;

    /**
     * Default create for SessionBean without any creation Arguments.
     */
    @PostConstruct
    public void create() {
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
            sessionCtx.getTimerService().createTimer(SERVICELOADER_PERIOD, SERVICELOADER_ID);
            load(0);
        } else {
            ServiceConfig serviceConfig = null;
            ITimedService timedService = null;
            boolean run = false;
            boolean isSingleton = false;
            UserTransaction ut = sessionCtx.getUserTransaction();
            try {
                ut.begin();
                IWorker worker = workerManagerSession.getWorker(timerInfo.intValue(), globalConfigurationSession);
                if (worker != null) {
                    serviceConfig = new ServiceConfig(worker.getConfig());
                    timedService = (ITimedService) worker;
                    sessionCtx.getTimerService().createTimer(timedService.getNextInterval(), timerInfo);
                    isSingleton = timedService.isSingleton();
                    if (!isSingleton) {
                        run = true;
                    } else {
                        GlobalConfiguration gc = globalConfigurationSession.getGlobalConfiguration();
                        Date nextRunDate = new Date(0);
                        if (gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "SERVICENEXTRUNDATE" + timerInfo.intValue()) != null) {
                            nextRunDate = new Date(Long.parseLong(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "SERVICENEXTRUNDATE" + timerInfo.intValue())));
                        }
                        Date currentDate = new Date();
                        if (currentDate.after(nextRunDate)) {
                            nextRunDate = new Date(currentDate.getTime() + timedService.getNextInterval());
                            globalConfigurationSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "SERVICENEXTRUNDATE" + timerInfo.intValue(), "" + nextRunDate.getTime());
                            run = true;
                        }
                    }
                }
            } catch (NotSupportedException e) {
                LOG.error(e);
            } catch (SystemException e) {
                LOG.error(e);
            } catch (SecurityException e) {
                LOG.error(e);
            } catch (IllegalStateException e) {
                LOG.error(e);
            } finally {
                try {
                    ut.commit();
                } catch (RollbackException e) {
                    LOG.error(e);
                } catch (HeuristicMixedException e) {
                    LOG.error(e);
                } catch (HeuristicRollbackException e) {
                    LOG.error(e);
                } catch (SystemException e) {
                    LOG.error(e);
                }
            }

            if (run) {
                if (serviceConfig != null && timedService != null) {
                    try {
                        if (timedService.isActive() && timedService.getNextInterval() != ITimedService.DONT_EXECUTE) {
                            timedService.work();
                            serviceConfig.setLastRunTimestamp(new Date());
                            for (final ITimedService.LogType logType :
                                    timedService.getLogTypes()) {
                                switch (logType) {
                                    case INFO_LOGGING:
                                        LOG.info("Service " +
                                                timerInfo.intValue() +
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
                        LOG.error("Service" + timerInfo.intValue() + " execution failed. ", e);
                        
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
                    LOG.error("Service with id " + timerInfo.intValue() + " not found.");
                }
            } else {
                if (isSingleton) {
                    LOG.info("Service " + timerInfo.intValue() + " have been executed on another node in the cluster, waiting.");
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
        HashSet<Serializable> existingTimers = new HashSet<Serializable>();
        while (iter.hasNext()) {
            Timer timer = (Timer) iter.next();
            existingTimers.add(timer.getInfo());
        }

        final Collection<Integer> serviceIds;
        if (serviceId == 0) {
            serviceIds = workerManagerSession.getWorkers(GlobalConfiguration.WORKERTYPE_SERVICES, globalConfigurationSession);
        } else {
            serviceIds = new ArrayList<Integer>();
            serviceIds.add(new Integer(serviceId));
        }
        iter = serviceIds.iterator();
        while (iter.hasNext()) {
            Integer nextId = (Integer) iter.next();
            if (!existingTimers.contains(nextId)) {
                ITimedService timedService = (ITimedService) workerManagerSession.getWorker(nextId.intValue(), globalConfigurationSession);
                if (timedService != null && timedService.isActive() && timedService.getNextInterval() != ITimedService.DONT_EXECUTE) {
                    sessionCtx.getTimerService().createTimer((timedService.getNextInterval()), nextId);
                }
            }
        }

        if (!existingTimers.contains(SERVICELOADER_ID)) {
            // load the service timer
            sessionCtx.getTimerService().createTimer(SERVICELOADER_PERIOD, SERVICELOADER_ID);
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
                            if (((Integer) timer.getInfo()).intValue() == serviceId) {
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
     * Adds a timer to the bean
     */
    @Override
    public void addTimer(long interval, Integer id) {
        sessionCtx.getTimerService().createTimer(interval, id);
    }

    /**
     * cancels a timer with the given Id
     *
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
