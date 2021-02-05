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
package org.signserver.server.timedservices;

import java.text.ParseException;
import java.util.Date;
import java.util.EnumSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import javax.persistence.EntityManager;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.quartz.CronExpression;
import org.signserver.common.ServiceConfig;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.server.BaseWorker;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;

/**
 * TODO: Document me!
 *
 * @version $Id$
 */
public abstract class BaseTimedService extends BaseWorker implements ITimedService {

    /** Log4j instance for actual implementation class */
    private final transient Logger log = Logger.getLogger(this.getClass());

    private static final FastDateFormat FDF = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ss,SSS");

    private final Set<ITimedService.LogType> logTypes =
            EnumSet.noneOf(ITimedService.LogType.class);
    private final List<String> fatalErrors = new LinkedList<>();
    
    protected BaseTimedService() {
    }

    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        final String[] logTypeStrings =
                config.getPropertyThatCouldBeEmpty(ServiceConfig.WORK_LOG_TYPES,
                        ServiceConfig.DEFAULT_WORK_LOG_TYPES).split(",");
        for (final String logType : logTypeStrings) {
            final String logTypeTrimmed = logType.trim();
            if (!logTypeTrimmed.isEmpty()) {
                try {
                    logTypes.add(LogType.valueOf(logTypeTrimmed));
                } catch (IllegalArgumentException e) {
                    fatalErrors.add("Unknown log type: " + logType);
                }
            }
        }
    }
    
    

    /**
     * @see org.signserver.server.timedservices.ITimedService#getNextInterval()
     */
    @Override
    public long getNextInterval() {
        long retval = DONT_EXECUTE;
    	final String interval
                = config.getProperties().getProperty(ServiceConfig.INTERVAL);
        final String intervalMs
                = config.getProperties().getProperty(ServiceConfig.INTERVALMS);
    	final String cronExpression
                = config.getProperties().getProperty(ServiceConfig.CRON);

        if (interval == null && cronExpression == null && intervalMs == null) {
            log.warn("Neither an interval (in seconds or milliseconds) nor CRON expression defined for service with id: " + workerId);
        } else if ((interval != null && cronExpression != null)
                || (interval != null && intervalMs != null)
                || (cronExpression != null && intervalMs != null)) {
            log.error("More than on of " + ServiceConfig.INTERVAL + ", " + ServiceConfig.INTERVALMS + " and " + ServiceConfig.CRON + " specified for service with id: " + workerId);
        } else if (interval != null) {
            try {
                retval = Long.parseLong(interval) * 1000;
            } catch (NumberFormatException e) {
                log.error("Error in Service configuration, Interval must contains numbers only. Service id: " + workerId);
            }
        } else if (intervalMs != null) {
            try {
                retval = Long.parseLong(intervalMs);
            } catch (NumberFormatException e) {
                log.error("Error in Service configuration, Interval must contains numbers only. Service id: " + workerId);
            }
        } else if (cronExpression != null) {
            try {
                CronExpression ce = new CronExpression(cronExpression);
                Date nextDate = ce.getNextValidTimeAfter(new Date());
                retval = (long) (nextDate.getTime() - System.currentTimeMillis());
            } catch (ParseException e) {
                log.error("Error in Service configuration, illegal CRON expression : " + cronExpression + " defined for service with ID " + workerId);
            }
        }
        return retval;
    }

    /**
     * @see org.signserver.server.timedservices.ITimedService#isActive()
     */
    @Override
    public boolean isActive() {
        if (config.getProperties().getProperty(ServiceConfig.ACTIVE) == null) {
            return false;
        }

        String active = config.getProperties().getProperty(ServiceConfig.ACTIVE);

        return active.trim().equalsIgnoreCase("TRUE");
    }

    /**
     * @see org.signserver.server.timedservices.ITimedService#isSingleton()
     */
    @Override
    public boolean isSingleton() {
        if (config.getProperties().getProperty(ServiceConfig.SINGLETON) == null) {
            return false;
        }

        String active = config.getProperties().getProperty(ServiceConfig.SINGLETON);

        return active.trim().equalsIgnoreCase("TRUE");
    }

    @Override
    public WorkerStatusInfo getStatus(final List<String> additionalFatalErrors, final IServices services) {
        final List<String> fatalErrorsIncludingAdditionalErrors = new LinkedList<>(additionalFatalErrors);
        fatalErrorsIncludingAdditionalErrors.addAll(getFatalErrors(services));

        List<WorkerStatusInfo.Entry> briefEntries = new LinkedList<>();
        List<WorkerStatusInfo.Entry> completeEntries = new LinkedList<>();

        // Worker status
        briefEntries.add(new WorkerStatusInfo.Entry("Worker status", fatalErrorsIncludingAdditionalErrors.isEmpty() ? "Active" : "Offline"));
        briefEntries.add(new WorkerStatusInfo.Entry("Service was last run at", getLastRunDate()));

        // Properties
        final StringBuilder configValue = new StringBuilder();
        Properties properties = config.getProperties();
        for (String key : properties.stringPropertyNames()) {
            final String value = config.shouldMaskProperty(key) ?
                                 WorkerConfig.WORKER_PROPERTY_MASK_PLACEHOLDER :
                                 properties.getProperty(key);
            configValue.append("  ").append(key).append("=").append(value).append("\n\n");
        }
        completeEntries.add(new WorkerStatusInfo.Entry("Active Properties are", configValue.toString()));

        return new WorkerStatusInfo(workerId, config.getProperty("NAME"),
                                    "Service", WorkerStatus.STATUS_ACTIVE,
                                    briefEntries,
                                    fatalErrorsIncludingAdditionalErrors,
                                    completeEntries, config);
    }

    /**
     * @return the date this service was last run or an error message
     * if it has not run since the server started.
     */
    protected String getLastRunDate() {
        Date lastRun = new ServiceConfig(config).getLastRunTimestamp();

        if (lastRun == null) {
            return "Service does not seem to have run since start or reload of the server.";
        }

        return FDF.format(lastRun);
    }

    @Override
    protected List<String> getFatalErrors(IServices services) {
        final List<String> errors = new LinkedList<>(super.getFatalErrors(services));
        
        errors.addAll(fatalErrors);
        return errors;
    }

    @Override
    public Set<LogType> getLogTypes() {
        return logTypes;
    }
}
