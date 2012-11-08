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
import java.util.LinkedList;
import java.util.List;
import org.apache.log4j.Logger;
import org.quartz.CronExpression;
import org.signserver.common.ServiceConfig;
import org.signserver.common.ServiceStatus;
import org.signserver.common.WorkerStatus;
import org.signserver.server.BaseWorker;

/**
 * TODO: Document me!
 *
 * @version $Id$
 */
public abstract class BaseTimedService extends BaseWorker implements ITimedService {

    /** Log4j instance for actual implementation class */
    private final transient Logger log = Logger.getLogger(this.getClass());

    protected BaseTimedService() {
    }

    /**
     * @see org.signserver.server.timedservices.ITimedService#getNextInterval()
     */
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
                log.error("Error in Service configuration, illegal CRON expression : " + cronExpression + " defined for service with id " + workerId);
            }
        }
        return retval;
    }

    /**
     * @see org.signserver.server.timedservices.ITimedService#isActive()
     */
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
    public boolean isSingleton() {
        if (config.getProperties().getProperty(ServiceConfig.SINGLETON) == null) {
            return false;
        }

        String active = config.getProperties().getProperty(ServiceConfig.SINGLETON);

        return active.trim().equalsIgnoreCase("TRUE");
    }

    @Override
    public WorkerStatus getStatus(final List<String> additionalFatalErrors) {
        final List<String> fatalErrors = new LinkedList<String>(additionalFatalErrors);
        fatalErrors.addAll(getFatalErrors());
        ServiceStatus retval = new ServiceStatus(workerId, fatalErrors, new ServiceConfig(config));

        return retval;
    }
}
