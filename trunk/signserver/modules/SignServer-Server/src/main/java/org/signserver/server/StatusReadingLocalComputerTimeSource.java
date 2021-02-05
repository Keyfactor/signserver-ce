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
package org.signserver.server;

import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.TimeZone;
import org.apache.log4j.Logger;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.server.log.LogMap;
import org.signserver.statusrepo.common.NoSuchPropertyException;
import org.signserver.statusrepo.common.StatusEntry;
import org.signserver.statusrepo.common.StatusName;
import org.signserver.statusrepo.StatusRepositorySessionLocal;

/**
 * ITimeSource taking the current time from the computer clock as long as the 
 * status property TIMESOURCE0_INSYNC is true and has not expired.
 *
 * It reads a status property TIMESOURCE0_INSYNC from the status repository.
 * Worker properties:
 * <b>LEAPSECOND_HANDLING</b>: How leap seconds should be handled. Could be 
 * NONE, PAUSE or STOP.
 * 
 *
 * @version $Id$
 */
public class StatusReadingLocalComputerTimeSource implements ITimeSource {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            StatusReadingLocalComputerTimeSource.class);

    private final StatusName insyncPropertyName = StatusName.TIMESOURCE0_INSYNC;
    private final StatusName leapsecondPropertyName = StatusName.LEAPSECOND;

    // property constants
    private static final String LEAPSECOND_HANDLING = "LEAPSECOND_HANDLING";
    
    // log values
    private static final String LEAP_UPCOMING = "LEAP_UPCOMING";
    private static final String LEAP_PERIOD = "LEAP_PERIOD";
    private static final String LEAP_ACTION = "LEAP_ACTION";

    /** defines leap second handling strategies */
    protected enum LeapSecondHandlingStrategy {
        /** Don't do anything special for leap seconds. **/
    	NONE,
        
        /** 
         * Pause during the potential leap second interval if there is a 
         * positive or negative leap second.
         * Fail if no information is available
         */
    	PAUSE,
        
        /**
         * Stop the issuance (return null) during the potential leap second 
         * interval if there is a positive or negative leap second.
         * Fail if no information is available.
         */
        STOP
    }
    
    private static final String LEAPSECOND_HANDLING_DEFAULT = "NONE";
   
    private String leapSecondHandlingString;
    private LeapSecondHandlingStrategy leapSecondHandlingStrategy;
    
    // number of milliseconds to sleep when waiting for a leapsecond to pass
    private static final int LEAPSECOND_WAIT_PERIOD = 500;
    
    // leapsecond property values
    protected static final String LEAPSECOND_NONE = "NONE";
    protected static final String LEAPSECOND_POSITIVE = "POSITIVE";
    protected static final String LEAPSECOND_NEGATIVE = "NEGATIVE";
    
    
    /**
     * @param props Properties for this TimeSource
     * @see org.signserver.server.ITimeSource#init(java.util.Properties)
     */
    @Override
    public void init(final Properties props) {
        leapSecondHandlingString = props.getProperty(LEAPSECOND_HANDLING, LEAPSECOND_HANDLING_DEFAULT);
        try {
            leapSecondHandlingStrategy =
                    LeapSecondHandlingStrategy.valueOf(leapSecondHandlingString);

            if (LOG.isDebugEnabled()) {
            	LOG.debug("Leap second handling strategy: " + leapSecondHandlingStrategy.name());
            }
        } catch (IllegalArgumentException ex) {
            LOG.error("Illegal value for leap second handling strategy: " + leapSecondHandlingString);
        }
    }

    /**
     * Main method that should retrieve the current time from the device.
     * @return an accurate current time or null if it is not available.
     */
    @Override
    public Date getGenTime(final RequestContext context) throws SignServerException {
        try {
            final Date result;
            final StatusRepositorySessionLocal statusSession = context.getServices().get(StatusRepositorySessionLocal.class);
            final StatusEntry entry = statusSession.getValidEntry(insyncPropertyName.name());
            
            final LogMap logMap = LogMap.getInstance(context);

            if (leapSecondHandlingStrategy == null) {
                throw new SignServerException("Illegal leap second strategy: " + leapSecondHandlingString);
            }
            
            logMap.put(LEAP_ACTION, leapSecondHandlingStrategy.name());

            if (entry != null && Boolean.valueOf(entry.getValue())) {
                Date date = getCurrentDate();                    
                // check if a leapsecond is near
                final StatusEntry leapsecond = statusSession.getValidEntry(leapsecondPropertyName.name());

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Check for leapsecond");
                }

                if (leapsecond == null) {
                    if (leapSecondHandlingStrategy == LeapSecondHandlingStrategy.NONE) {
                        result = date;
                    } else {
                        // leapsecond property is expired
                        LOG.error("Leapsecond status has expired");
                        result = null;
                    }
                    logMap.put(LEAP_PERIOD, String.valueOf(isPotentialLeapsecond(date)));
                    logMap.put(LEAP_UPCOMING, "unknown");
                } else {
                    final String leapsecondValue = leapsecond.getValue();
                    boolean potentialLeap = isPotentialLeapsecond(date);

                    logMap.put(LEAP_PERIOD, Boolean.toString(potentialLeap));

                    if (LEAPSECOND_POSITIVE.equals(leapsecondValue) ||
                        LEAPSECOND_NEGATIVE.equals(leapsecondValue)) {
                        
                        logMap.put(LEAP_UPCOMING, Boolean.TRUE.toString());

                        // Handle leap second strategy STOP
                        if (leapSecondHandlingStrategy == LeapSecondHandlingStrategy.STOP 
                                && potentialLeap) {
                            LOG.info("Stopping issuance");
                            result = null;
                        } else if (leapSecondHandlingStrategy ==
                                   LeapSecondHandlingStrategy.PAUSE) {
                            for (int i = 0; i < 6 && potentialLeap; i++) {
                                    // sleep for the amount of time nessesary to skip over the leap second
                                    try {
                                            LOG.info("Waiting for leapsecond to pass");

                                            pause();

                                            if (LOG.isDebugEnabled()) {
                                                LOG.debug("Pause finished");
                                            }

                                    } catch (InterruptedException ex) {
                                            // if the thread gets interrupted while pausing,
                                            // return time source not available
                                            LOG.error("Interrupted while pausing");
                                            potentialLeap = true;
                                            break;
                                    }

                                    date = getCurrentDate();
                                    potentialLeap = isPotentialLeapsecond(date);
                            }

                            if (potentialLeap) {
                                LOG.error("Still potentially leap second after maximum pause");
                                result = null;
                            } else {
                                result = date;
                            }
                        } else {
                            // Strategy == NONE
                            result = date;
                        }
                    } else {
                        logMap.put(LEAP_UPCOMING, Boolean.FALSE.toString());
                        result = date;
                    }
                }
            } else {
                logMap.put(LEAP_UPCOMING, "unknown");
                logMap.put(LEAP_PERIOD, "unknown");
                result = null;
            }
            return result;
        } catch (NoSuchPropertyException ex) {
            throw new RuntimeException(ex);
        }
    }
    
    /**
     * Get current timestamp date.
     * This is overridable for the unit test to allow
     * simulating leapsecond events.
     * 
     * @return Current date
     */
    protected Date getCurrentDate() {
        return new Date();
    }
    
    protected void pause() throws InterruptedException {
    	Thread.sleep(LEAPSECOND_WAIT_PERIOD);
    }

    /**
     * Sets the handle leapsecond-handling strategy.
     * This is available for the unit test.
     * 
     * @param leapSecondHandlingStrategy
     */
    protected void setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy leapSecondHandlingStrategy) {
        this.leapSecondHandlingStrategy = leapSecondHandlingStrategy;
    }
    
    /**
     * Returns true if passed in date is near a potential leapsecond
     * 
     * The following log time line describes timestamps from the beginning of
     * a leap second interval flagged by this method, to the end with the start and end of
     * positive and negative leap seconds marked within the overall interval.
     * 
	 * 2012-06-30 23:59:58,989 UTC <- interval start, negative start
	 * ...
	 * 2012-06-30 23:59:58,999 UTC <- negative end
	 * 2012-06-30 23:59:59,000 UTC <- positive start
	 * ...
	 * 2012-06-30 23:59:59,999 UTC <- positive end
     * 2012-07-01 00:00:00,000 UTC <- leap bug workaround start
	 * ...
     * 2012-07-01 00:00:00,999 UTC <- leap bug workaround end
     * ...
	 * 2012-07-01 00:00:01,010 UTC <- interval end
     * 
     * @param date
     * @return true if possible leapsecond
     */
    protected static boolean isPotentialLeapsecond(final Date date) {
        final Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        
        cal.setTime(date);

        final int day = cal.get(Calendar.DAY_OF_MONTH);
        final int hour = cal.get(Calendar.HOUR_OF_DAY);
        final int min = cal.get(Calendar.MINUTE);
        final int sec = cal.get(Calendar.SECOND);
        final int milli = cal.get(Calendar.MILLISECOND);
        
        final int lastDayOfMonth = cal.getActualMaximum(Calendar.DAY_OF_MONTH);
        
        // check for the first two seconds following
        // a potential leapsecond month-shift
        return (day == 1 && hour == 0 && min == 0 && sec <= 1 && milli <= 10) ||
        	(day == lastDayOfMonth && hour == 23 && min == 59 && ((sec == 58 && milli >= 989) || sec >= 59));
    }
   
    @Override
    public List<WorkerStatusInfo.Entry> getStatusBriefEntries() {
        return Collections.singletonList(
                new WorkerStatusInfo.Entry("Leapsecond strategy",
                                           leapSecondHandlingStrategy != null ?
                                           leapSecondHandlingStrategy.name() :
                                           "invalid"));
    }
    
    @Override
    public List<WorkerStatusInfo.Entry> getStatusCompleteEntries() {
        return Collections.emptyList();
    }
}
