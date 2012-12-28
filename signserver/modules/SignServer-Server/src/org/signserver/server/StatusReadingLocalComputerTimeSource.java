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
import java.util.Date;
import java.util.Properties;
import java.util.TimeZone;
import javax.ejb.EJB;
import javax.naming.NamingException;
import org.apache.log4j.Logger;
import org.signserver.common.ServiceLocator;
import org.signserver.statusrepo.IStatusRepositorySession;
import org.signserver.statusrepo.common.NoSuchPropertyException;
import org.signserver.statusrepo.common.StatusEntry;
import org.signserver.statusrepo.common.StatusName;

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
 * $Id$
 */
public class StatusReadingLocalComputerTimeSource implements ITimeSource {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            StatusReadingLocalComputerTimeSource.class);

    /** Status repository session. */
    @EJB
    private IStatusRepositorySession statusSession;

    private StatusName insyncPropertyName = StatusName.TIMESOURCE0_INSYNC;
    private StatusName leapsecondPropertyName = StatusName.LEAPSECOND;

    // property constants
    private static final String LEAPSECOND_HANDLING = "LEAPSECOND_HANDLING";
    
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
        final String leapHandling = props.getProperty(LEAPSECOND_HANDLING, LEAPSECOND_HANDLING_DEFAULT);
        try {
            statusSession = ServiceLocator.getInstance().lookupRemote(
                        IStatusRepositorySession.IRemote.class);
            leapSecondHandlingStrategy = LeapSecondHandlingStrategy.valueOf(leapHandling);

            if (LOG.isDebugEnabled()) {
            	LOG.debug("Leap second handling strategy: " + leapSecondHandlingStrategy.name());
            }
        } catch (IllegalArgumentException ex) {
            LOG.error("Illegal value for leap second handling strategy: " + leapHandling);
        } catch (NamingException ex) {
            LOG.error("Looking up status repository session", ex);
        }
    }

    /**
     * Main method that should retrieve the current time from the device.
     * @return an accurate current time or null if it is not available.
     */
    @Override
    public Date getGenTime() {
        try {
            Date date;
            final StatusEntry entry = statusSession.getValidEntry(insyncPropertyName.name());
            
            if (entry != null && Boolean.valueOf(entry.getValue())) {
                date = getCurrentDate();
                
                // If we are handling leap seconds
                if (leapSecondHandlingStrategy == LeapSecondHandlingStrategy.PAUSE
                        || leapSecondHandlingStrategy == LeapSecondHandlingStrategy.STOP) {
                    
                    // check if a leapsecond is near
                    final StatusEntry leapsecond = statusSession.getValidEntry(leapsecondPropertyName.name());
                    
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Check for leapsecond");
                    }
                    
                    if (leapsecond == null) {
                        // leapsecond property is expired
                        LOG.error("Leapsecond status has expired");
                        return null;
                    }
                    
                    final String leapsecondValue = leapsecond.getValue();
                    if (LEAPSECOND_POSITIVE.equals(leapsecondValue) ||
                        LEAPSECOND_NEGATIVE.equals(leapsecondValue)) {
                        boolean potentialLeap = isPotentialLeapsecond(date);
                        
                        // Handle leap second strategy STOP
                        if (leapSecondHandlingStrategy == LeapSecondHandlingStrategy.STOP 
                                && potentialLeap) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Stopping issuance");
                            }
                            return null;
                        }
                        
                    	for (int i = 0; i < 6 && potentialLeap; i++) {
                    		// sleep for the amount of time nessesary to skip over the leap second
                    		try {
                    			if (LOG.isDebugEnabled()) {
                    			    LOG.debug("Waiting for leapsecond to pass");
                    			}

                    			pause();
                    	
                    			if (LOG.isDebugEnabled()) {
                    			    LOG.debug("Pause finished");
                    			}
                    			
                    		} catch (InterruptedException ex) {
                    			// if the thread gets interrupted while pausing,
                    			// return time source not available
                    			LOG.error("Interrupted while pausing");
                    			return null;
                    		}
                        
                    		date = getCurrentDate();
                    		potentialLeap = isPotentialLeapsecond(date);
                    	}
                    	
                    	if (potentialLeap) {
                    	    LOG.error("Still potentially leap second after maximum pause");
                    	    return null;
                    	}
                    	
                    	return date;
                    }
                }
                
            } else {
                date = null;
            }
            return date;
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
     * Set the status session.
     * This is visible for the unit test
     * 
     * @param statusSession
     */
    protected void setStatusSession(final IStatusRepositorySession statusSession) {
        this.statusSession = statusSession;
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
        if ((day == 1 && hour == 0 && min == 0 && sec <= 1 && milli <= 10) ||
        	(day == lastDayOfMonth && hour == 23 && min == 59 && ((sec == 58 && milli >= 989) || sec >= 59))) {
        	return true;
        }

        return false;
    }

}
