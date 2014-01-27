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
import java.util.Map;
import java.util.TimeZone;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.signserver.server.StatusReadingLocalComputerTimeSource.LeapSecondHandlingStrategy;
import org.signserver.statusrepo.IStatusRepositorySession;
import org.signserver.statusrepo.common.NoSuchPropertyException;
import org.signserver.statusrepo.common.StatusEntry;
import org.signserver.statusrepo.common.StatusName;

/**
 * Tests the leapsecond support in status-reading local timesource.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */

public class StatusReadingLocalComputerTimeSourceTest extends TestCase {

    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(StatusReadingLocalComputerTimeSourceTest.class);
    
    private void assertPotentialLeapsecond(int year, int month, int day, int hour, int min, int sec, int milli) {
        Date date;
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        
        cal.set(year, month - 1, day, hour, min, sec);
        cal.set(Calendar.MILLISECOND, milli);
        date = cal.getTime();
        
        assertTrue("Should detect possible leapsecond: " + date.toString(), StatusReadingLocalComputerTimeSource.isPotentialLeapsecond(date));
    }
    
    private void assertNotPotentialLeapsecond(int year, int month, int day, int hour, int min, int sec, int milli) {
        Date date;
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        
        cal.set(year, month - 1, day, hour, min, sec);
        cal.set(Calendar.MILLISECOND, milli);
        date = cal.getTime();
        
        assertFalse("Should not detect possible leapsecond: " + date.toString(), StatusReadingLocalComputerTimeSource.isPotentialLeapsecond(date));
    }
    
    /**
     * Test that the last second of December is detected as a potential leapsecond event.
     * 
     * @throws Exception
     */
    public void test01PotentialLeapSecondDecember() throws Exception {
        LOG.info("test01PotentialLeapSecondDecember");
        assertPotentialLeapsecond(2012, 12, 31, 23, 59, 59, 0);
    }
    
    /**
     * Test that the last second of June is detected as a potential leapsecond event.
     * 
     * @throws Exception
     */
    public void test02PotentialLeapSecondJune() throws Exception {
        LOG.info("test02PotentialLeapSecondJune");
        assertPotentialLeapsecond(2013, 6, 30, 23, 59, 59, 0);
    }
    
    /**
     * Test that the second second of January is detected as a potential leapsecond event.
     * (an interval around the actual second should be detected).
     * 
     * @throws Exception
     */
    public void test03PotentialLeapSecondJanuary() throws Exception {
        LOG.info("test03PotentialLeapSecondJanuary");
        assertPotentialLeapsecond(2013, 1, 1, 0, 0, 1, 0);
    }
    
    /**
     * Test that another arbitrary date is not detected as a potential leapsecond event.
     * 
     * @throws Exception
     */
    public void test04NotPotentialLeapSecondOther() throws Exception {
        LOG.info("test04NotPotentialLeapSecondOther");
        assertNotPotentialLeapsecond(2013, 4, 7, 12, 47, 11, 0);
    }
    
    
    /** 
     * Tests that requesting time when a leap second is near,
     * the time is returned right after for the PAUSE strategy and
     * directly returns null for the STOP strategy.
     */
    public void test05RequestTimeBeforeLeapsecond() throws Exception {
        LOG.info("test05RequestTimeBeforeLeapsecond");
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        cal.set(2012, 11, 31, 23, 59, 59);
        
        // Strategy: PAUSE
        MockTimeSource timeSource = new MockTimeSource(cal.getTime());
        timeSource.setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy.PAUSE);
        timeSource.setStatusSession(new LeapsecondStatusRepositorySession(StatusReadingLocalComputerTimeSource.LEAPSECOND_POSITIVE));
        
        Date date = timeSource.getGenTime();
        assertTrue("Timesource did not pause", timeSource.pauseCalled);
        assertNotNull("Should get a time", date);
        
        // Strategy: STOP
        timeSource = new MockTimeSource(cal.getTime());
        timeSource.setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy.STOP);
        timeSource.setStatusSession(new LeapsecondStatusRepositorySession(StatusReadingLocalComputerTimeSource.LEAPSECOND_POSITIVE));
        
        date = timeSource.getGenTime();
        assertFalse("Timesource should not pause", timeSource.pauseCalled);
        assertNull("Should not get a time", date);
    }
    
    /**
     * Test that requesting time when a negative leap second is near,
     * the time is returned right after.
     * Test that the time source is causing a pause.
     */
    public void test06RequestTimeBeforeNegativeLeapsecond() throws Exception {
        LOG.info("test06RequestTimeBeforeNegativeLeapsecond");
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        // set just before the leap second start
        // (in the negative case this is 23:59:59)
        // to simulate the real case
        cal.set(2012, 11, 31, 23, 59, 58);
        cal.add(Calendar.MILLISECOND, 990);
  
        // Strategy: PAUSE
        MockTimeSource timeSource = new MockTimeSource(cal.getTime());
        timeSource.setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy.PAUSE);
        timeSource.setStatusSession(new LeapsecondStatusRepositorySession(StatusReadingLocalComputerTimeSource.LEAPSECOND_NEGATIVE));
        
        Date date = timeSource.getGenTime();
        assertTrue("Timesource did not pause", timeSource.pauseCalled);
        assertNotNull("Should get a time", date);
        
        // Strategy: STOP
        timeSource = new MockTimeSource(cal.getTime());
        timeSource.setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy.STOP);
        timeSource.setStatusSession(new LeapsecondStatusRepositorySession(StatusReadingLocalComputerTimeSource.LEAPSECOND_NEGATIVE));
        
        date = timeSource.getGenTime();
        assertFalse("Timesource should not pause", timeSource.pauseCalled);
        assertNull("Should not get a time", date);
    }
    
    /** 
     * Test that requesting time when a leap second is not imminent
     * does not cause an extra sleep and the time is returned.
     */
    public void test07RequestTimeNoLeapsecond() throws Exception {
        LOG.info("test07RequestTimeNoLeapsecond");
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        cal.set(2013, 0, 16, 23, 59, 59);
        
        // Strategy: PAUSE
    	MockTimeSource timeSource = new MockTimeSource(cal.getTime());
        timeSource.setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy.PAUSE);
        timeSource.setStatusSession(new LeapsecondStatusRepositorySession(StatusReadingLocalComputerTimeSource.LEAPSECOND_NEGATIVE));
        
        Date date = timeSource.getGenTime();
        assertFalse("Should not paused", timeSource.pauseCalled);
        assertNotNull("Should get a time", date);
        
        // Strategy: STOP
    	timeSource = new MockTimeSource(cal.getTime());
        timeSource.setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy.STOP);
        timeSource.setStatusSession(new LeapsecondStatusRepositorySession(StatusReadingLocalComputerTimeSource.LEAPSECOND_NEGATIVE));
        
        date = timeSource.getGenTime();
        assertFalse("Should not paused", timeSource.pauseCalled);
        assertNotNull("Should get a time", date);
    }
    
    /** 
     * Test that requesting time when leap second set to "NONE"
     * does not cause an extra sleep.
     */
    public void test08RequestTimeNoLeapsecond() throws Exception {
        LOG.info("test08RequestTimeNoLeapsecond");
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        cal.set(2012, 11, 31, 23, 59, 59);
        
        // Strategy: PAUSE
        MockTimeSource timeSource = new MockTimeSource(cal.getTime());
        timeSource.setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy.PAUSE);
        timeSource.setStatusSession(new LeapsecondStatusRepositorySession(StatusReadingLocalComputerTimeSource.LEAPSECOND_NONE));
        
        Date date = timeSource.getGenTime();
        assertFalse("Timesource paused", timeSource.pauseCalled);
        assertNotNull("Should get a time", date);
        
        // Strategy: STOP
        timeSource = new MockTimeSource(cal.getTime());
        timeSource.setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy.STOP);
        timeSource.setStatusSession(new LeapsecondStatusRepositorySession(StatusReadingLocalComputerTimeSource.LEAPSECOND_NONE));
        
        date = timeSource.getGenTime();
        assertFalse("Timesource paused", timeSource.pauseCalled);
        assertNotNull("Should get a time", date);
    }
    
    /** 
     * Test that requesting time when leapsecond is coming up, but time source is configured
     * not to handle leapseconds, does not cause an extra sleep.
     */
    public void test09RequestTimeLeapsecondNotHandled() throws Exception {
        LOG.info("test09RequestTimeLeapsecondNotHandled");
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        cal.set(2012, 11, 31, 23, 59, 59);
        final MockTimeSource timeSource =
        		new MockTimeSource(cal.getTime());
  
        timeSource.setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy.NONE);
        timeSource.setStatusSession(new LeapsecondStatusRepositorySession(StatusReadingLocalComputerTimeSource.LEAPSECOND_POSITIVE));

        final Date date = timeSource.getGenTime();
        assertFalse("Timesource paused", timeSource.pauseCalled);
        assertNotNull("Should get a time", date);
    }
    
    /** 
     * Test that the time source returns null when the status property is not available.
     */
    public void test10RequestTimeLeapsecondNotHandled() throws Exception {
        LOG.info("test10RequestTimeLeapsecondNotHandled");
    	Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        cal.set(2012, 11, 31, 23, 59, 59);
        
        // Strategy: PAUSE
        MockTimeSource timeSource = new MockTimeSource(cal.getTime());
        timeSource.setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy.PAUSE);
        timeSource.setStatusSession(new LeapsecondStatusRepositorySession(null));
        
        Date date = timeSource.getGenTime();
        assertNull("Should not get a time", date);
        
        // Strategy: STOP
        timeSource = new MockTimeSource(cal.getTime());
        timeSource.setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy.STOP);
        timeSource.setStatusSession(new LeapsecondStatusRepositorySession(null));
        
        date = timeSource.getGenTime();
        assertNull("Should not get a time", date);
    }
    
    /** 
     * Test that requesting time when a leap second is near,
     * but with the time stamp near midnight, but in the local time zone
     * Test that the time source is not pausing in this case.
     */
    public void test11RequestTimeLocalTimezone() throws Exception {
        LOG.info("test11RequestTimeLocalTimezone");
    	Calendar cal = Calendar.getInstance();
        cal.set(2012, 11, 31, 23, 59, 59);
        
        // Strategy: PAUSE
        MockTimeSource timeSource = new MockTimeSource(cal.getTime());
        timeSource.setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy.PAUSE);
        timeSource.setStatusSession(new LeapsecondStatusRepositorySession(StatusReadingLocalComputerTimeSource.LEAPSECOND_POSITIVE));
        
        Date date = timeSource.getGenTime();
        assertFalse("Should not pause", timeSource.pauseCalled);
        assertNotNull("Should get a time", date);
        
        // Strategy: STOP
        timeSource = new MockTimeSource(cal.getTime());
        timeSource.setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy.STOP);
        timeSource.setStatusSession(new LeapsecondStatusRepositorySession(StatusReadingLocalComputerTimeSource.LEAPSECOND_POSITIVE));
        
        date = timeSource.getGenTime();
        assertFalse("Should not pause", timeSource.pauseCalled);
        assertNotNull("Should get a time", date);
    }
    
    /** 
     * Test that requesting time when a leap second is near,
     * but with the time stamp near midnight, but in a non-GMT.
     * Test that the time source is not pausing in this case
     */
    public void test12RequestTimeOtherTimezone() throws Exception {
        LOG.info("test12RequestTimeOtherTimezone");
    	Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT+5:00"));
        cal.set(2012, 11, 31, 23, 59, 59);
        
        // Strategy: PAUSE
        MockTimeSource timeSource = new MockTimeSource(cal.getTime());
        timeSource.setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy.PAUSE);
        timeSource.setStatusSession(new LeapsecondStatusRepositorySession(StatusReadingLocalComputerTimeSource.LEAPSECOND_POSITIVE));
        
        Date date = timeSource.getGenTime();
        assertFalse("Timesource paused", timeSource.pauseCalled);
        assertNotNull("Should get a time", date);
        
        // Strategy: STOP
        timeSource = new MockTimeSource(cal.getTime());
        timeSource.setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy.STOP);
        timeSource.setStatusSession(new LeapsecondStatusRepositorySession(StatusReadingLocalComputerTimeSource.LEAPSECOND_POSITIVE));
        
        date = timeSource.getGenTime();
        assertFalse("Timesource paused", timeSource.pauseCalled);
        assertNotNull("Should get a time", date);
    }
    
    /**
     * Tests that a time in last second of february of a non-leapyear is correctly
     * detected as a potential leap second.
     * 
     * @throws Exception
     */
    public void test13PotentialLeapSecondFebruaryNonLeapYear() throws Exception {
        LOG.info("test13PotentialLeapSecondFebruaryNonLeapYear");
    	assertPotentialLeapsecond(2013, 2, 28, 23, 59, 59, 0);
    }
    
    /**
     * Tests that 29 february is detected as a potential leapsecond occurance on a leap year.
     * 
     * @throws Exception
     */
    public void test14PotentialLeapSecondFebruaryLeapYear() throws Exception {
        LOG.info("test14PotentialLeapSecondFebruaryLeapYear");
    	assertPotentialLeapsecond(2012, 2, 29, 23, 59, 59, 0);
    }
    
    /**
     * Tests that 28 february is not detected as a potential leapsecond occurance on a leap year.
     * 
     * @throws Exception
     */
    public void test15NotPotentialLeapSecond28Feb() throws Exception {
        LOG.info("test15NotPotentialLeapSecond28Feb");
    	assertNotPotentialLeapsecond(2012, 2, 28, 23, 59, 59, 0);
    }
    
    /**
     * Tests that 23:59:58,990 is detected as a potential leap second event (23:59:59 will not occur
     * if there is a negative leap second).
     * 
     * @throws Exception
     */
    public void test16PotentialLeapSecondNegative() throws Exception {
        LOG.info("test16PotentialLeapSecondNegative");
        assertPotentialLeapsecond(2012, 12, 31, 23, 59, 58, 990);
    }
    
    /**
     * Tests the border case time of 23:59:57,999.
     * Should not be flagged as a leap second event-
     * 
     * @throws Exception
     */
    public void test17NotPotentialLeapSecondJustBefore() throws Exception {
        LOG.info("test17NotPotentialLeapSecondJustBefore");
        assertNotPotentialLeapsecond(2012, 12, 31, 23, 59, 57, 999);
    }
    
    /**
     * Tests the border case time of 00:00:02,000
     * 
     * @throws Exception
     */
    public void test18NotPotentialLeapSecondJustAfter() throws Exception {
        LOG.info("test18NotPotentialLeapSecondJustAfter");
        assertNotPotentialLeapsecond(2013, 1, 1, 0, 0, 2, 0);
    }
    
    /** Tests the border case time of 00:00:01,010
     * 
     * @throws Exception
     */
    public void test19PotentialLeapSecondLastMilliSecond() throws Exception {
        LOG.info("test19PotentialLeapSecondLastMilliSecond");
        assertPotentialLeapsecond(2013, 1, 1, 0, 0, 1, 010);
    }
    
    /** 
     * Test that requesting time when a negative leapsecond is near,
     * the time is returned right after for the PAUSE strategy and returned 
     * null for the STOP strategy.
     */
    public void test20RequestTimeBeforePositiveLeapsecond() throws Exception {  
        LOG.info("test20RequestTimeBeforePositiveLeapsecond");
        
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        // set just before the leap second start
        // (in the negative case this is 23:59:59)
        // to simulate the real case
        cal.set(2012, 11, 31, 23, 59, 58);
        cal.add(Calendar.MILLISECOND, 990);
        
        // Strategy: PAUSE
        MockTimeSource timeSource = new MockTimeSource(cal.getTime());
        timeSource.setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy.PAUSE);
        timeSource.setStatusSession(new LeapsecondStatusRepositorySession(StatusReadingLocalComputerTimeSource.LEAPSECOND_POSITIVE));
        
        Date date = timeSource.getGenTime();
        assertTrue("Should pause", timeSource.pauseCalled);
        assertNotNull("Should get a time", date);
        
        // Strategy: STOP
        timeSource = new MockTimeSource(cal.getTime());
        timeSource.setLeapSecondHandlingStrategy(LeapSecondHandlingStrategy.STOP);
        timeSource.setStatusSession(new LeapsecondStatusRepositorySession(StatusReadingLocalComputerTimeSource.LEAPSECOND_POSITIVE));
        
        date = timeSource.getGenTime();
        assertFalse("Should not pause", timeSource.pauseCalled);
        assertNull("Should not get a time", date);
    }
    
    /**
     * Base class for status repository mockups.
     */
    private class LeapsecondStatusRepositorySession implements IStatusRepositorySession {
        private final String leapsecondType;
        
        LeapsecondStatusRepositorySession(final String leapsecondType) {
        	this.leapsecondType = leapsecondType;
        }
        
        @Override
        public StatusEntry getValidEntry(String key)
                throws NoSuchPropertyException {
            long time = new Date().getTime();
            if (StatusName.LEAPSECOND.name().equals(key)) {
            	if (leapsecondType == null) {
            		return null;
            	} else {
            		// return a status entry valid for an hour, we won't actually expire it, but for good measure...
            		return new StatusEntry(time, leapsecondType, time + 3600 * 1000);
            	}
            } else if (StatusName.TIMESOURCE0_INSYNC.name().equals(key)) {
                return new StatusEntry(time, Boolean.TRUE.toString(), time + 3600 * 1000);
            }
            return null;
        }
    	
    	@Override
        public void update(String key, String value)
                throws NoSuchPropertyException {
            throw new UnsupportedOperationException("Not implemented");
            
        }

        @Override
        public void update(String key, String value, long expiration)
                throws NoSuchPropertyException {
            throw new UnsupportedOperationException("Not implemented");
            
        }

        @Override
        public Map<String, StatusEntry> getAllEntries() {
            throw new UnsupportedOperationException("Not implemented");
        }

    }

    /**
     * Mockup time source with a configurable time and keeps track of
     * calls to the pause method.
     *
     */
    private class MockTimeSource extends StatusReadingLocalComputerTimeSource {
    	protected boolean pauseCalled;
    	private Date time;
    	
    	public MockTimeSource(final Date time) {
    		this.time = time;
    	}
    	
    	@Override
    	public Date getCurrentDate() {
    		return time;
    	}
    	
    	@Override
    	public void pause() {
    	    time = new Date(time.getTime() + 500);
    	    pauseCalled = true;
    		
    	}
    }
}
