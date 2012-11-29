package org.signserver.server;

import java.util.Calendar;
import java.util.Date;
import junit.framework.TestCase;

/**
 * Tests the leapsecond support in status-reading local timesource.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */

public class StatusReadingLocalComputerTimeSourceTest extends TestCase {

    
    private void assertPotentialLeapsecond(int year, int month, int day, int hour, int min, int sec) {
        Date date;
        Calendar cal = Calendar.getInstance();
        
        cal.set(year, month - 1, day, hour, min, sec);
        date = cal.getTime();
        
        assertTrue("Should detect possible leapsecond: " + date.toString(), StatusReadingLocalComputerTimeSource.isPotentialLeapsecond(date));
    }
    
    private void assertNotPotentialLeapsecond(int year, int month, int day, int hour, int min, int sec) {
        Date date;
        Calendar cal = Calendar.getInstance();
        
        cal.set(year, month - 1, day, hour, min, sec);
        date = cal.getTime();
        
        assertFalse("Should not detect possible leapsecond: " + date.toString(), StatusReadingLocalComputerTimeSource.isPotentialLeapsecond(date));
    }
    
    /**
     * Test that the last second of December is detected as a potential leapsecond event.
     * 
     * @throws Exception
     */
    public void test01PotentialLeapSecondDecember() throws Exception {
        assertPotentialLeapsecond(2012, 12, 31, 23, 59, 59);
    }
    
    /**
     * Test that the last second of June is detected as a potential leapsecond event.
     * 
     * @throws Exception
     */
    public void test02PotentialLeapSecondJune() throws Exception {
        assertPotentialLeapsecond(2013, 6, 30, 23, 59, 59);
    }
    
    /**
     * Test that the first second of January is detected as a potential leapsecond event.
     * (an interval around the actual second should be detected).
     * 
     * @throws Exception
     */
    public void test03PotentialLeapSecondJanuary() throws Exception {
        assertPotentialLeapsecond(2013, 1, 1, 0, 0, 0);
    }
    
    /**
     * Test that another arbitrary date is not detected as a potential leapsecond event.
     * 
     * @throws Exception
     */
    public void test04NotPotentialLeapSecondOther() throws Exception {
        assertNotPotentialLeapsecond(2013, 4, 7, 12, 47, 11);
    }
}
