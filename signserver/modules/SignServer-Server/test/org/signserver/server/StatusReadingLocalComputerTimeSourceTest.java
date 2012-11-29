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

    
    /**
     * Test that the last second of December is detected as a potential leapsecond event
     */
    public void test01PotentialLeapSecondDecember() throws Exception {
        Date date;
        Calendar cal = Calendar.getInstance();
        
        cal.set(2012, 11, 31, 23, 59, 59);
        date = cal.getTime();
        
        assertTrue("Should detect possible leapsecond", StatusReadingLocalComputerTimeSource.isPotentialLeapsecond(date));
    }
    
}
