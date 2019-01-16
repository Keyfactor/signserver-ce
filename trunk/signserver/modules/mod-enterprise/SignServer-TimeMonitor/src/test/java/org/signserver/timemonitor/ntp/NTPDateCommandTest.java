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
package org.signserver.timemonitor.ntp;

import java.util.Arrays;
import java.util.List;
import junit.framework.TestCase;
import org.apache.log4j.Logger;

/**
 * Tests for the NTPDateCommand class.
 *
 * @author Markus Kilås
 * @version $Id: NTPDateCommandTest.java 5239 2013-05-13 10:56:21Z malu9369 $
 */
public class NTPDateCommandTest extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(NTPDateCommandTest.class);


    public NTPDateCommandTest(String testName) {
        super(testName);
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

//    The execute method is not easily tested as it requires the ntpdate command.
//    public void testExecute() throws Exception {
//        System.out.println("execute");
//        NTPDateCommand instance = null;
//        NTPDateResult expResult = null;
//        NTPDateResult result = instance.execute();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }

    /**
     * Test of getArguments method, of class NTPDateCommand.
     */
    @SuppressWarnings("UnusedAssignment")
    public void testGetArguments() {
        LOG.info("getArguments");
        NTPDateCommand instance = new NTPDateCommand("ntpdate", "host123");
        List<String> result = Arrays.asList(instance.getArguments());
        assertEquals(Arrays.asList("ntpdate", "-q", "host123"), result);

        instance = new NTPDateCommand("/usr/sbin/ntpdate", "127.0.1.2", 5, 0.356);
        result = Arrays.asList(instance.getArguments());
        assertEquals(Arrays.asList("/usr/sbin/ntpdate", "-q", "-p", "5", "-t", "0.356", "127.0.1.2"), result);

        // Test with a comma-separated host argument
        instance = new NTPDateCommand("/usr/sbin/ntpdate", "127.0.1.2, 127.0.1.3", 5, 0.356);
        result = Arrays.asList(instance.getArguments());
        assertEquals(Arrays.asList("/usr/sbin/ntpdate", "-q", "-p", "5", "-t", "0.356", "127.0.1.2", "127.0.1.3"), result);

        try {
            instance = new NTPDateCommand("ntpdate", null);
            fail("Should have failed as no host were specified");
        } catch (IllegalArgumentException ok) { // NOPMD
            // OK
        }
        try {
            instance = new NTPDateCommand("ntpdate", null, 5, 0.356);
            fail("Should have failed as no host were specified");
        } catch (IllegalArgumentException ok) { // NOPMD
            // OK
        }

        try {
            instance = new NTPDateCommand(null, "host1");
            fail("Should have failed as no executable were specified");
        } catch (IllegalArgumentException ok) { // NOPMD
            // OK
        }
        try {
            instance = new NTPDateCommand(null, "host1", 5, 0.356);
            fail("Should have failed as no executable were specified");
        } catch (IllegalArgumentException ok) { // NOPMD
            // OK
        }
    }
}
