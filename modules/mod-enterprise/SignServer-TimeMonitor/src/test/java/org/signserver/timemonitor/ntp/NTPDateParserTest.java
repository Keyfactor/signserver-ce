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
import java.util.Collections;
import junit.framework.TestCase;
import org.apache.log4j.Logger;

/**
 * Tests for the NTPDateParser class.
 *
 * @author Markus Kilås
 * @version $Id: NTPDateParserTest.java 5792 2013-09-04 11:40:45Z netmackan $
 */
public class NTPDateParserTest extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(NTPDateParserTest.class);

    public NTPDateParserTest(String testName) {
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

    /**
     * Test of parse method, of class NTPDateParser.
     */
    public void testParse() {
        LOG.info("parse");

        NTPDateParser instance = new NTPDateParser();

        // Test error
        NTPDateResult result = instance.parse(-1, "The error message", Collections.<String>emptyList());
        assertEquals(new NTPDateResult(-1, "The error message", null, 16, Double.NaN, Double.NaN, false), result);

        // Test error
        result = instance.parse(1, null, Arrays.asList(
                "Error resolving 192.168.13.278: Name or service not known (-2)",
                "1 Nov 20:46:54 ntpdate[4617]: Can't find host 192.168.13.278: Name or service not known (-2)",
                "1 Nov 20:46:54 ntpdate[4617]: no servers can be used, exiting,"));
        assertEquals("exit code", 1, result.getExitCode());
        assertEquals("stratum", 16, result.getStratum());
        assertEquals("offset", Double.NaN, result.getOffset());
        assertEquals("delay", Double.NaN, result.getDelay());
        assertFalse("rate limiting status", result.isRateLimited());

        // Test normal response
        result = instance.parse(0, null, Arrays.asList("server 192.168.13.200, stratum 3, offset -0.000867, delay 0.02814", " 1 Nov 20:43:51 ntpdate[4529]: adjust time server 192.168.13.200 offset -0.000867 sec"));
        assertEquals("exit code", 0, result.getExitCode());
        assertEquals("server", "192.168.13.200", result.getServer());
        assertEquals("stratum", 3, result.getStratum());
        assertEquals("offset", -0.000867, result.getOffset());
        assertEquals("delay", 0.02814, result.getDelay());
        assertFalse("rate limiting status", result.isRateLimited());

        // Test normal response
        result = instance.parse(0, null, Arrays.asList("server 192.168.14.200, stratum 2, offset 0.001167, delay 0.12317"));
        assertEquals("exit code", 0, result.getExitCode());
        assertEquals("server", "192.168.14.200", result.getServer());
        assertEquals("stratum", 2, result.getStratum());
        assertEquals("offset", 0.001167, result.getOffset());
        assertEquals("delay", 0.12317, result.getDelay());

        // Test response with several server results, first with stratum reported as 0 (unavailable server)
        result = instance.parse(0, null, Arrays.asList("server 192.168.15.200, stratum 0, offset 0.000000, delay 0.00000",
                "server 192.168.16.200, stratum 2, offset 0.004711, delay 0.04478"));
        assertEquals("exit code", 0, result.getExitCode());
        assertEquals("server", "192.168.16.200", result.getServer());
        assertEquals("stratum", 2, result.getStratum());
        assertEquals("offset", 0.004711, result.getOffset());
        assertEquals("delay", 0.04478, result.getDelay());
        assertFalse("rate limiting status", result.isRateLimited());

        // Test response with serveral valid responses, should pick the first one
        result = instance.parse(0, null, Arrays.asList("server 192.168.15.200, stratum 3, offset 0.005781, delay 0.03389",
                "server 192.168.16.200, stratum 2, offset 0.004711, delay 0.04478"));
        assertEquals("exit code", 0, result.getExitCode());
        assertEquals("server", "192.168.15.200", result.getServer());
        assertEquals("stratum", 3, result.getStratum());
        assertEquals("offset", 0.005781, result.getOffset());
        assertEquals("delay", 0.03389, result.getDelay());
        assertFalse("rate limiting status", result.isRateLimited());

        // Test response with second server not responding
        result = instance.parse(0, null, Arrays.asList("server 192.168.15.200, stratum 3, offset 0.005781, delay 0.03389",
                "server 192.168.16.200, stratum 0, offset 0.000000, delay 0.00000"));
        assertEquals("exit code", 0, result.getExitCode());
        assertEquals("server", "192.168.15.200", result.getServer());
        assertEquals("stratum", 3, result.getStratum());
        assertEquals("offset", 0.005781, result.getOffset());
        assertEquals("delay", 0.03389, result.getDelay());
        assertFalse("rate limiting status", result.isRateLimited());

        // Test response with several server results, both with stratum reported as 0 (unavailable server)
        result = instance.parse(0, null, Arrays.asList(
                "server 192.168.30.25, stratum 0, offset 0.000000, delay 0.00000",
                "server 192.168.30.25, stratum 0, offset 0.000000, delay 0.00000",
                " 4 Sep 13:32:27 ntpdate[12458]: no server suitable for synchronization found"));
        assertEquals("exit code", 0, result.getExitCode());
        assertEquals("stratum", 0, result.getStratum());
        assertEquals("offset", 0.0, result.getOffset());
        assertEquals("delay", 0.0, result.getDelay());
        assertTrue(result.getErrorMessage().contains("Server didn't respond: server 192.168.30.25"));
        assertFalse("rate limiting status", result.isRateLimited());
        
        // Test response with kiss-of-death
        result = instance.parse(1, "192.168.30.25 rate limit response from server.",
                Collections.<String>emptyList());
        assertTrue("rate limiting status", result.isRateLimited());
    }
}
