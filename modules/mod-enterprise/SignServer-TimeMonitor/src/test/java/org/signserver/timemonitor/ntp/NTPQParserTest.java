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

import org.apache.log4j.Logger;

import junit.framework.TestCase;
import org.signserver.timemonitor.common.LeapState;

/**
 * Tests for the NTPQ command parser
 *
 * @author Marcus Lundblad
 * @version $Id: NTPQParserTest.java 5793 2013-09-04 12:08:50Z netmackan $
 *
 */

public class NTPQParserTest extends TestCase {

    /** Logger for this class */
    Logger LOG = Logger.getLogger(NTPQParser.class);

    /**
     * Tests the parse result.
     *
     * @throws Exception
     */
    public void testParse() throws Exception {
        NTPQParser instance = new NTPQParser();

        // Test error
        NTPQResult result = instance.parse(-1, "The error message", Collections.<String>emptyList());
        assertEquals(new NTPQResult(-1, "The error message", LeapState.UNKNOWN), result);

        // Test normal response with leap=00
        result = instance.parse(0, null, Arrays.asList("leap=00"));
        assertEquals(new NTPQResult(0, null, LeapState.NONE), result);

        // Test normal response with leap=01
        result = instance.parse(0, null, Arrays.asList("leap=01"));
        assertEquals(new NTPQResult(0, null, LeapState.POSITIVE), result);

        // Test normal response with leap=10
        result = instance.parse(0, null, Arrays.asList("leap=10"));
        assertEquals(new NTPQResult(0, null, LeapState.NEGATIVE), result);

        // Test error response with leap=11
        result = instance.parse(-1, "Some error", Arrays.asList("leap=11"));
        assertEquals(new NTPQResult(-1, "Some error", LeapState.UNKNOWN), result);

        // Run With the same error again to see that the message is not logged twice
        instance.parse(-1, "Some error", Arrays.asList("leap=11"));

        // Test with other (erronios code)
        result = instance.parse(-1, "Some other error", Arrays.asList("leap=42"));
        assertEquals(new NTPQResult(-1, "Some other error", LeapState.UNKNOWN), result);

        // Test with some unconformant result
        result = instance.parse(-1, "Very wrong", Arrays.asList("foobar"));
        assertEquals(new NTPQResult(-1, "Very wrong", LeapState.UNKNOWN), result);

        // Test with a more than one value (could happen with older versions of ntpq)
        result = instance.parse(0, null, Arrays.asList("leap=00, stratum=16"));
        assertEquals(new NTPQResult(0, null, LeapState.NONE), result);

        result = instance.parse(0, null, Arrays.asList("stratum=16, leap=00"));
        assertEquals(new NTPQResult(0, null, LeapState.NONE), result);

        // Test with multiple lines
        result = instance.parse(0, null, Arrays.asList("associd=0 status=c012", "stratum=16, leap=01"));
        assertEquals(new NTPQResult(0, null, LeapState.POSITIVE), result);

    }

}
