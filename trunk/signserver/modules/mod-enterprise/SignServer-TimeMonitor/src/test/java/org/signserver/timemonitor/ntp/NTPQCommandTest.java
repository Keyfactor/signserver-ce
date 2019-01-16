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

import org.apache.log4j.Logger;

import junit.framework.TestCase;

/**
 * Tests for the NTPQ command
 *
 * @author Marcus Lundblad
 * @version $Id: NTPQCommandTest.java 4513 2012-12-05 14:13:40Z marcus $
 *
 */

public class NTPQCommandTest extends TestCase {

    /** Logger for this class */
    private Logger LOG = Logger.getLogger(NTPQCommandTest.class);

    /**
     * Test that the NTPQ command set the correct arguments.
     *
     * @throws Exception
     */
    public void testGetArguments() throws Exception {
        LOG.info("testGetArguments");
        // test
        NTPQCommand instance = new NTPQCommand("/usr/bin/ntpq", 0);

        List<String> result = Arrays.asList(instance.getArguments());

        assertEquals(Arrays.asList("/usr/bin/ntpq", "-c", "rv 0 leap"), result);
    }

}
