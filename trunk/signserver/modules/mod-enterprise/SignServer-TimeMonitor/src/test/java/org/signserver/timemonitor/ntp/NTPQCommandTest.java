/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
    private static final Logger LOG = Logger.getLogger(NTPQCommandTest.class);

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
