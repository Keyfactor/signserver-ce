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
package org.signserver.server.log;

import junit.framework.TestCase;
import org.junit.Test;

/**
 * Unit test for the ConstantStringLoggable Loggable implementation.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ConstantStringLoggableUnitTest extends TestCase {
    /**
     * Test that the logValue() method returns the string constant set for the
     * loggable instance.
     *
     * @throws Exception 
     */
    @Test
    public void testConstantStringLogging() throws Exception {
        final Loggable loggable = new ConstantStringLoggable("Log message");
        
        assertEquals("Log message", "Log message", loggable.logValue());
    }
}
