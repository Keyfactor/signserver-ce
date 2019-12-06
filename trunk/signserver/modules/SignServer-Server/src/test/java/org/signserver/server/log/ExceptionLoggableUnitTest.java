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
 * Test for the ExceptionLoggable Loggable implementation.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ExceptionLoggableUnitTest extends TestCase {
    /**
     * Test that an instance of ExceptionLoggable is correctly evaluating
     * the exception message when getting the log message.
     * 
     * @throws Exception 
     */
    @Test
    public void testLoggingException() throws Exception {
        try {
            throw new Exception("An exception");
        } catch (Exception e) {
            final ExceptionLoggable loggable = new ExceptionLoggable(e);
            
            assertEquals("Should log error message", "An exception",
                         loggable.toString());
        }
    }
}
