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
 * Unit tests for the StringValueLoggable Loggable implementation.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class StringValueLoggableUnitTest extends TestCase {
    /**
     * Test that setting a boolean value gives a correct string evaluation.
     * 
     * @throws Exception 
     */
    @Test
    public void testLoggingBoolean() throws Exception {
        final Loggable loggable = new StringValueLoggable(false);
        
        assertEquals("Log message", "false", loggable.toString());
    }
    
    /**
     * Test that setting an integer value gives a correct string evaluation.
     *
     * @throws Exception 
     */
    @Test
    public void testLoggingInteger() throws Exception {
        final Loggable loggable = new StringValueLoggable(42);
        
        assertEquals("Log message", "42", loggable.toString());
    }
}
