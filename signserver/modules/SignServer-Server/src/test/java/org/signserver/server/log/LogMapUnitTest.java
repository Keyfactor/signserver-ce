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
import org.signserver.common.RequestContext;

/**
 * Unit tests for the LogMap class.
 * Currently only tests that copying a request context gives an independent
 * log map, not clobbering the original one.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class LogMapUnitTest extends TestCase {
    /**
     * Test that copying a request context gets a new log map not updating the
     * original one.
     * Note that this test can not be in SignServer-Common (with RequestContext),
     * as that module can't access SignServer-Server (and LogMap).
     * 
     * @throws Exception 
     */
    public void testCopyRequestContextWithNewLogMap() throws Exception {
        final RequestContext origContext = new RequestContext();
        final RequestContext copiedContext = origContext.copyWithNewLogMap();
        
        final LogMap origLogMap = LogMap.getInstance(origContext);
        
        // write to the original log map
        origLogMap.put("original key", new Loggable() {
            @Override
            public String toString() {
                return "original value";
            }
        });
        
        final LogMap copiedLogMap = LogMap.getInstance(copiedContext);
        
        // write to the copied log map
        copiedLogMap.put("copied key", new Loggable() {
            @Override
            public String toString() {
                return "copied value";
            }
        });
        
        // check that the expected values are logged to their correct log maps
        final Object origLoggable = origLogMap.get("original key");
        assertEquals("original log map should contain", "original value",
                     String.valueOf(origLoggable));
        
        final Object copiedLoggable = copiedLogMap.get("copied key");
        assertEquals("copied log map should contain", "copied value",
                     String.valueOf(copiedLoggable));
        
        // check that the value written in the new log map is not visible in
        // orignal one, and vice-versa
        assertNull("should not be written in original log map",
                   origLogMap.get("copied key"));
        assertNull("should not be written in copied log map",
                   copiedLogMap.get("original key"));
    }
}
