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

import java.util.Map;
import junit.framework.TestCase;
import org.junit.Test;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;

/**
 * Unit tests for the base worker logger implementation.
 * Tests the fatal errors mechanism.
 * 
 * @author Marcus Lundblad
 * @version $Id
 */
public class BaseWorkerLoggerUnitTest extends TestCase {
    
    /**
     * Test that no fatal error is included by default.
     * 
     */
    @Test
    public void testNoErrors() {
        final BaseWorkerLogger workerLogger = new BaseWorkerLogger() {
            @Override
            public void init(int workerId, WorkerConfig config, SignServerContext context) {
            }

            @Override
            public void log(AdminInfo adminInfo, Map<String, String> fields, RequestContext requestContext) throws WorkerLoggerException {
            }            
        };
        
        assertEquals("Should contain no errors",
                     0, workerLogger.getFatalErrors().size());
        assertFalse("Should not report errors", workerLogger.hasErrors());
    }
}
