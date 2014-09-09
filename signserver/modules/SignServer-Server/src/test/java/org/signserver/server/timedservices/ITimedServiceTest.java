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
package org.signserver.server.timedservices;

import java.util.Collections;
import java.util.List;
import junit.framework.TestCase;
import org.signserver.common.WorkerConfig;
import org.signserver.server.ServiceExecutionFailedException;

/**
 * Unit test for ITimedService.
 * Contains tests for the log types facility.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ITimedServiceTest extends TestCase {
    
    private static int DUMMY_WORKERID = 42;
    
    /**
     * Test that the default log type is INFO_LOGGING.
     * 
     * @throws Exception 
     */
    public void test01defaultLogType() throws Exception {
        final ITimedService instance =
               new BaseTimedService() {
                    @Override
                    public void work() throws ServiceExecutionFailedException {
                        throw new UnsupportedOperationException("Not supported yet.");
                    }
               };
        
        instance.init(DUMMY_WORKERID, new WorkerConfig(), null, null);
        
        final List<ITimedService.LogType> logTypes = instance.getLogTypes();
        final List<String> fatalErrors =
            instance.getStatus(Collections.<String>emptyList()).getFatalErrors();
        
        assertEquals("Number of log types", 1, logTypes.size());
        assertEquals("Log type",
                ITimedService.LogType.INFO_LOGGING, logTypes.get(0));
        assertTrue("Should not contain errors", fatalErrors.isEmpty());
    }
    
}
