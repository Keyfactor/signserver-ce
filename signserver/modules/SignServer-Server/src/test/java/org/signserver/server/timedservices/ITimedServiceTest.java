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

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import junit.framework.TestCase;
import org.signserver.common.ServiceConfig;
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
    
    private ITimedService createInstance() {
        return new BaseTimedService() {
                    @Override
                    public void work() throws ServiceExecutionFailedException {
                        throw new UnsupportedOperationException("Not supported yet.");
                    }
               };
    }
    
    /**
     * Test that the default log type is INFO_LOGGING.
     * 
     * @throws Exception 
     */
    public void test01defaultLogType() throws Exception {
        final ITimedService instance = createInstance();
        
        instance.init(DUMMY_WORKERID, new WorkerConfig(), null, null);
        
        final Set<ITimedService.LogType> logTypes = instance.getLogTypes();
        final List<String> fatalErrors =
            instance.getStatus(Collections.<String>emptyList()).getFatalErrors();
        
        assertEquals("Number of log types", 1, logTypes.size());
        assertEquals("Log type",
                ITimedService.LogType.INFO_LOGGING, logTypes.iterator().next());
        assertTrue("Should not contain errors", fatalErrors.isEmpty());
    }
    
    /**
     * Internal helper method testing the log type property.
     * 
     * @param propertyValue Property value
     * @param expectedValues Expected values returned
     * @throws Exception 
     */
    private void testLoggingTypes(final String propertyValue,
            final Collection<ITimedService.LogType> expectedValues) throws Exception {
        final ITimedService instance = createInstance();
        
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty(ServiceConfig.WORK_LOG_TYPES, propertyValue);
        instance.init(DUMMY_WORKERID, config, null, null);
        
        final Set<ITimedService.LogType> logTypes = instance.getLogTypes();
        final List<String> fatalErrors =
            instance.getStatus(Collections.<String>emptyList()).getFatalErrors();
        
        assertEquals("Number of log types", expectedValues.size(), logTypes.size());
        assertTrue("Contains expected values",
                logTypes.containsAll(expectedValues));
        assertTrue("Should not contain errors", fatalErrors.isEmpty());
    }
    
    /**
     * Test the SECURE_AUDITLOGGING property value.
     * 
     * @throws Exception 
     */
    public void test02secureLoggingType() throws Exception {
        testLoggingTypes("SECURE_AUDITLOGGING",
                Arrays.asList(ITimedService.LogType.SECURE_AUDITLOGGING));
    }
    
}
