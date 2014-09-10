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
     * @param expectedValues Expected values returned, if null don't check values
     * @param expectedErrors Expected errors
     * @throws Exception 
     */
    private void testLoggingTypes(final String propertyValue,
            final Collection<ITimedService.LogType> expectedValues,
            final Collection<String> expectedErrors) throws Exception {
        final ITimedService instance = createInstance();
        
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty(ServiceConfig.WORK_LOG_TYPES, propertyValue);
        instance.init(DUMMY_WORKERID, config, null, null);
        
        final Set<ITimedService.LogType> logTypes = instance.getLogTypes();
        final List<String> fatalErrors =
            instance.getStatus(Collections.<String>emptyList()).getFatalErrors();
        
        assertEquals("Number of log types", expectedValues.size(), logTypes.size());
        
        if (expectedValues != null) {
            assertTrue("Contains expected values",
                    logTypes.containsAll(expectedValues));
        }
   
        if (expectedErrors.isEmpty()) {
            assertTrue("Should not contain errors", fatalErrors.isEmpty());
        } else {
            assertTrue("Should contain expected errors",
                    fatalErrors.containsAll(expectedErrors));
            assertEquals("Should only contain expected errors",
                    expectedErrors.size(), fatalErrors.size());
        }
    }
    
    /**
     * Test the SECURE_AUDITLOGGING property value.
     * 
     * @throws Exception 
     */
    public void test02secureLoggingType() throws Exception {
        testLoggingTypes("SECURE_AUDITLOGGING",
                Arrays.asList(ITimedService.LogType.SECURE_AUDITLOGGING),
                Collections.<String>emptyList());
    }
    
    /**
     * Test the INFO_LOGGING property value.
     * 
     * @throws Exception 
     */
    public void test03infoLoggingType() throws Exception {
        testLoggingTypes("INFO_LOGGING",
                Arrays.asList(ITimedService.LogType.INFO_LOGGING),
                Collections.<String>emptyList());
    }
    
    /**
     * Test setting both logging types.
     * 
     * @throws Exception 
     */
    public void test04bothLoggingTypes() throws Exception {
        testLoggingTypes("INFO_LOGGING,SECURE_AUDITLOGGING",
                Arrays.asList(ITimedService.LogType.INFO_LOGGING,
                              ITimedService.LogType.SECURE_AUDITLOGGING),
                Collections.<String>emptyList());
    }
    
    /**
     * Test setting an empty list of logging types.
     * 
     * @throws Exception 
     */
    public void test05emptyLoggingTypes() throws Exception {
        testLoggingTypes("", Collections.<ITimedService.LogType>emptyList(),
                Collections.<String>emptyList());
    }
    
    /**
     * Test with some white-space padding and re-ordered the arguments.
     * 
     * @throws Exception 
     */
    public void test06logTypesWithPadding() throws Exception {
        testLoggingTypes("SECURE_AUDITLOGGING, INFO_LOGGING",
                Arrays.asList(ITimedService.LogType.INFO_LOGGING,
                              ITimedService.LogType.SECURE_AUDITLOGGING),
                Collections.<String>emptyList());
    }
}
