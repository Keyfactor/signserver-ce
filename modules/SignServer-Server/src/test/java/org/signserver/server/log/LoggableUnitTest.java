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
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class LoggableUnitTest extends TestCase {
    /**
     * Test that inserting Loggable instances in a LogMap doesn't evaluate the
     * log message directly.
     * 
     * @throws Exception 
     */
    @Test
    public void testNoGreedyEvaluation() throws Exception {
        final TrackingLoggable loggable = new TrackingLoggable();
        final LogMap logMap = new LogMap();
        
        logMap.put("LOG_ITEM", loggable);
        
        assertFalse("Should not evaluate log message", loggable.hasEvaluated);
    }
 
    
    static class TrackingLoggable implements Loggable {
        public boolean hasEvaluated = false;

        @Override
        public String toString() {
            hasEvaluated = true;
            return null;
        }
    };
}
