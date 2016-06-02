/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
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
        public String logValue() {
            hasEvaluated = true;
            return null;
        }
    };
}
