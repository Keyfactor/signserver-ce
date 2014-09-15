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
package org.signserver.server.timedservices.hsmkeepalive;

import java.util.Collections;
import java.util.List;
import junit.framework.TestCase;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IWorkerSession;

/**
 * Unit test for the HSM keep alive timed service.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class HSMKeepAliveTimedServiceUnitTest extends TestCase {
    
    private static final int DUMMY_WORKERID = 42;
    
    /**
     * Test that omitting the CRYPTOTOKENS property results in a configuration
     * error.
     * 
     * @throws Exception 
     */
    public void test01missingCryptoTokens() throws Exception {
       final HSMKeepAliveTimedService instance =
               new HSMKeepAliveTimedService() {
                    @Override
                    IWorkerSession getWorkerSession() {
                        return null;
                    }
               };
       
       instance.init(DUMMY_WORKERID, new WorkerConfig(), null, null);
       
       final List<String> fatalErrors =
            instance.getStatus(Collections.<String>emptyList()).getFatalErrors();

       assertTrue("Should contain error", fatalErrors.contains("Must specify CRYPTOTOKENS"));
    }
    
    /**
     * Test that setting an empty value for CRYPTOTOKEN is not producing
     * a config error.
     * 
     * @throws Exception 
     */
    public void test02emptyCryptoTokens() throws Exception {
        final HSMKeepAliveTimedService instance =
               new HSMKeepAliveTimedService() {
                   @Override
                   IWorkerSession getWorkerSession() {
                       return null;
                   }
               };
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty(HSMKeepAliveTimedService.CRYPTOTOKENS, "");
        instance.init(DUMMY_WORKERID, config, null, null);
        
        final List<String> fatalErrors =
            instance.getStatus(Collections.<String>emptyList()).getFatalErrors();

        assertTrue("Should not contain errors", fatalErrors.isEmpty());
    }
}
