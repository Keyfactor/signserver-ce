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

/**
 * Unit test for the HSM keep alive timed service.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class HSMKeepAliveTimedServiceUnitTest extends TestCase {
    
    private static int DUMMY_WORKERID = 42;
    
    /**
     * Test that omitting the CRYPTOWORKERS property results in a configuration
     * error.
     * 
     * @throws Exception 
     */
    public void test01missingCryptoWorkers() throws Exception {
       final HSMKeepAliveTimedService instance =
               new HSMKeepAliveTimedService();
       
       instance.init(DUMMY_WORKERID, new WorkerConfig(), null, null);
       
       final List<String> fatalErrors =
            instance.getStatus(Collections.<String>emptyList()).getFatalErrors();

       assertTrue("Should contain error", fatalErrors.contains("Must specify CRYPTOWORKERS"));
    }
    
}
