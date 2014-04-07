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
package org.signserver.server.dispatchers;

import java.io.File;
import java.security.cert.X509Certificate;
import org.apache.log4j.Logger;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.*;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.testutils.ModulesTestCase;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests for the FirstActiveDispatcher.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class FirstActiveDispatcherTest extends ModulesTestCase {

    /**
     * WORKERID used in this test case as defined in
     * junittest-part-config.properties.
     */
    private static final int WORKERID_DISPATCHER = 5680;
    private static final int WORKERID_1 = 5681;
    private static final int WORKERID_2 = 5682;
    private static final int WORKERID_3 = 5683;
    
    private static final int[] WORKERS = new int[] {5676, 5679, 5681, 5682, 5683, 5802, 5803};
    
    /**
     * Dummy authentication code used to test activation of a dispatcher worker
     */
    private static final String DUMMY_AUTH_CODE = "1234";

    /** Logger for this class */
    private static Logger LOG = Logger.getLogger(FirstActiveDispatcherTest.class);
    
    private final IWorkerSession workerSession = getWorkerSession();
    
    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        setProperties(new File(getSignServerHome(), "modules/SignServer-Module-XMLSigner/src/conf/junittest-part-config.properties"));

        workerSession.reloadConfiguration(WORKERID_DISPATCHER);
        workerSession.reloadConfiguration(WORKERID_1);
        workerSession.reloadConfiguration(WORKERID_2);
        workerSession.reloadConfiguration(WORKERID_3);
    }
    
    /**
     * Sets the DispatchedAuthorizer for the dispatchees.
     */
    private void setDispatchedAuthorizerForAllWorkers() {
        workerSession.setWorkerProperty(WORKERID_1, "AUTHTYPE", "org.signserver.server.DispatchedAuthorizer");
        workerSession.setWorkerProperty(WORKERID_1, "AUTHORIZEALLDISPATCHERS", "true");
        workerSession.setWorkerProperty(WORKERID_2, "AUTHTYPE", "org.signserver.server.DispatchedAuthorizer");
        workerSession.setWorkerProperty(WORKERID_2, "AUTHORIZEALLDISPATCHERS", "true");
        workerSession.setWorkerProperty(WORKERID_3, "AUTHTYPE", "org.signserver.server.DispatchedAuthorizer");
        workerSession.setWorkerProperty(WORKERID_3, "AUTHORIZEALLDISPATCHERS", "true");
        workerSession.reloadConfiguration(WORKERID_1);
        workerSession.reloadConfiguration(WORKERID_2);
        workerSession.reloadConfiguration(WORKERID_3);
    }
    
    /**
     * Resets authorization for the dispatchees to be able to call them directly.
     */
    private void resetDispatchedAuthorizerForAllWorkers() {
        workerSession.setWorkerProperty(WORKERID_1, "AUTHTYPE", "NOAUTH");
        workerSession.removeWorkerProperty(WORKERID_1, "AUTHORIZEALLDISPATCHERS");
        workerSession.setWorkerProperty(WORKERID_2, "AUTHTYPE", "NOAUTH");
        workerSession.removeWorkerProperty(WORKERID_2, "AUTHORIZEALLDISPATCHERS");
        workerSession.setWorkerProperty(WORKERID_3, "AUTHTYPE", "NOAUTH");
        workerSession.removeWorkerProperty(WORKERID_3, "AUTHORIZEALLDISPATCHERS");
        workerSession.reloadConfiguration(WORKERID_1);
        workerSession.reloadConfiguration(WORKERID_2);
        workerSession.reloadConfiguration(WORKERID_3);
    }
    

    /**
     * Tests that requests sent to the dispatching worker are forwarded to
     * any of the configured workers.
     * @throws Exception in case of exception
     */
    @Test
    public void test01Dispatched() throws Exception {
        try {
            final RequestContext context = new RequestContext();
    
            final GenericSignRequest request =
                    new GenericSignRequest(1, "<root/>".getBytes());
    
            GenericSignResponse res;
    
            setDispatchedAuthorizerForAllWorkers();
            
            // Send request to dispatcher
            res = (GenericSignResponse) workerSession.process(WORKERID_DISPATCHER,
                    request, context);
            
            X509Certificate cert = (X509Certificate) res.getSignerCertificate();
            assertTrue("Response from signer 81, 82 or 83",
                cert.getSubjectDN().getName().contains("testdocumentsigner81")
                || cert.getSubjectDN().getName().contains("testdocumentsigner82")
                || cert.getSubjectDN().getName().contains("testdocumentsigner83"));
    
            // Disable signer 81
            workerSession.setWorkerProperty(WORKERID_1, "DISABLED", "TRUE");
            workerSession.reloadConfiguration(WORKERID_1);
    
            // Send request to dispatcher
            res = (GenericSignResponse) workerSession.process(WORKERID_DISPATCHER,
                    request, context);
    
            cert = (X509Certificate) res.getSignerCertificate();
            assertTrue("Response from signer 82 or 83",
                cert.getSubjectDN().getName().contains("testdocumentsigner82")
                || cert.getSubjectDN().getName().contains("testdocumentsigner83"));
    
            // Disable signer 83
            workerSession.setWorkerProperty(WORKERID_3, "DISABLED", "TRUE");
            workerSession.reloadConfiguration(WORKERID_3);
    
            // Send request to dispatcher
            res = (GenericSignResponse) workerSession.process(WORKERID_DISPATCHER,
                    request, context);
    
            cert = (X509Certificate) res.getSignerCertificate();
            assertTrue("Response from signer 82",
                cert.getSubjectDN().getName().contains("testdocumentsigner82"));
    
            // Disable signer 82
            workerSession.setWorkerProperty(WORKERID_2, "DISABLED", "TRUE");
            workerSession.reloadConfiguration(WORKERID_2);
    
            // Send request to dispatcher
            try {
                workerSession.process(WORKERID_DISPATCHER, request, context);
                fail("Should have got CryptoTokenOfflineException");
            } catch(CryptoTokenOfflineException ex) {
                // OK
            }
    
            // Enable signer 81
            workerSession.setWorkerProperty(WORKERID_1, "DISABLED", "FALSE");
            workerSession.reloadConfiguration(WORKERID_1);
    
            // Send request to dispatcher
            res = (GenericSignResponse) workerSession.process(WORKERID_DISPATCHER,
                    request, context);
    
            cert = (X509Certificate) res.getSignerCertificate();
            assertTrue("Response from signer 81",
                cert.getSubjectDN().getName().contains("testdocumentsigner81"));
        } finally {
            resetDispatchedAuthorizerForAllWorkers();
        }
    }
    
    /**
     * Test that trying to activate the dispatcher worker doesn't throw an exception (DSS-380)
     * This will actually not activate any crypto token
     * 
     * @throws Exception
     */
    @Test
    public void test02Activate() throws Exception {
    	try {
    		workerSession.activateSigner(WORKERID_DISPATCHER, DUMMY_AUTH_CODE);
    	} catch (Exception e) {
    		LOG.error("Exception thrown", e);
    		fail("Failed to activate the dispatcher");
    	}
    }

    /**
     * Test that trying to deactivate the dispatcher doesn't throw an exception (DSS-380)
     * @throws Exception
     */
    @Test
    public void test03Deactivate() throws Exception {
    	try {
    		workerSession.deactivateSigner(WORKERID_DISPATCHER);
    	} catch (Exception e) {
    		LOG.error("Exception thrown", e);
    		fail("Failed to deactive the dispatcher");
    	}
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(WORKERID_DISPATCHER);
        for (int workerId : WORKERS) {
            removeWorker(workerId);
        }
    }

}
