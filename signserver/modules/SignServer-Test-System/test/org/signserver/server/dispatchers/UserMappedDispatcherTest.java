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
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.signserver.server.UsernamePasswordClientCredential;

/**
 * Tests for the UserMappedDispatcher.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class UserMappedDispatcherTest extends ModulesTestCase {

    /**
     * WORKERID used in this test case as defined in
     * junittest-part-config.properties.
     */
    private static final int WORKERID_DISPATCHER = 5780;
    private static final int WORKERID_1 = 5681;
    private static final int WORKERID_2 = 5682;
    private static final int WORKERID_3 = 5683;
    
    private static final int[] WORKERS = new int[] {5676, 5679, 5681, 5682, 5683, 5802, 5803};
    
    /**
     * Dummy authentication code used to test activation of a dispatcher worker
     */
    private static final String DUMMY_AUTH_CODE = "1234";

    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(UserMappedDispatcherTest.class);
    
    @Before
    @Override
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        workerSession = ServiceLocator.getInstance().lookupRemote(
                        IWorkerSession.IRemote.class);
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
     * Tests that requests sent to the dispatching worker are forwarded to
     * the right worker
     * @throws Exception in case of exception
     */
    @Test
    public void test01Dispatched() throws Exception {
        LOG.info("test01Dispatched");
        final RequestContext context = new RequestContext();
        final GenericSignRequest request =
                new GenericSignRequest(1, "<root/>".getBytes());

        GenericSignResponse res;

        // Send request to dispatcher as user1
        context.put(RequestContext.CLIENT_CREDENTIAL, 
                new UsernamePasswordClientCredential("user1", "password"));
        res = (GenericSignResponse) workerSession.process(WORKERID_DISPATCHER,
                request, context);
        
        X509Certificate cert = (X509Certificate) res.getSignerCertificate();
        assertEquals("Response from signer 81", 
                "CN=testdocumentsigner81,OU=Testing,O=SignServer,C=SE", cert.getSubjectDN().getName());

        // Send request to dispatcher as user2
        context.put(RequestContext.CLIENT_CREDENTIAL, 
                new UsernamePasswordClientCredential("user2", "password"));
        res = (GenericSignResponse) workerSession.process(WORKERID_DISPATCHER,
                request, context);
        cert = (X509Certificate) res.getSignerCertificate();
        assertEquals("Response from signer 82", 
                "CN=testdocumentsigner82,OU=Testing,O=SignServer,C=SE", cert.getSubjectDN().getName());

        // Send request to dispatcher as user3
        context.put(RequestContext.CLIENT_CREDENTIAL, 
                new UsernamePasswordClientCredential("user3", "password"));
        res = (GenericSignResponse) workerSession.process(WORKERID_DISPATCHER,
                request, context);
        cert = (X509Certificate) res.getSignerCertificate();
        assertEquals("Response from signer 83", 
                "CN=testdocumentsigner83,OU=Testing,O=SignServer,C=SE", cert.getSubjectDN().getName());

        // Send request to dispatcher as user4 for which the worker does not exist
        try {
            context.put(RequestContext.CLIENT_CREDENTIAL, 
                    new UsernamePasswordClientCredential("user4", "password"));
            workerSession.process(WORKERID_DISPATCHER, request, context);
            fail("Should have got SignServerException as the worker configured does not exist");
        } catch(SignServerException expected) { // NOPMD
            // OK
        }
        
        // Send request to dispatcher as user5 which mapps to the dispatcher
        // itself
        try {
            context.put(RequestContext.CLIENT_CREDENTIAL, 
                    new UsernamePasswordClientCredential("user5", "password"));
            workerSession.process(WORKERID_DISPATCHER, request, context);
            fail("Should have got SignServerException as it is configured to dispatch to itself");
        } catch(SignServerException expected) { // NOPMD
            // OK
        }
        
        // Send request to dispatcher as user6 for which there is no mapping
        try {
            context.put(RequestContext.CLIENT_CREDENTIAL, 
                    new UsernamePasswordClientCredential("user6", "password"));
            workerSession.process(WORKERID_DISPATCHER, request, context);
            fail("Should have got IllegalRequestException as there is no mapping");
        } catch(IllegalRequestException expected) { // NOPMD
            // OK
        }
    }
    
    /**
     * Test that trying to activate the dispatcher worker doesn't throw an 
     * exception (DSS-380).
     * This will actually not activate any crypto token
     */
    @Test
    public void test02Activate() throws Exception {
        LOG.info("test02Activate");
    	try {
            workerSession.activateSigner(WORKERID_DISPATCHER, DUMMY_AUTH_CODE);
    	} catch (Exception e) {
            LOG.error("Exception thrown", e);
            fail("Failed to activate the dispatcher");
    	}
    }

    /**
     * Test that trying to deactivate the dispatcher doesn't throw an exception 
     * (DSS-380).
     */
    @Test
    public void test03Deactivate() throws Exception {
        LOG.info("test03Deactivate");
    	try {
    		workerSession.deactivateSigner(WORKERID_DISPATCHER);
    	} catch (Exception e) {
    		LOG.error("Exception thrown", e);
    		fail("Failed to deactive the dispatcher");
    	}
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        LOG.info("test99TearDownDatabase");
        removeWorker(WORKERID_DISPATCHER);
        for (int workerId : WORKERS) {
            removeWorker(workerId);
        }
    }

}
