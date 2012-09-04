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
package org.signserver.web;

import java.io.File;
import java.util.Collections;
import java.util.Map;

import org.signserver.common.ServiceLocator;
import org.signserver.statusrepo.IStatusRepositorySession;
import org.signserver.statusrepo.common.StatusName;

/**
 * Tests the Health check.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class HealthCheckTest extends WebTestCase {

    private static final Map<String, String> NO_FIELDS = Collections.emptyMap();
    
    /** Worker ID for test TSA worker. */
    private static final int TSA_WORKER = 8904;
    
    /** The status repository session. */
    private static IStatusRepositorySession.IRemote repository;
    
    @Override
    protected String getServletURL() {
        return "http://localhost:8080/signserver/healthcheck/signserverhealth";
    }
    
    

    @Override
	protected void setUp() throws Exception {
        repository = ServiceLocator.getInstance().lookupRemote(
                IStatusRepositorySession.IRemote.class);
	}



	/**
     * Sets up a dummy signer.
     * @throws Exception in case of error
     */
    public void test00SetupDatabase() throws Exception {
        addDummySigner1();
//        addCMSSigner1();
        setProperties(new File(getSignServerHome(), "modules/SignServer-Module-TSA/src/conf/junittest-part-config.properties"));
        workerSession.reloadConfiguration(TSA_WORKER);
    }

    /**
     * Test that Health check returns ALLOK.
     */
    public void test01AllOk() throws Exception {
        assertStatusReturned(NO_FIELDS, 200);
        String body = new String(sendAndReadyBody(NO_FIELDS));
        assertTrue("Contains ALLOK: " + body, body.contains("ALLOK"));
    }
    
    /**
     * Tests that an error message is returned when the crypto token is offline.
     */
    public void test02CryptoTokenOffline() throws Exception {
        // Make sure one worker is offline
        getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), "KEYDATA");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        if (getWorkerSession().getStatus(getSignerIdDummy1()).getFatalErrors().isEmpty()) {
            throw new Exception("Error in test case. We should have an offline worker to test with");
        }
        
        assertStatusReturned(NO_FIELDS, 500);
        String body = new String(sendAndReadyBody(NO_FIELDS));
        assertFalse("Not ALLOK: " + body, body.contains("ALLOK"));
    }
    
    /**
     * Tests that a time stamp signer with a timesource not insync results in a healthcheck error
     */
    public void test03TimeSourceNotInsync() throws Exception {
    	// Test without insync
        repository.update(StatusName.TIMESOURCE0_INSYNC.name(), "");
        
        assertStatusReturned(NO_FIELDS, 500);
        String body = new String(sendAndReadyBody(NO_FIELDS));
        assertFalse("Not ALLOK: " + body, body.contains("ALLOK"));
    }

    /**
     * Remove the workers created etc.
     * @throws Exception in case of error
     */
    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdDummy1());
//        removeWorker(getSignerIdCMSSigner1());
        removeWorker(TSA_WORKER);
    }
}
