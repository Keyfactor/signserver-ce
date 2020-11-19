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

import org.signserver.testutils.WebTestCase;
import java.io.File;
import java.io.FileOutputStream;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;

import org.signserver.common.ServiceLocator;
import org.signserver.statusrepo.common.StatusName;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.statusrepo.StatusRepositorySessionRemote;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Tests the Health check.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class HealthCheckTest extends WebTestCase {

    /** Logger for this class. */
    private final static Logger LOG = Logger.getLogger(HealthCheckTest.class);

    /** Worker ID for test TSA worker. */
    private static final int TSA_WORKER = 8904;

    /** The status repository session. */
    private static StatusRepositorySessionRemote repository;

    private final WorkerSession workerSession = getWorkerSession();

    @Override
    protected String getServletURL() {
        return getPreferredHTTPProtocol() + getHTTPHost() + ":" + getPreferredHTTPPort() + "/signserver/healthcheck/signserverhealth";
    }

    @Before
    public void setUp() throws Exception {
        repository = ServiceLocator.getInstance().lookupRemote(StatusRepositorySessionRemote.class);
    }

	/**
     * Sets up a dummy signer.
     * @throws Exception in case of error
     */
    @Test
    public void test00SetupDatabase() throws Exception {
        LOG.info("test00SetupDatabase");
        addDummySigner1(true);
    }

    /**
     * Test that Health check returns ALLOK.
     */
    @Test
    public void test01AllOk() throws Exception {
        LOG.info("test01AllOk");
        assertStatusReturned(NO_FIELDS, 200);
        String body = new String(sendAndReadyBody(NO_FIELDS));
        assertTrue("Contains ALLOK: " + body, body.contains("ALLOK"));
    }

    /**
     * Tests that an error message is returned when the crypto token is offline.
     */
    @Test
    public void test02CryptoTokenOffline() throws Exception {
        LOG.info("test02CryptoTokenOffline");
        try {
            // Make sure one worker is offline
            getWorkerSession().setWorkerProperty(getSignerIdDummy1(), "KEYSTOREPATH", "_non-existing-path_");
            getWorkerSession().reloadConfiguration(getSignerIdDummy1());
            if (getWorkerSession().getStatus(new WorkerIdentifier(getSignerIdDummy1())).getFatalErrors().isEmpty()) {
                throw new Exception("Error in test case. We should have an offline worker to test with");
            }

            assertStatusReturned(NO_FIELDS, 500);
            String body = new String(sendAndReadyBody(NO_FIELDS));
            assertFalse("Not ALLOK: " + body, body.contains("ALLOK"));
        } finally {
            // remove offline worker so it won't interfere with the next tests
            removeWorker(getSignerIdDummy1());
        }
    }

    /**
     * Tests that a time stamp signer with a timesource not insync results in a healthcheck error
     */
    @Test
    public void test03TimeSourceNotInsync() throws Exception {
        LOG.info("test03TimeSourceNotInsync");
        try {
            addTimeStampSigner(TSA_WORKER, "TestTSA4", true);
            workerSession.setWorkerProperty(TSA_WORKER, "DEFAULTTSAPOLICYOID", "1.3.6.1.4.1.22408.1.2.3.45");
            workerSession.setWorkerProperty(TSA_WORKER, "TIMESOURCE", "org.signserver.server.StatusReadingLocalComputerTimeSource");
            workerSession.reloadConfiguration(TSA_WORKER);

            // Test without insync
            repository.update(StatusName.TIMESOURCE0_INSYNC.name(), "");

            assertStatusReturned(NO_FIELDS, 500);
            String body = new String(sendAndReadyBody(NO_FIELDS));
            assertFalse("Not ALLOK: " + body, body.contains("ALLOK"));
        } finally {
            removeWorker(TSA_WORKER);
        }
    }

    private FileOutputStream openMaintenanceProperties() throws Exception {
    	File maintenanceFile = new File(getSignServerHome() + File.separator +
    			getConfig().getProperty("healthcheck.maintenancefile"));

    	return new FileOutputStream(maintenanceFile);
    }

    /**
     * Test the down-for-maintenance functionality
     */
    @Test
    public void test04DownForMaintenance() throws Exception {
        LOG.info("test04DownForMaintenance");
    	FileOutputStream fos = openMaintenanceProperties();
    	Properties properties = new Properties();

    	// set down for maintenance on
    	String maintProp = getConfig().getProperty("healthcheck.propertyname");
    	if (maintProp == null) {
    		maintProp = "DOWN_FOR_MAINTENANCE";
    	}
    	properties.setProperty(maintProp, "true");
    	properties.store(fos, null);

    	assertStatusReturned(NO_FIELDS, 500);
    	String body = new String(sendAndReadyBody(NO_FIELDS));
    	String maintString = "MAINT: " + maintProp;
    	assertTrue("Mainenance mode should be on: " + body, body.contains(maintString));

    	// set down for maintenance off, needs to "flush" the property file to
    	// ensure it gets emptied...
    	properties.remove(maintProp);
    	properties.store(fos, null);
    	fos.close();
    	fos = openMaintenanceProperties();
    	properties.setProperty(maintProp, "false");
    	properties.store(fos, null);

    	assertStatusReturned(NO_FIELDS, 200);
        body = new String(sendAndReadyBody(NO_FIELDS));
        assertTrue("Contains ALLOK: " + body, body.contains("ALLOK"));
    }

    /**
     * Remove the workers created etc.
     * @throws Exception in case of error
     */
    @Test
    public void test99TearDownDatabase() throws Exception {
        LOG.info("test99TearDownDatabase");
        removeWorker(getSignerIdDummy1());
    }
}
