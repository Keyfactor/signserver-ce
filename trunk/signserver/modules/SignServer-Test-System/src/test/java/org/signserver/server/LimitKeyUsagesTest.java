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
package org.signserver.server;

import java.io.File;

import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.testutils.ModulesTestCase;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * Tests limits for the key usages.
 *
 * @author Markus Kilas
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class LimitKeyUsagesTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            LimitKeyUsagesTest.class);

    /** WORKERID used in this test case. */
    private static final WorkerIdentifier WORKERID_1 = new WorkerIdentifier(5802);

    /**
     * Test with this number of signings.
     */
    private static final int LIMIT = 10;

    private final WorkerSession workerSession = getWorkerSession();
    private final ProcessSessionRemote processSession = getProcessSession();

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        addP12DummySigner(WORKERID_1.getId(), "TestLimitKeyUsageSigner", new File(getSignServerHome(), "res/test/dss10/dss10_signer3.p12"), null, "Signer 3");
        workerSession.reloadConfiguration(WORKERID_1.getId());
    }

    /**
     * Do signings up to KEYUSAGELIMIT and then check that the next signing
     * fails.
     *
     * Assumption: The configured key (test_keyusagelimit1.p12) is not used by
     * any other tests.
     *
     * @throws Exception in case of exception
     */
    @Test
    public void test01Limit() throws Exception {
        workerSession.activateSigner(WORKERID_1, "foo123");
        final long oldValue = workerSession.getKeyUsageCounterValue(WORKERID_1);
        workerSession.setWorkerProperty(WORKERID_1.getId(), "KEYUSAGELIMIT",
                String.valueOf(oldValue + LIMIT));
        workerSession.reloadConfiguration(WORKERID_1.getId());
        workerSession.activateSigner(WORKERID_1, "foo123");

        // Do a number of signings LIMIT
        try {
            for (int i = 0; i < LIMIT; i++) {
                LOG.info("Signing " + i);
                doSign();
            }
        } catch (CryptoTokenOfflineException ex) {
            fail(ex.getMessage());
        }

        try {
            doSign();
            fail("Should have failed now");

        } catch (CryptoTokenOfflineException ok) {
        }
    }

    @Test
    public void test02NoIncreaseWhenOffline() throws Exception {
        // Increase key usage limit so we should be able to do two more signings
        final long oldValue = workerSession.getKeyUsageCounterValue(WORKERID_1);
        workerSession.setWorkerProperty(WORKERID_1.getId(), "KEYUSAGELIMIT",
                String.valueOf(oldValue + 2));
        workerSession.reloadConfiguration(WORKERID_1.getId());
        workerSession.activateSigner(WORKERID_1, "foo123");

        // Do one signing just to see that it works
        doSign();

        // Make the signer offline and do one signing that should not increase
        //counter, which means that after activating it again we should be able
        //to do one more signing
        workerSession.deactivateSigner(WORKERID_1);
        doSignOffline();

        // Should be able to do one signing now
        workerSession.activateSigner(WORKERID_1, "foo123");
        doSign();
    }

    /**
     * Tests that when the key usage counter is not disabled it will increase
     * after a signing.
     */
    @Test
    public void test03IncreaseWhenNotDisabled() throws Exception {
        // Remove any limits just in case
        workerSession.removeWorkerProperty(WORKERID_1.getId(), "KEYUSAGELIMIT");
        // Set to not disabled = enabled
        workerSession.setWorkerProperty(WORKERID_1.getId(), "DISABLEKEYUSAGECOUNTER", "FaLsE");
        workerSession.reloadConfiguration(WORKERID_1.getId());
        workerSession.activateSigner(WORKERID_1, "foo123");

        final long oldValue = workerSession.getKeyUsageCounterValue(WORKERID_1);
        if (oldValue < 0) {
            throw new Exception("Test case assumes non negative counter value");
        }

        doSign();

        // Counter should have increased
        final long actual = workerSession.getKeyUsageCounterValue(WORKERID_1);
        assertEquals("counter should have increased", oldValue + 1, actual);
    }

    /**
     * Tests that when the key usage counter is disabled and there is no
     * key usage limit a signing will not increase the counter.
     */
    @Test
    public void test04NoIncreaseWhenDisabled() throws Exception {
        // Remove any limits just in case
        workerSession.removeWorkerProperty(WORKERID_1.getId(), "KEYUSAGELIMIT");
        // Set to be disabled
        workerSession.setWorkerProperty(WORKERID_1.getId(), "DISABLEKEYUSAGECOUNTER", "TrUe");
        workerSession.reloadConfiguration(WORKERID_1.getId());
        workerSession.activateSigner(WORKERID_1, "foo123");

        final long oldValue = workerSession.getKeyUsageCounterValue(WORKERID_1);
        if (oldValue < 0) {
            throw new Exception("Test case assumes non negative counter value");
        }

        doSign();

        // Counter should not have increased
        final long actual = workerSession.getKeyUsageCounterValue(WORKERID_1);
        assertEquals("counter should not have increased", oldValue, actual);
    }

    /**
     * Tests that when a KEYUSAGELIMIT is specified but also
     * DISABLEKEYUSAGECOUNTER=TRUE, the request fails.
     */
    @Test
    public void test05IncreaseWhenDisabledButThereIsALimit() throws Exception {
        // Set a limit so we should still to counting
        workerSession.setWorkerProperty(WORKERID_1.getId(), "KEYUSAGELIMIT", "100000");
        // Set to disabled
        workerSession.setWorkerProperty(WORKERID_1.getId(), "DISABLEKEYUSAGECOUNTER", "TRUE");
        workerSession.reloadConfiguration(WORKERID_1.getId());
        workerSession.activateSigner(WORKERID_1, "foo123");

        final long oldValue = workerSession.getKeyUsageCounterValue(WORKERID_1);
        if (oldValue < 0) {
            throw new Exception("Test case assumes non negative counter value");
        }

        try {
            doSign();

            fail("Request should not have been accepted as both disabled and limit specified");
        } catch (SignServerException expected) {
            assertEquals("exception message", "Worker is misconfigured", expected.getMessage());
        }
    }

    @Test
    public void test06() throws Exception {

        final long oldValue = workerSession.getKeyUsageCounterValue(WORKERID_1);
        if (oldValue < 0) {
            throw new Exception("Test case assumes non negative counter value");
        }

        // Set a limit so we can only do one signing
        workerSession.setWorkerProperty(WORKERID_1.getId(), "KEYUSAGELIMIT", String.valueOf(oldValue + 1));
        workerSession.setWorkerProperty(WORKERID_1.getId(), "DISABLEKEYUSAGECOUNTER", "FALSE");
        workerSession.reloadConfiguration(WORKERID_1.getId());
        workerSession.activateSigner(WORKERID_1, "foo123");

        // One signing is ok
        doSign();

        // Next the signer should be offline
        doSignOffline();
    }

    /** Do a dummy sign. */
    private void doSign() throws Exception {
        final GenericSignRequest request = new GenericSignRequest(1,
                "<root/>".getBytes());
        GenericSignResponse res;
        // Send request to dispatcher
        res = (GenericSignResponse) processSession.process(WORKERID_1,
                request, new RemoteRequestContext());
        assertNotNull(res.getSignerCertificate());
    }

    /** Do a dummy sign and expect failure. */
    private void doSignOffline() {
        try {
            final GenericSignRequest request = new GenericSignRequest(1,
                    "<root/>".getBytes());
            // Send request to dispatcher
            processSession.process(WORKERID_1,
                    request, new RemoteRequestContext());
        } catch (CryptoTokenOfflineException ok) {
            // OK
        } catch (Exception ex) {
            LOG.error("Signer offline but other exception", ex);
            fail("Signer offline but other exception: " + ex.getMessage());
        }
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(WORKERID_1.getId());
    }
}
