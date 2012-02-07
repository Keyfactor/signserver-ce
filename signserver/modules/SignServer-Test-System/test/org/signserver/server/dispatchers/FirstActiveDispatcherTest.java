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
import org.signserver.common.*;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestUtils;

/**
 * Tests for the FirstActiveDispatcher.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class FirstActiveDispatcherTest extends ModulesTestCase {

    /**
     * WORKERID used in this test case as defined in
     * junittest-part-config.properties.
     */
    private static final int WORKERID_DISPATCHER = 5680;
    private static final int WORKERID_1 = 5681;
    private static final int WORKERID_2 = 5682;
    private static final int WORKERID_3 = 5683;

    @Override
    protected void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        workerSession = ServiceLocator.getInstance().lookupRemote(
                        IWorkerSession.IRemote.class);
        TestUtils.redirectToTempOut();
        TestUtils.redirectToTempErr();
    }

    @Override
    protected void tearDown() throws Exception {
    }

    public void test00SetupDatabase() throws Exception {

        setProperties(new File(getSignServerHome(), "modules/SignServer-Module-XMLSigner/src/conf/junittest-part-config.properties"));

        workerSession.reloadConfiguration(WORKERID_DISPATCHER);
        workerSession.reloadConfiguration(WORKERID_1);
        workerSession.reloadConfiguration(WORKERID_2);
        workerSession.reloadConfiguration(WORKERID_3);
    }

    /**
     * Tests that requests sent to the dispatching worker are forwarded to
     * any of the configured workers.
     * @throws Exception in case of exception
     */
    public void test01Dispatched() throws Exception {

        final RequestContext context = new RequestContext();

        final GenericSignRequest request =
                new GenericSignRequest(1, "<root/>".getBytes());

        GenericSignResponse res;

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
    }

    public void test99TearDownDatabase() throws Exception {
        removeWorker(WORKERID_DISPATCHER);
        removeWorker(WORKERID_1);
        removeWorker(WORKERID_2);
        removeWorker(WORKERID_3);
    }

}
