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
package org.signserver.ejb;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Properties;
import javax.crypto.Cipher;

import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.admin.common.config.RekeyUtil;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.MRTDSignRequest;
import org.signserver.common.MRTDSignResponse;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.common.StaticWorkerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.testutils.ModulesTestCase;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;

/**
 * TODO: Document me!
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class WorkerSessionBeanTest extends ModulesTestCase {

    private final WorkerSession workerSession = getWorkerSession();
    private final ProcessSessionRemote processSession = getProcessSession();

    /**
     * Set up the test case
     */
    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        workerSession.setWorkerProperty(3, WorkerConfig.IMPLEMENTATION_CLASS,
                "org.signserver.module.mrtdsigner.MRTDSigner");
        workerSession.setWorkerProperty(3, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS,
                "org.signserver.server.cryptotokens.KeystoreCryptoToken");

        workerSession.setWorkerProperty(3, "KEYSTOREPATH",
                getSignServerHome() + File.separator + "res" + File.separator +
                        "test" + File.separator + "dss10" + File.separator +
                        "dss10_signer1.p12");
        workerSession.setWorkerProperty(3, "KEYSTORETYPE", "PKCS12");
        workerSession.setWorkerProperty(3, "KEYSTOREPASSWORD", "foo123");
        workerSession.setWorkerProperty(3, "DEFAULTKEY", "Signer 1");
        workerSession.setWorkerProperty(3, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(3, "NAME", "testWorker");
        workerSession.reloadConfiguration(3);

        addDummySigner1(true);
    }

    /*
     * Test method for 'org.signserver.ejb.SignSessionBean.signData(int, ISignRequest)'
     */
    @Test
    public void test01SignData() throws Exception {

        int reqid = 11;
        ArrayList<byte[]> signrequests = new ArrayList<>();

        byte[] signreq1 = "Hello World".getBytes();
        byte[] signreq2 = "Hello World2".getBytes();
        signrequests.add(signreq1);
        signrequests.add(signreq2);

        MRTDSignRequest req = new MRTDSignRequest(reqid, signrequests);
        MRTDSignResponse res = (MRTDSignResponse) processSession.process(new WorkerIdentifier(3), req, new RemoteRequestContext());

        assertEquals(reqid, res.getRequestID());

        Certificate signercert = res.getSignerCertificate();
        ArrayList<?> signatures = (ArrayList<?>) res.getProcessedData();
        assertEquals(2, signatures.size());

        Cipher c = Cipher.getInstance("RSA", "BC");
        c.init(Cipher.DECRYPT_MODE, signercert);

        byte[] signres1 = c.doFinal((byte[]) ((ArrayList<?>) res.getProcessedData()).get(0));
        assertArrayEquals("First MRTD doesn't match with request, " + new String(signreq1) + " = " + new String(signres1), signreq1, signres1);
        byte[] signres2 = c.doFinal((byte[]) ((ArrayList<?>) res.getProcessedData()).get(1));
        assertArrayEquals("Second MRTD doesn't match with request", signreq2, signres2);
    }

    /*
     * Test method for 'org.signserver.ejb.SignSessionBean.getStatus(int)'
     */
    @Test
    public void test02GetStatus() throws Exception {
        assertTrue(((StaticWorkerStatus) workerSession.getStatus(new WorkerIdentifier(3))).getTokenStatus() == WorkerStatus.STATUS_ACTIVE
                || ((StaticWorkerStatus) workerSession.getStatus(new WorkerIdentifier(3))).getTokenStatus() == WorkerStatus.STATUS_OFFLINE);
    }

    @Test
    public void test02GetStatus_ok() throws Exception {
        final WorkerStatus actual = workerSession.getStatus(new WorkerIdentifier(getSignerIdDummy1()));
        assertEquals("getStatus: ", 0, actual.getFatalErrors().size());
        assertEquals(getSignerIdDummy1(), actual.getWorkerId());
    }

    @Test
    public void test02GetStatus_cryptoTokenOffline() throws Exception {
        // First check that there isn't any other problem
        final WorkerStatus before = workerSession.getStatus(new WorkerIdentifier(getSignerIdDummy1()));
        if (!before.getFatalErrors().isEmpty()) {
            throw new Exception("Test case expected the worker status to be OK before it will run");
        }

        // Now change so the crypto token is offline
        final String keyDataBefore = before.getActiveSignerConfig().getProperty("KEYSTOREPATH");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "KEYSTOREPATH");
        workerSession.reloadConfiguration(getSignerIdDummy1());

        final WorkerStatus actual = workerSession.getStatus(new WorkerIdentifier(getSignerIdDummy1()));

        // Restore
        workerSession.setWorkerProperty(getSignerIdDummy1(), "KEYSTOREPATH", keyDataBefore);
        workerSession.reloadConfiguration(getSignerIdDummy1());

        assertFalse("getFatalErrors should not be empty", actual.getFatalErrors().isEmpty());
    }

    /**
     * Tests the isTokenActive method. Checking that the token status is independent of the worker status.
     * @throws Exception in case of error
     */
    @Test
    public void test02isTokenActive() throws Exception {
        // First check that there isn't any other problem
        final WorkerStatus before = workerSession.getStatus(new WorkerIdentifier(getSignerIdDummy1()));
        if (!before.getFatalErrors().isEmpty()) {
            throw new Exception("Test case expected the worker status to be OK before it will run");
        }

        assertTrue("token active", workerSession.isTokenActive(new WorkerIdentifier(getSignerIdDummy1())));

        // Make a configuration error making the _worker_ offline but the _token_ still active
        workerSession.setWorkerProperty(getSignerIdDummy1(), WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS, "_not_a_level_");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        assertTrue("token still active", workerSession.isTokenActive(new WorkerIdentifier(getSignerIdDummy1())));
        if (workerSession.getStatus(new WorkerIdentifier(getSignerIdDummy1())).getFatalErrors().isEmpty()) {
            throw new Exception("Test case expected the worker status to be OFFLINE because of incorrect value for INCLUDE_CERTIFICATE_LEVEL but it was not");
        }

        // Remove the configuration error
        workerSession.removeWorkerProperty(getSignerIdDummy1(), WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS);
        workerSession.reloadConfiguration(getSignerIdDummy1());
        if (!workerSession.getStatus(new WorkerIdentifier(getSignerIdDummy1())).getFatalErrors().isEmpty()) {
            throw new Exception("Test case expected the worker status to be ok now");
        }

        // Now change so the crypto token is offline
        final String keyDataBefore = before.getActiveSignerConfig().getProperty("KEYSTOREPATH");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "KEYSTOREPATH");
        workerSession.reloadConfiguration(getSignerIdDummy1());

        assertFalse("token offline", workerSession.isTokenActive(new WorkerIdentifier(getSignerIdDummy1())));

        // Restore
        workerSession.setWorkerProperty(getSignerIdDummy1(), "KEYSTOREPATH", keyDataBefore);
        workerSession.reloadConfiguration(getSignerIdDummy1());
    }

    /*
     *
     * Test method for 'org.signserver.ejb.SignSessionBean.reloadConfiguration()'
     */
    @Test
    public void test03ReloadConfiguration() {
        workerSession.reloadConfiguration(0);
    }

    @Test
    public void test04NameMapping() throws Exception {
        int id = workerSession.getWorkerId("testWorker");
        assertEquals("" + id, 3, id);
    }

    /*
     * Test method for 'org.signserver.ejb.SignSessionBean.SetProperty(int, String, String)'
     */
    @Test
    public void test05SetProperty() {
        workerSession.setWorkerProperty(3, "test", "Hello World");

        Properties props = workerSession.getCurrentWorkerConfig(3).getProperties();
        assertEquals("Hello World", props.getProperty("TEST"));
    }

    /*
     * Test method for 'org.signserver.ejb.SignSessionBean.RemoveProperty(int, String)'
     */
    @Test
    public void test06RemoveProperty() {
        workerSession.removeWorkerProperty(3, "test");

        Properties props = workerSession.getCurrentWorkerConfig(3).getProperties();
        assertNull(props.getProperty("test"));
    }

    /*
     * Test method for 'org.signserver.ejb.SignSessionBean.AddAuthorizedClient(int, AuthorizedClient)'
     */
    @Test
    public void test07AddAuthorizedClient() {
        AuthorizedClient authClient = new AuthorizedClient("123456", "CN=testca");
        workerSession.addAuthorizedClient(3, authClient);

        Collection<?> result = workerSession.getAuthorizedClients(3);
        boolean exists = false;
        for (Object o : result) {
            AuthorizedClient next = (AuthorizedClient) o;
            exists = exists || (next.getCertSN().equals("123456") && next.getIssuerDN().equals("CN=testca"));
        }

        assertTrue(exists);
    }

    /*
     * Test method for 'org.signserver.ejb.SignSessionBean.RemoveAuthorizedClient(int, AuthorizedClient)'
     */
    @Test
    public void test08RemoveAuthorizedClient() {
        int initialsize = workerSession.getAuthorizedClients(3).size();
        AuthorizedClient authClient = new AuthorizedClient("123456", "CN=testca");
        assertTrue(workerSession.removeAuthorizedClient(3, authClient));

        Collection<?> result = workerSession.getAuthorizedClients(3);
        assertEquals(result.size(), initialsize - 1);

        boolean exists = false;
        for (Object o : result) {
            AuthorizedClient next = (AuthorizedClient) o;
            exists = exists || (next.getCertSN().equals("123456") && next.getIssuerDN().equals("CN=testca"));
        }

        assertFalse(exists);
    }

    /**
     * Test for nextAliasInSequence.
     */
    @Test
    public void test09nextAliasInSequence() {

        assertEquals("KeyAlias2",
                RekeyUtil.nextAliasInSequence("KeyAlias1"));
        assertEquals("MyKey00002",
                RekeyUtil.nextAliasInSequence("MyKey00001"));
        assertEquals("MyKey2",
                RekeyUtil.nextAliasInSequence("MyKey"));
        assertEquals("MyKey00001",
                RekeyUtil.nextAliasInSequence("MyKey00000"));
        assertEquals("MyKeys1_0038",
                RekeyUtil.nextAliasInSequence("MyKeys1_0037"));
    }

    /**
     * Tests that a request to a disabled worker fails.
     */
    @Test
    public void test10processForDisabledWorker() throws Exception {
        // Restore
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "DISABLED");
        workerSession.reloadConfiguration(getSignerIdDummy1());

        // First test that there isn't anything wrong with the worker before
        GenericSignRequest request = new GenericSignRequest(123, "<test/>".getBytes(StandardCharsets.UTF_8));
        processSession.process(new WorkerIdentifier(getSignerIdDummy1()), request, new RemoteRequestContext());

        try {
            workerSession.setWorkerProperty(getSignerIdDummy1(), "DISABLED", "TRUE");
            workerSession.reloadConfiguration(getSignerIdDummy1());

            // Test signing
            request = new GenericSignRequest(124, "<test/>".getBytes(StandardCharsets.UTF_8));
            processSession.process(new WorkerIdentifier(getSignerIdDummy1()), request, new RemoteRequestContext());
            fail("Request should have failed as worker is disabled");
        } catch (CryptoTokenOfflineException ex) { // OK
            assertTrue("message should say that worker is disabled: " + ex.getMessage(), ex.getMessage().contains("disabled") || ex.getMessage().contains("Disabled"));
            System.out.println("ex.msg: " + ex.getMessage());
        } finally {
            // Restore
            workerSession.removeWorkerProperty(getSignerIdDummy1(), "DISABLED");
            workerSession.reloadConfiguration(getSignerIdDummy1());
        }
    }

    /**
     * Test that getCurrentWorkerConfig doesn't include the internal authclients
     * mapping.
     */
    @Test
    public void test12noAuthClientsInGetCurrentWorkerConfig() {
        try {
            workerSession.addAuthorizedClient(getSignerIdDummy1(),
               new AuthorizedClient("123456789", "CN=SomeUser"));

            final WorkerConfig config =
                    workerSession.getCurrentWorkerConfig(getSignerIdDummy1());

            assertTrue("Should not contain authclients",
                    config.getAuthorizedClients().isEmpty());
        } finally {
            workerSession.removeAuthorizedClient(getSignerIdDummy1(),
               new AuthorizedClient("123456789", "CN=SomeUser"));
        }
    }

    /**
     * Try setting a class property (such as WORKERLOGGER, AUTHORIZER to
     * a nonexisting class and check for an expected error.
     *
     * @param property Property to try with
     * @param expectedErrorString Error string to expect as part of a fatal
     *                            error component
     */
    private void testWithInvalidClass(final String property,
                                      final String expectedErrorString)
            throws Exception {
        try {
            workerSession.setWorkerProperty(getSignerIdDummy1(),
                property, "nonexistant");
            workerSession.reloadConfiguration(getSignerIdDummy1());

            final List<String> fatalErrors =
                    workerSession.getStatus(new WorkerIdentifier(getSignerIdDummy1())).getFatalErrors();
            boolean foundError = false;
            for (final String fatalError : fatalErrors) {
                // check for an error message mentioning WORKERLOGGER
                if (fatalError.contains(expectedErrorString)) {
                    foundError = true;
                    break;
                }
            }
            assertTrue("Should contain error", foundError);
        } finally {
            workerSession.removeWorkerProperty(getSignerIdDummy1(), property);
            workerSession.reloadConfiguration(getSignerIdDummy1());
        }
    }

    /**
     * Test that setting a non-existing WORKERLOGGER results in a fatal error.
     */
    @Test
    public void test13invalidWorkerLogger() throws Exception {
        testWithInvalidClass("WORKERLOGGER", "WORKERLOGGER");
    }

    @Test
    public void test14invalidAuthorizer() throws Exception {
        testWithInvalidClass("AUTHTYPE", "AUTHTYPE");
    }

    @Test
    public void test15invalidAccounter() throws Exception {
        testWithInvalidClass("ACCOUNTER", "ACCOUNTER");
    }

    @Test
    public void test16invalidArchiver() throws Exception {
        testWithInvalidClass("ARCHIVERS", "ARCHIVERS");
    }
    
    /**
     * Tests that after renaming a worker the new name can be used but not the
     * old name.
     * @throws Exception in case of error
     */
    @Test
    public void test20RenamedWorkerNotAccessibleWithOldName() throws Exception {
        final int workerId = 12345;
        try {
            // given
            final String initialName = "TestWorkerNameInitial";
            final String newName = "WorkerWorkerNameNew";        
            addDummySigner(workerId, initialName, true);

            // Test that signing works with the inital name
            GenericSignRequest request = new GenericSignRequest(2, "<test1/>".getBytes(StandardCharsets.UTF_8));
            processSession.process(new WorkerIdentifier(initialName), request, new RemoteRequestContext());

            // when
            // Rename the worker
            workerSession.setWorkerProperty(workerId, "NAME", newName);
            workerSession.reloadConfiguration(workerId);

            // then
            // It should be possible to sign with the new name
            try {
                request = new GenericSignRequest(3, "<test2/>".getBytes(StandardCharsets.UTF_8));
                processSession.process(new WorkerIdentifier(newName), request, new RemoteRequestContext());
            } catch (IllegalRequestException | SignServerException | CryptoTokenOfflineException ex) {
                fail("Signing failed with new name after rename: " + ex.getMessage());
            }
            // It should not be possible to sign with the old name
            try {
                request = new GenericSignRequest(4, "<test3/>".getBytes(StandardCharsets.UTF_8));
                processSession.process(new WorkerIdentifier(initialName), request, new RemoteRequestContext());
                fail("Should have failed as the worker has been renamed");
            } catch (IllegalRequestException ex) {
                assertEquals("No such worker: " + initialName, ex.getMessage());
            }
        } finally {
            removeWorker(workerId);
        }
    }
    
    /**
     * Tests that a worker can not be called (by name) after it has been
     * removed.
     * @throws Exception in case of error
     */
    @Test
    public void test21RemovedWorkerNotAccessible() throws Exception {
        final int workerId = 12346;
        try {
            // given
            final String workerName = "TheWorkerName";
            addDummySigner(workerId, workerName, true);

            // Test that signing works with the worker
            GenericSignRequest request = new GenericSignRequest(2, "<test1/>".getBytes(StandardCharsets.UTF_8));
            processSession.process(new WorkerIdentifier(workerName), request, new RemoteRequestContext());

            // when
            // Remove the worker
            removeWorker(workerId);

            // then
            // It should not be possible to sign with the worker name
            try {
                request = new GenericSignRequest(4, "<test3/>".getBytes(StandardCharsets.UTF_8));
                processSession.process(new WorkerIdentifier(workerName), request, new RemoteRequestContext());
                fail("Should have failed as the worker has been removed");
            } catch (IllegalRequestException ex) {
                assertEquals("No such worker: " + workerName, ex.getMessage());
            }
            // It should not be possible to sign with the worker id
            try {
                request = new GenericSignRequest(4, "<test3/>".getBytes(StandardCharsets.UTF_8));
                processSession.process(new WorkerIdentifier(workerId), request, new RemoteRequestContext());
                fail("Should have failed as the worker has been removed");
            } catch (IllegalRequestException ex) {
                assertEquals("No such worker: " + workerId, ex.getMessage());
            }
        } finally {
            removeWorker(workerId);
        }
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(3);
        removeWorker(getSignerIdDummy1());
    }
}
