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
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import javax.crypto.Cipher;
import org.signserver.common.*;
import org.signserver.testutils.ModulesTestCase;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSession;

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
    protected void setUp() throws Exception {
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
        ArrayList<byte[]> signrequests = new ArrayList<byte[]>();

        byte[] signreq1 = "Hello World".getBytes();
        byte[] signreq2 = "Hello World2".getBytes();
        signrequests.add(signreq1);
        signrequests.add(signreq2);

        MRTDSignRequest req = new MRTDSignRequest(reqid, signrequests);
        MRTDSignResponse res = (MRTDSignResponse) processSession.process(new WorkerIdentifier(3), req, new RemoteRequestContext());

        assertTrue(reqid == res.getRequestID());

        Certificate signercert = res.getSignerCertificate();
        ArrayList<?> signatures = (ArrayList<?>) res.getProcessedData();
        assertTrue(signatures.size() == 2);

        Cipher c = Cipher.getInstance("RSA", "BC");
        c.init(Cipher.DECRYPT_MODE, signercert);

        byte[] signres1 = c.doFinal((byte[]) ((ArrayList<?>) res.getProcessedData()).get(0));

        if (!arrayEquals(signreq1, signres1)) {
            assertTrue("First MRTD doesn't match with request, " + new String(signreq1) + " = " + new String(signres1), false);
        }

        byte[] signres2 = c.doFinal((byte[]) ((ArrayList<?>) res.getProcessedData()).get(1));

        if (!arrayEquals(signreq2, signres2)) {
            assertTrue("Second MRTD doesn't match with request", false);
        }
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

    /*
     * 
     * Test method for 'org.signserver.ejb.SignSessionBean.reloadConfiguration()'
     */
    @Test
    public void test03ReloadConfiguration() throws Exception {
        workerSession.reloadConfiguration(0);
    }

    @Test
    public void test04NameMapping() throws Exception {
        int id = workerSession.getWorkerId("testWorker");
        assertTrue("" + id, id == 3);
    }

    /*
     * Test method for 'org.signserver.ejb.SignSessionBean.SetProperty(int, String, String)'
     */
    @Test
    public void test05SetProperty() throws Exception {
        workerSession.setWorkerProperty(3, "test", "Hello World");

        Properties props = workerSession.getCurrentWorkerConfig(3).getProperties();
        assertTrue(props.getProperty("TEST").equals("Hello World"));
    }

    /*
     * Test method for 'org.signserver.ejb.SignSessionBean.RemoveProperty(int, String)'
     */
    @Test
    public void test06RemoveProperty() throws Exception {
        workerSession.removeWorkerProperty(3, "test");

        Properties props = workerSession.getCurrentWorkerConfig(3).getProperties();
        assertNull(props.getProperty("test"));
    }

    /*
     * Test method for 'org.signserver.ejb.SignSessionBean.AddAuthorizedClient(int, AuthorizedClient)'
     */
    @Test
    public void test07AddAuthorizedClient() throws Exception {
        AuthorizedClient authClient = new AuthorizedClient("123456", "CN=testca");
        workerSession.addAuthorizedClient(3, authClient);

        Collection<?> result = workerSession.getAuthorizedClients(3);
        boolean exists = false;
        Iterator<?> iter = result.iterator();
        while (iter.hasNext()) {
            AuthorizedClient next = (AuthorizedClient) iter.next();
            exists = exists || (next.getCertSN().equals("123456") && next.getIssuerDN().toString().equals("CN=testca"));
        }

        assertTrue(exists);
    }

    /*
     * Test method for 'org.signserver.ejb.SignSessionBean.RemoveAuthorizedClient(int, AuthorizedClient)'
     */
    @Test
    public void test08RemoveAuthorizedClient() throws Exception {
        int initialsize = workerSession.getAuthorizedClients(3).size();
        AuthorizedClient authClient = new AuthorizedClient("123456", "CN=testca");
        assertTrue(workerSession.removeAuthorizedClient(3, authClient));

        Collection<?> result = workerSession.getAuthorizedClients(3);
        assertTrue(result.size() == initialsize - 1);

        boolean exists = false;
        Iterator<?> iter = result.iterator();
        while (iter.hasNext()) {
            AuthorizedClient next = (AuthorizedClient) iter.next();
            exists = exists || (next.getCertSN().equals("123456") && next.getIssuerDN().toString().equals("CN=testca"));
        }

        assertFalse(exists);
    }

    /**
     * Test for nextAliasInSequence.
     * @throws Exception in case of exception
     */
    @Test
    public void test09nextAliasInSequence() throws Exception {

        assertEquals("KeyAlias2",
                WorkerSessionBean.nextAliasInSequence("KeyAlias1"));
        assertEquals("MyKey00002",
                WorkerSessionBean.nextAliasInSequence("MyKey00001"));
        assertEquals("MyKey2",
                WorkerSessionBean.nextAliasInSequence("MyKey"));
        assertEquals("MyKey00001",
                WorkerSessionBean.nextAliasInSequence("MyKey00000"));
        assertEquals("MyKeys1_0038",
                WorkerSessionBean.nextAliasInSequence("MyKeys1_0037"));
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
        GenericSignRequest request = new GenericSignRequest(123, "<test/>".getBytes("UTF-8"));
        processSession.process(new WorkerIdentifier(getSignerIdDummy1()), request, new RemoteRequestContext());
        
        try {
            workerSession.setWorkerProperty(getSignerIdDummy1(), "DISABLED", "TRUE");
            workerSession.reloadConfiguration(getSignerIdDummy1());
            
            // Test signing
            request = new GenericSignRequest(124, "<test/>".getBytes("UTF-8"));
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
     * 
     * @throws Exception 
     */
    @Test
    public void test12noAuthClientsInGetCurrentWorkerConfig() throws Exception {
        try {
            workerSession.addAuthorizedClient(getSignerIdDummy1(),
               new AuthorizedClient("123456789", "CN=SomeUser"));
            
            final WorkerConfig config =
                    workerSession.getCurrentWorkerConfig(getSignerIdDummy1());
            final ProcessableConfig pc = new ProcessableConfig(config);
            
            assertTrue("Should not contain authclients",
                    pc.getAuthorizedClients().isEmpty());
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
     * @throws Exception 
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
                if (fatalError.indexOf(expectedErrorString) != -1) {
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
     * 
     * @throws Exception 
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

    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(3);
        removeWorker(getSignerIdDummy1());
    }

    private boolean arrayEquals(byte[] signreq2, byte[] signres2) {
        boolean retval = true;

        if (signreq2.length != signres2.length) {
            return false;
        }

        for (int i = 0; i < signreq2.length; i++) {
            if (signreq2[i] != signres2[i]) {
                return false;
            }
        }
        return retval;
    }
}
