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

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Properties;
import javax.crypto.Cipher;
import org.signserver.common.*;
import org.signserver.testutils.ModulesTestCase;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class WorkerSessionBeanTest extends ModulesTestCase {

    /**
     * Set up the test case
     */
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
    }
    /* (non-Javadoc)
     * @see junit.framework.TestCase#tearDown()
     */

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    public void test00SetupDatabase() throws Exception {
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
                "WORKER3.CLASSPATH",
                "org.signserver.module.mrtdsigner.MRTDSigner");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
                "WORKER3.SIGNERTOKEN.CLASSPATH",
                "org.signserver.server.cryptotokens.HardCodedCryptoToken");

        workerSession.setWorkerProperty(3, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(3, "NAME", "testWorker");
        workerSession.reloadConfiguration(3);
                
        addDummySigner1();
    }

    /*
     * Test method for 'org.signserver.ejb.SignSessionBean.signData(int, ISignRequest)'
     */
    public void test01SignData() throws Exception {

        int reqid = 11;
        ArrayList<byte[]> signrequests = new ArrayList<byte[]>();

        byte[] signreq1 = "Hello World".getBytes();
        byte[] signreq2 = "Hello World2".getBytes();
        signrequests.add(signreq1);
        signrequests.add(signreq2);

        MRTDSignRequest req = new MRTDSignRequest(reqid, signrequests);
        MRTDSignResponse res = (MRTDSignResponse) workerSession.process(3, req, new RequestContext());

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
    public void test02GetStatus() throws Exception {
        assertTrue(((SignerStatus) workerSession.getStatus(3)).getTokenStatus() == SignerStatus.STATUS_ACTIVE
                || ((SignerStatus) workerSession.getStatus(3)).getTokenStatus() == SignerStatus.STATUS_OFFLINE);
    }
     
    public void test02GetStatus_ok() throws Exception {
        final WorkerStatus actual = workerSession.getStatus(getSignerIdDummy1());
        assertNull("getStatus: ", actual.isOK());
        assertEquals(getSignerIdDummy1(), actual.getWorkerId());
    }
    
    public void test02GetStatus_cryptoTokenOffline() throws Exception {
        // First check that there isn't any other problem
        final WorkerStatus before = workerSession.getStatus(getSignerIdDummy1());
        if (before.isOK() != null) {
            throw new Exception("Test case expected the worker status to be OK before it will run");
        }
        
        // Now change so the crypto token is offline
        final String keyDataBefore = before.getActiveSignerConfig().getProperty("KEYDATA");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "KEYDATA");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        final WorkerStatus actual = workerSession.getStatus(getSignerIdDummy1());
        
        // Restore
        workerSession.setWorkerProperty(getSignerIdDummy1(), "KEYDATA", keyDataBefore);
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        assertNotNull("getStatus should not be null", actual.isOK());
    }

    /*
     * 
     * Test method for 'org.signserver.ejb.SignSessionBean.reloadConfiguration()'
     */
    public void test03ReloadConfiguration() throws Exception {
        workerSession.reloadConfiguration(0);
    }

    public void test04NameMapping() throws Exception {
        int id = workerSession.getWorkerId("testWorker");
        assertTrue("" + id, id == 3);
    }

    /*
     * Test method for 'org.signserver.ejb.SignSessionBean.SetProperty(int, String, String)'
     */
    public void test05SetProperty() throws Exception {
        workerSession.setWorkerProperty(3, "test", "Hello World");

        Properties props = workerSession.getCurrentWorkerConfig(3).getProperties();
        assertTrue(props.getProperty("TEST").equals("Hello World"));
    }
    /*
     * Test method for 'org.signserver.ejb.SignSessionBean.RemoveProperty(int, String)'
     */

    public void test06RemoveProperty() throws Exception {
        workerSession.removeWorkerProperty(3, "test");

        Properties props = workerSession.getCurrentWorkerConfig(3).getProperties();
        assertNull(props.getProperty("test"));
    }
    /*
     * Test method for 'org.signserver.ejb.SignSessionBean.AddAuthorizedClient(int, AuthorizedClient)'
     */

    public void test07AddAuthorizedClient() throws Exception {
        AuthorizedClient authClient = new AuthorizedClient("123456", "CN=testca");
        workerSession.addAuthorizedClient(3, authClient);

        Collection<?> result = new ProcessableConfig(workerSession.getCurrentWorkerConfig(3)).getAuthorizedClients();
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

    public void test08RemoveAuthorizedClient() throws Exception {
        int initialsize = new ProcessableConfig(workerSession.getCurrentWorkerConfig(3)).getAuthorizedClients().size();
        AuthorizedClient authClient = new AuthorizedClient("123456", "CN=testca");
        assertTrue(workerSession.removeAuthorizedClient(3, authClient));

        Collection<?> result = new ProcessableConfig(workerSession.getCurrentWorkerConfig(3)).getAuthorizedClients();
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

    public void test99TearDownDatabase() throws Exception {
        removeWorker(3);
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
