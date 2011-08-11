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
package org.signserver.module.mrtdsigner;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;

import junit.framework.TestCase;

import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.MRTDSignRequest;
import org.signserver.common.MRTDSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.common.SignerStatus;
import org.signserver.common.ServiceLocator;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class MRTDSignerTest extends TestCase {

    private static IWorkerSession.IRemote sSSession = null;
    private static String signserverhome;
    private static int moduleVersion;

    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
        sSSession = ServiceLocator.getInstance().lookupRemote(IWorkerSession.IRemote.class);
        TestUtils.redirectToTempOut();
        TestUtils.redirectToTempErr();
        TestingSecurityManager.install();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
    }

    /* (non-Javadoc)
     * @see junit.framework.TestCase#tearDown()
     */
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        TestingSecurityManager.remove();
    }

    public void test00SetupDatabase() throws Exception {

        MARFileParser marFileParser = new MARFileParser(signserverhome + "/dist-server/mrtdsigner.mar");
        moduleVersion = marFileParser.getVersionFromMARFile();

        TestUtils.assertSuccessfulExecution(new String[]{"module", "add",
                    signserverhome + "/dist-server/mrtdsigner.mar", "junittest"});
        assertTrue(TestUtils.grepTempOut("Loading module MRTDSIGNER"));
        assertTrue(TestUtils.grepTempOut("Module loaded successfully."));

        sSSession.reloadConfiguration(7890);
    }

    /*
     * Test method for 'org.signserver.server.MRTDSigner.signData(ISignRequest)'
     */
    public void testSignData() throws Exception {
        int reqid = 12;
        ArrayList<byte[]> signrequests = new ArrayList<byte[]>();

        byte[] signreq1 = "Hello World".getBytes();
        byte[] signreq2 = "Hello World2".getBytes();
        signrequests.add(signreq1);
        signrequests.add(signreq2);

        MRTDSignResponse res = (MRTDSignResponse) sSSession.process(7890, new MRTDSignRequest(reqid, signrequests), new RequestContext());
        assertTrue(res != null);
        assertTrue(reqid == res.getRequestID());
        Certificate signercert = res.getSignerCertificate();
        assertNotNull(signercert);

        Cipher c = Cipher.getInstance("RSA", "BC");
        c.init(Cipher.DECRYPT_MODE, signercert);

        byte[] signres1 = c.doFinal((byte[]) ((ArrayList<?>) res.getProcessedData()).get(0));

        if (!arrayEquals(signreq1, signres1)) {
            assertTrue("First MRTD doesn't match with request", false);
        }

        byte[] signres2 = c.doFinal((byte[]) ((ArrayList<?>) res.getProcessedData()).get(1));

        if (!arrayEquals(signreq2, signres2)) {
            assertTrue("Second MRTD doesn't match with request", false);
        }
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

    /*
     * Test method for 'org.signserver.server.MRTDSigner.getStatus()'
     */
    public void testGetStatus() throws Exception {
        SignerStatus stat = (SignerStatus) sSSession.getStatus(7890);
        assertTrue(stat.getTokenStatus() == SignerStatus.STATUS_ACTIVE);

    }

    public void testGenericSignData() throws Exception {

        int reqid = 13;
        byte[] signreq1 = "Hello World".getBytes();

        GenericSignResponse res = (GenericSignResponse) sSSession.process(7890, new GenericSignRequest(reqid, signreq1), new RequestContext());
        assertTrue(res != null);
        assertTrue(reqid == res.getRequestID());
        Certificate signercert = res.getSignerCertificate();
        assertNotNull(signercert);

        Cipher c = Cipher.getInstance("RSA", "BC");
        c.init(Cipher.DECRYPT_MODE, signercert);

        byte[] signres1 = c.doFinal(res.getProcessedData());

        assertTrue(Arrays.equals(signreq1, signres1));
    }

    public void test99TearDownDatabase() throws Exception {
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker",
                    "7890"});

        TestUtils.assertSuccessfulExecution(new String[]{"module", "remove", "MRTDSIGNER", "" + moduleVersion});
        assertTrue(TestUtils.grepTempOut("Removal of module successful."));
        sSSession.reloadConfiguration(7890);
    }
}
