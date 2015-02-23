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

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Properties;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.junit.After;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.*;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.module.tsa.TimeStampSigner;
import org.signserver.server.cryptotokens.HardCodedCryptoToken;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestingSecurityManager;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.util.PathUtil;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CustomAuthTest extends ModulesTestCase {

    private String signserverhome;
    private int moduleVersion;
    
    private final IWorkerSession workerSession = getWorkerSession();
    private final IGlobalConfigurationSession globalSession = getGlobalSession();

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        signserverhome = PathUtil.getAppHome().getAbsolutePath();
        assertNotNull(signserverhome);
    }

    /* (non-Javadoc)
     * @see junit.framework.TestCase#tearDown()
     */
    @After
    public void tearDown() throws Exception {
        TestingSecurityManager.remove();
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER9.CLASSPATH", "org.signserver.module.tsa.TimeStampSigner");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER9.SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.P12CryptoToken");

        workerSession.setWorkerProperty(9, "AUTHTYPE", "org.signserver.server.DummyAuthorizer");
        workerSession.setWorkerProperty(9, "TESTAUTHPROP", "DATA");
        workerSession.setWorkerProperty(9, "KEYSTOREPATH", signserverhome + "/res/test/dss10/dss10_tssigner1.p12");
        workerSession.setWorkerProperty(9, "KEYSTOREPASSWORD", "foo123");
        workerSession.setWorkerProperty(9, "DEFAULTKEY", "TS Signer 1");
        workerSession.setWorkerProperty(9, TimeStampSigner.DEFAULTTSAPOLICYOID, "1.0.1.2.33");
        workerSession.setWorkerProperty(9, TimeStampSigner.TSA, "CN=TimeStampTest1");
        workerSession.setWorkerProperty(9, SignServerConstants.MODULENAME, "TSA");
        workerSession.setWorkerProperty(9, SignServerConstants.MODULEVERSION, moduleVersion + "");

        workerSession.reloadConfiguration(9);
    }

    @Test
    public void test01TestCustomAuth() throws Exception {
        genTimeStampRequest(1, null, null);

        try {
            genTimeStampRequest(2, null, null);
            assertTrue(false);
        } catch (IllegalRequestException e) {
        }

        genTimeStampRequest(1, null, "1.2.3.4");
        try {
            genTimeStampRequest(1, null, "1.2.3.5");
            assertTrue(false);
        } catch (IllegalRequestException e) {
        }

        HardCodedCryptoToken token = new HardCodedCryptoToken();
        token.init(1, new Properties());

        // This test apparently borrows the signer certificate to test with
        // as if it were a client authentication certificate. Well I guess it work...
        X509Certificate cert = (X509Certificate) token.getCertificate(ICryptoToken.PROVIDERUSAGE_SIGN);
        //System.out.println(CertTools.stringToBCDNString(cert.getSubjectDN().toString()));

        try {
            genTimeStampRequest(1, cert, null);
            assertTrue(false);
        } catch (IllegalRequestException e) {
        }

    }

    private void genTimeStampRequest(int reqid, X509Certificate cert, String ip) throws Exception {
        TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();

        GenericSignRequest req = new GenericSignRequest(reqid, requestBytes);

        GenericSignResponse res = (GenericSignResponse) workerSession.process(9, req, new RequestContext(cert, ip));

        assertTrue(reqid == res.getRequestID());

        Certificate signercert = res.getSignerCertificate();

        assertNotNull(signercert);
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(9);
    }
}
