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
package org.signserver.protocol.ws;

import java.io.File;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.RequestAndResponseManager;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.module.tsa.TimeStampSigner;
import org.signserver.protocol.ws.client.ISignServerWSClient;
import org.signserver.protocol.ws.client.SignServerWSClientFactory;
import org.signserver.protocol.ws.client.WSClientUtil;
import org.signserver.protocol.ws.gen.CryptoTokenOfflineException_Exception;
import org.signserver.protocol.ws.gen.IllegalRequestException_Exception;
import org.signserver.protocol.ws.gen.InvalidWorkerIdException_Exception;
import org.signserver.protocol.ws.gen.ProcessResponseWS;
import org.signserver.protocol.ws.gen.SignServerWS;
import org.signserver.protocol.ws.gen.SignServerWSService;
import org.signserver.protocol.ws.gen.WorkerStatusWS;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.ValidationServiceConstants;
import org.signserver.validationservice.server.ValidationTestUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.signserver.protocol.ws.WorkerStatusWS.OVERALLSTATUS_ALLOK;
import static org.signserver.protocol.ws.WorkerStatusWS.OVERALLSTATUS_ERROR;

/**
 * TODO: Document me!
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MainWebServiceTestSeparately extends ModulesTestCase {

    private static final Logger LOG = Logger.getLogger(MainWebServiceTestSeparately.class);

    private static X509Certificate validCert1;
    private SignServerWS signServerWS;

    private final WorkerSession workerSession = getWorkerSession();

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();

        QName qname = new QName("gen.ws.protocol.signserver.org", "SignServerWSService");
        SignServerWSService signServerWSService = new SignServerWSService(new URL("http://localhost:8080/signserver/signserverws/signserverws?wsdl"), qname);
        signServerWS = signServerWSService.getSignServerWSPort();
    }

    @After
    public void tearDown() {
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        workerSession.setWorkerProperty(9, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.tsa.TimeStampSigner");
        workerSession.setWorkerProperty(9, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, "org.signserver.server.cryptotokens.P12CryptoToken");

        workerSession.setWorkerProperty(9, "AUTHTYPE", "org.signserver.server.DummyAuthorizer");
        workerSession.setWorkerProperty(9, "TESTAUTHPROP", "DATA");
        workerSession.setWorkerProperty(9, "NAME", "TestTimeStamp");
        final String signserverhome = PathUtil.getAppHome().getAbsolutePath();
        assertNotNull(signserverhome);
        workerSession.setWorkerProperty(9, "KEYSTOREPATH", signserverhome + "/src/test/timestamp1.p12");
        //sSSession.setWorkerProperty(9, "KEYSTOREPASSWORD", "foo123");
        workerSession.setWorkerProperty(9, TimeStampSigner.DEFAULTTSAPOLICYOID, "1.0.1.2.33");
        workerSession.setWorkerProperty(9, TimeStampSigner.TSA, "CN=TimeStampTest1");
        workerSession.reloadConfiguration(9);

        KeyPair validRootCA1Keys = KeyTools.genKeys("1024", "RSA");
        X509Certificate validRootCA1 = ValidationTestUtils.genCert("CN=ValidRootCA1", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validRootCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

        KeyPair validSubCA1Keys = KeyTools.genKeys("1024", "RSA");
        X509Certificate validSubCA1 = ValidationTestUtils.genCert("CN=ValidSubCA1", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validSubCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

        KeyPair validCert1Keys = KeyTools.genKeys("1024", "RSA");
        validCert1 = ValidationTestUtils.genCert("CN=ValidCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);


        ArrayList<X509Certificate> validChain1 = new ArrayList<>();
        // Add in the wrong order
        validChain1.add(validRootCA1);
        validChain1.add(validSubCA1);

        workerSession.setWorkerProperty(16, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.validationservice.server.ValidationServiceWorker");
        workerSession.setWorkerProperty(16, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, "org.signserver.server.cryptotokens.KeystoreCryptoToken");

        workerSession.setWorkerProperty(16, "KEYSTOREPATH",
                signserverhome + File.separator + "res" + File.separator +
                        "test" + File.separator + "dss10" + File.separator +
                        "dss10_signer1.p12");
        workerSession.setWorkerProperty(16, "KEYSTORETYPE", "PKCS12");
        workerSession.setWorkerProperty(16, "KEYSTOREPASSWORD", "foo123");
        workerSession.setWorkerProperty(16, "DEFAULTKEY", "Signer 1");
        workerSession.setWorkerProperty(16, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(16, "NAME", "ValTest");
        workerSession.setWorkerProperty(16, "VAL1.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");
        workerSession.setWorkerProperty(16, "VAL1.TESTPROP", "TEST");
        workerSession.setWorkerProperty(16, "VAL1.ISSUER1.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(validChain1));

        workerSession.reloadConfiguration(16);
    }

    @Test
    public void test01BasicWSStatuses() throws InvalidWorkerIdException_Exception, CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException, InvalidWorkerIdException {
        List<WorkerStatusWS> statuses = signServerWS.getStatus("9");
        assertEquals(1, statuses.size());
        assertEquals("9", statuses.get(0).getWorkerName());
        assertEquals(statuses.get(0).getOverallStatus(), OVERALLSTATUS_ERROR);
        assertNotNull(statuses.get(0).getErrormessage());
        workerSession.activateSigner(new WorkerIdentifier(9), "foo123");
        statuses = signServerWS.getStatus("TestTimeStamp");
        assertEquals(1, statuses.size());
        assertEquals("TestTimeStamp", statuses.get(0).getWorkerName());
        assertEquals(statuses.get(0).getOverallStatus(), OVERALLSTATUS_ALLOK);
        assertNull(statuses.get(0).getErrormessage());

        statuses = signServerWS.getStatus("ALLWORKERS");
        final StringBuilder sb = new StringBuilder();
        for (org.signserver.protocol.ws.gen.WorkerStatusWS stat : statuses) {
            sb.append(stat.getWorkerName());
            sb.append(", ");
        }
        LOG.info("Got status for: " + sb);
        assertTrue(statuses.size() >= 2);
        assertTrue("workerStatusesContains 9", workerStatusesContains(statuses, "9"));
        assertTrue("workerStatusesContains 16", workerStatusesContains(statuses, "16"));

        try {
            signServerWS.getStatus("1991817");
            fail();
        } catch (InvalidWorkerIdException_Exception e) {
        }
    }

    @Test
    public void test02BasicWSProcess() throws Exception {
        TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest1 = timeStampRequestGenerator.generate(TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        byte[] requestBytes1 = timeStampRequest1.getEncoded();
        GenericSignRequest signRequest1 = new GenericSignRequest(12, requestBytes1);
        ProcessRequestWS req1 = new ProcessRequestWS(signRequest1);

        TimeStampRequest timeStampRequest2 = timeStampRequestGenerator.generate(TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        byte[] requestBytes2 = timeStampRequest2.getEncoded();
        GenericSignRequest signRequest2 = new GenericSignRequest(13, requestBytes2);
        ProcessRequestWS req2 = new ProcessRequestWS(signRequest2);

        ArrayList<ProcessRequestWS> reqs = new ArrayList<>();
        reqs.add(req1);
        reqs.add(req2);

        try {
            signServerWS.process("9", WSClientUtil.convertProcessRequestWS(reqs));
            fail();
        } catch (IllegalRequestException_Exception e) {
        }

        workerSession.setWorkerProperty(9, "AUTHTYPE", "NOAUTH");
        workerSession.reloadConfiguration(9);

        workerSession.deactivateSigner(new WorkerIdentifier(9));
        try {
            signServerWS.process("9", WSClientUtil.convertProcessRequestWS(reqs));
            fail();
        } catch (CryptoTokenOfflineException_Exception e) {
        }

        workerSession.activateSigner(new WorkerIdentifier(9), "foo123");

        List<ProcessResponseWS> resps = signServerWS.process("TestTimeStamp", WSClientUtil.convertProcessRequestWS(reqs));
        assertEquals(2, resps.size());
        assertEquals(12, resps.get(0).getRequestID());
        assertEquals(13, resps.get(1).getRequestID());
        assertNotNull(resps.get(0).getWorkerCertificate());

        GenericSignResponse resp = (GenericSignResponse) RequestAndResponseManager.parseProcessResponse(WSClientUtil.convertProcessResponseWS(resps).get(0).getResponseData());

        TimeStampResponse timeStampResponse = new TimeStampResponse(resp.getProcessedData());
        timeStampResponse.validate(timeStampRequest1);

        try {
            signServerWS.process("1991817", WSClientUtil.convertProcessRequestWS(reqs));
            fail();
        } catch (InvalidWorkerIdException_Exception e) {
        }


        ValidateRequest req = new ValidateRequest(validCert1, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);

        req1 = new ProcessRequestWS(req);

        reqs = new ArrayList<>();
        reqs.add(req1);

        resps = signServerWS.process("16", WSClientUtil.convertProcessRequestWS(reqs));
        assertEquals(1, resps.size());
        ValidateResponse res = (ValidateResponse) RequestAndResponseManager.parseProcessResponse(WSClientUtil.convertProcessResponseWS(resps).get(0).getResponseData());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.VALID);
        assertNotNull(val.getStatusMessage());
        List<java.security.cert.Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(1)));
    }

    @Test
    public void test03CallFirstNodeWithStatusOKClient() throws Exception {
        FaultCallback callback = new FaultCallback();

        TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest1 = timeStampRequestGenerator.generate(TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        byte[] requestBytes1 = timeStampRequest1.getEncoded();
        GenericSignRequest signRequest1 = new GenericSignRequest(12, requestBytes1);
        ProcessRequestWS req1 = new ProcessRequestWS(signRequest1);
        ArrayList<ProcessRequestWS> reqs = new ArrayList<>();
        reqs.add(req1);

        // Perform a basic test

        SignServerWSClientFactory f = new SignServerWSClientFactory();
        String[] hosts = {"localhost"};
        ISignServerWSClient client = f.generateSignServerWSClient(SignServerWSClientFactory.CLIENTTYPE_CALLFIRSTNODEWITHSTATUSOK, hosts, false, callback);
        List<org.signserver.protocol.ws.ProcessResponseWS> resps = client.process("9", reqs);
        assertNotNull(resps);
        assertEquals(1, resps.size());
        assertFalse(callback.isCallBackCalled());

        // Test with a host that is down
        /*
        String[] hosts2 = {"128.0.0.2"};
        client = f.generateSignServerWSClient(SignServerWSClientFactory.CLIENTTYPE_CALLFIRSTNODEWITHSTATUSOK,hosts2 , false, callback);
        resps = client.process("9", reqs);
        assertTrue(resps == null);
        assertTrue(callback.isCallBackCalled());
         */
        // Test a with one host that is down and one up
        /*
        callback = new FaultCallback();
        String[] hosts3 = {"128.0.0.2","127.0.0.1"};
        client = f.generateSignServerWSClient(SignServerWSClientFactory.CLIENTTYPE_CALLFIRSTNODEWITHSTATUSOK,hosts3 , false, callback);
        resps = client.process("9", reqs);
        assertTrue(resps.size() == 1);
        assertTrue(callback.isCallBackCalled());
         */
        // Test a lot of subsequent calls

        callback = new FaultCallback();
        String[] hosts4 = {"128.0.0.2", "127.0.0.1", "128.0.0.3"};
        client = f.generateSignServerWSClient(SignServerWSClientFactory.CLIENTTYPE_CALLFIRSTNODEWITHSTATUSOK, hosts4, false, callback);
        for (int i = 0; i < 100; i++) {
            Thread.sleep(100);
            resps = client.process("9", reqs);
            assertEquals(1, resps.size());
            assertTrue(callback.isCallBackCalled());
        }

        // Test timeout
        String[] hosts5 = {"128.0.0.1"};
        client = f.generateSignServerWSClient(SignServerWSClientFactory.CLIENTTYPE_CALLFIRSTNODEWITHSTATUSOK, hosts5, false, callback, 8080, 5);
        resps = client.process("9", reqs);
        assertNull(resps);
        assertTrue(callback.isCallBackCalled());
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(9);
        removeWorker(16);
    }

    /**
     * @param statuses   List of worker statuses
     * @param workerName Name to search for
     * @return true if found in list
     */
    private static boolean workerStatusesContains(final List<WorkerStatusWS> statuses, final String workerName) {
        boolean ret = false;
        for (WorkerStatusWS stat : statuses) {
            if (workerName.equals(stat.getWorkerName())) {
                ret = true;
                break;
            }
        }
        return ret;
    }
}
