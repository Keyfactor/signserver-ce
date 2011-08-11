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
package org.signserver.module.tsa;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Random;
import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.ejbca.util.Base64;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerUtil;
import org.signserver.common.SignerStatus;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IStatusRepositorySession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Tests for the TimeStampSigner.
 *
 * @version $Id$
 */
public class TimeStampSignerTest extends TestCase {

    /** Logger for class. */
    private static final Logger LOG = Logger.getLogger(
            TimeStampSignerTest.class);

    private static IWorkerSession.IRemote sSSession = null;

    /** The status repository session. */
    private static IStatusRepositorySession.IRemote repository;

    /** Worker ID for test worker. */
    private static final int WORKER1 = 8901;

    /** Worker ID for test worker. */
    private static final int WORKER2 = 8902;

    /** Worker ID for test worker. */
    private static final int WORKER3 = 8903;

        /** Worker ID for test worker. */
    private static final int WORKER4 = 8904;

    /**
     * Base64 encoded request with policy 1.2.3.5.
     * <pre>
     * Version: 1
     *  Hash Algorithm: sha1
     *  Message data:
     *      0000 - 32 a0 61 7a ab 4c 9f e7-25 f1 b5 bc 44 12 91 18
     *      0010 - 0a d2 5b 73
     *  Policy OID: 1.2.3.5
     *  Nonce: unspecified
     *  Certificate required: no
     *  Extensions:
     *  </pre>
     */
    private static final String REQUEST_WITH_POLICY1235 =
            "MCsCAQEwITAJBgUrDgMCGgUABBQyoGF6q0yf5yXxtbxEEpEYCtJbcwYDKgMF";

    private static String signserverhome;
    private static int moduleVersion;

    private Random random = new Random(4711);


    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
        
        sSSession = ServiceLocator.getInstance().lookupRemote(
                IWorkerSession.IRemote.class);

        repository = ServiceLocator.getInstance().lookupRemote(
                IStatusRepositorySession.IRemote.class);

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

        MARFileParser marFileParser = new MARFileParser(signserverhome
                + "/dist-server/tsa.mar");
        moduleVersion = marFileParser.getVersionFromMARFile();

        TestUtils.assertSuccessfulExecution(new String[]{"module", "add",
                    signserverhome + "/dist-server/tsa.mar", "junittest"});
        assertTrue(TestUtils.grepTempOut("Loading module TSA"));
        assertTrue(TestUtils.grepTempOut("Module loaded successfully."));

        sSSession.reloadConfiguration(WORKER1);
        sSSession.reloadConfiguration(WORKER2);
        sSSession.reloadConfiguration(WORKER3);
        sSSession.reloadConfiguration(WORKER4);
    }

    public void test01BasicTimeStamp() throws Exception {
        assertSuccessfulTimestamp(WORKER1);
    }

    private void assertSuccessfulTimestamp(int worker) throws Exception {
        int reqid = random.nextInt();

        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();

        GenericSignRequest signRequest =
                new GenericSignRequest(reqid, requestBytes);


        final GenericSignResponse res = (GenericSignResponse) sSSession.process(
                worker, signRequest, new RequestContext());

        assertTrue(reqid == res.getRequestID());

        Certificate signercert = res.getSignerCertificate();

        assertNotNull(signercert);

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
                (byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);

        assertEquals("Token granted", PKIStatus.GRANTED,
                timeStampResponse.getStatus());
        assertNotNull("Got timestamp token",
                timeStampResponse.getTimeStampToken());
    }

    /*
     * Test method for 'org.signserver.server.MRTDSigner.getStatus()'.
     */
    public void test02GetStatus() throws Exception {

        SignerStatus stat = (SignerStatus) sSSession.getStatus(8901);
        assertTrue(stat.getTokenStatus() == SignerStatus.STATUS_ACTIVE);
    }

    /**
     * Test that a timestamp token is not granted for an policy not listed in
     * ACCEPTEDPOLICIES and that a proper resoonse is sent back.
     * @throws Exception in case of exception
     */
    public void test03NotAcceptedPolicy() throws Exception {
        // WORKER2 has ACCEPTEDPOLICIES=1.2.3
        // Create an request with another policy (1.2.3.5 != 1.2.3)
        final TimeStampRequest timeStampRequest = new TimeStampRequest(
                Base64.decode(REQUEST_WITH_POLICY1235.getBytes()));
        
        final byte[] requestBytes = timeStampRequest.getEncoded();

        final GenericSignRequest signRequest = new GenericSignRequest(13,
                requestBytes);

        final GenericSignResponse res = (GenericSignResponse) sSSession.process(
                WORKER2, signRequest, new RequestContext());

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
            (byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);

        LOG.info("Response: " + timeStampResponse.getStatusString());

        assertEquals("Token rejected", PKIStatus.REJECTION,
                timeStampResponse.getStatus());
    }

    /**
     * Tests that the timestamp signer returnes a time stamp response with
     * the timeNotAvailable status if the Date is null.
     * @throws Exception in case of exception
     */
    public void test04timeNotAvailable() throws Exception {
        assertTimeNotAvailable(WORKER3);
    }

    /**
     * Tests that the timestamp is only granted when the INSYNC property
     * is set.
     * @throws Exception in case of exception
     */
    public void test05ReadingStatusTimeSource() throws Exception {
        
        // Test with insync
        repository.setProperty("INSYNC", "true");
        assertSuccessfulTimestamp(WORKER4);

        // Test without insync
        repository.removeProperty("INSYNC");
        assertTimeNotAvailable(WORKER4);
    }

    private void assertTimeNotAvailable(int worker) throws Exception {
        final int reqid = random.nextInt();

        final TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        final TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(114));
        final byte[] requestBytes = timeStampRequest.getEncoded();

        final GenericSignRequest signRequest =
                new GenericSignRequest(reqid, requestBytes);


        final GenericSignResponse res = (GenericSignResponse) sSSession.process(
                worker, signRequest, new RequestContext());

        assertTrue(reqid == res.getRequestID());

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
                (byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);

        LOG.info("Response: " + timeStampResponse.getStatusString());

        assertEquals("Token not granted", PKIStatus.REJECTION,
                timeStampResponse.getStatus());

        assertEquals("PKIFailureInfo.timeNotAvailable",
                new PKIFailureInfo(PKIFailureInfo.timeNotAvailable),
                timeStampResponse.getFailInfo());

        assertNull("No timestamp token",
                timeStampResponse.getTimeStampToken());
    }

    public void test99TearDownDatabase() throws Exception {
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker",
                    String.valueOf(WORKER1)});
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker",
                    String.valueOf(WORKER2)});
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker",
                    String.valueOf(WORKER3)});

        TestUtils.assertSuccessfulExecution(new String[]{"module", "remove",
            "TSA", String.valueOf(moduleVersion)});
        assertTrue("module remove", TestUtils.grepTempOut(
                "Removal of module successful."));
        sSSession.reloadConfiguration(WORKER1);
        sSSession.reloadConfiguration(WORKER2);
        sSSession.reloadConfiguration(WORKER3);
        sSSession.reloadConfiguration(WORKER4);
    }

}
