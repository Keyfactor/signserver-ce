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

import java.io.File;
import java.math.BigInteger;
import java.security.Security;
import java.util.Arrays;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.server.LocalComputerTimeSource;
import org.signserver.server.log.LogMap;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.WorkerSessionMock;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionRemote;

/**
 * Unit tests for the TimeStampSigner.
 *
 * System tests can be put in the Test-System project instead.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TimeStampSignerUnitTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TimeStampSignerUnitTest.class);

    private static final int WORKER1 = 8890;
    private static final int WORKER2 = 8891;
    private static final int WORKER3 = 8892;
    private static final int WORKER4 = 8893;
    private static final String NAME = "NAME";
    private static final String AUTHTYPE = "AUTHTYPE";
    private static final String CRYPTOTOKEN_CLASSNAME =
            "org.signserver.server.cryptotokens.KeystoreCryptoToken";

    private static final String KEY_ALIAS = "TS Signer 1";
    
    private GlobalConfigurationSessionRemote globalConfig;
    private WorkerSessionRemote workerSession;
    private WorkerSessionMock processSession;

    @Before
    @Override
    public void setUp() throws Exception {
        setupWorkers();
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Tests that the log contains the TSA_TIMESOURCE entry.
     * @throws Exception
     */
    @Test
    public void testLogTimeSource() throws Exception {
        LOG.info("testLogTimeSource");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest = new GenericSignRequest(100, requestBytes);
        final GenericSignResponse res = (GenericSignResponse) processSession.process(
                new WorkerIdentifier(WORKER1), signRequest, new RemoteRequestContext());

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
                (byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);

        LogMap logMap = LogMap.getInstance(processSession.getLastRequestContext());
        assertEquals("timesource", LocalComputerTimeSource.class.getSimpleName(), logMap.get("TSA_TIMESOURCE"));
    }
    
    /**
     * Test that the base 64-encoded log entries for request and response
     * are not encoded with newlines, as this causes an extra base 64 encoding
     * with a B64: prefix by Base64PutHashMap.
     * 
     * @throws Exception 
     */
    @Test
    public void testLogBase64Entries() throws Exception {
        LOG.info("testLogBase64Entries");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[2000], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest = new GenericSignRequest(100, requestBytes);
        final GenericSignResponse res = (GenericSignResponse) processSession.process(
                new WorkerIdentifier(WORKER1), signRequest, new RemoteRequestContext());

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
                (byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);

        LogMap logMap = LogMap.getInstance(processSession.getLastRequestContext());
        assertNotNull("response",
                logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPRESPONSE_ENCODED));
        assertEquals("log line doesn't contain newlines", -1,
                logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPRESPONSE_ENCODED).lastIndexOf('\n'));
        assertNotNull("request",
                logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_ENCODED));
        assertEquals("log line doesn't contain newlines", -1,
                logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_ENCODED).lastIndexOf('\n'));
    }

    private void setupWorkers() throws Exception {

        final GlobalConfigurationSessionMock globalMock
                = new GlobalConfigurationSessionMock();
        final WorkerSessionMock workerMock = new WorkerSessionMock();
        globalConfig = globalMock;
        workerSession = workerMock;
        processSession = workerMock;

        // WORKER1
        {
            final int workerId = WORKER1;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestTimeStampSigner1");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty(TimeStampSigner.DEFAULTTSAPOLICYOID, "1.2.3.4");
            config.setProperty("DEFAULTKEY", KEY_ALIAS);
            config.setProperty("KEYSTOREPATH",
                getSignServerHome() + File.separator + "res" +
                        File.separator + "test" + File.separator + "dss10" +
                        File.separator + "dss10_tssigner1.p12");
            config.setProperty("KEYSTORETYPE", "PKCS12");
            config.setProperty("KEYSTOREPASSWORD", "foo123");

            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner() {
                @Override
                protected GlobalConfigurationSessionRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER2: some extensions accepted
        {
            final int workerId = WORKER2;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestTimeStampSigner3");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty(TimeStampSigner.DEFAULTTSAPOLICYOID, "1.2.3.4");
            config.setProperty("DEFAULTKEY", KEY_ALIAS);
            config.setProperty("ACCEPTEDEXTENSIONS", "1.2.74;1.2.7.2;1.2.7.8");
            config.setProperty("KEYSTOREPATH",
                getSignServerHome() + File.separator + "res" +
                        File.separator + "test" + File.separator + "dss10" +
                        File.separator + "dss10_tssigner1.p12");
            config.setProperty("KEYSTORETYPE", "PKCS12");
            config.setProperty("KEYSTOREPASSWORD", "foo123");
            
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner() {
                @Override
                protected GlobalConfigurationSessionRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER3: empty list of extensions
        {
            final int workerId = WORKER3;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestTimeStampSigner2");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty(TimeStampSigner.DEFAULTTSAPOLICYOID, "1.2.3.4");
            config.setProperty("DEFAULTKEY", KEY_ALIAS);
            config.setProperty("ACCEPTEDEXTENSIONS", "");
            config.setProperty("KEYSTOREPATH",
                getSignServerHome() + File.separator + "res" +
                        File.separator + "test" + File.separator + "dss10" +
                        File.separator + "dss10_tssigner1.p12");
            config.setProperty("KEYSTORETYPE", "PKCS12");
            config.setProperty("KEYSTOREPASSWORD", "foo123");
            
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner() {
                @Override
                protected GlobalConfigurationSessionRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER4: some extensions accepted (spaces between OIDs)
        {
            final int workerId = WORKER4;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestTimeStampSigner3");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty(TimeStampSigner.DEFAULTTSAPOLICYOID, "1.2.3.4");
            config.setProperty("DEFAULTKEY", KEY_ALIAS);
            config.setProperty("ACCEPTEDEXTENSIONS", "1.2.74; 1.2.7.2; 1.2.7.8");
            config.setProperty("KEYSTOREPATH",
                getSignServerHome() + File.separator + "res" +
                        File.separator + "test" + File.separator + "dss10" +
                        File.separator + "dss10_tssigner1.p12");
            config.setProperty("KEYSTORETYPE", "PKCS12");
            config.setProperty("KEYSTOREPASSWORD", "foo123");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner() {
                @Override
                protected GlobalConfigurationSessionRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }
    }

    /**
     * Tests that a request including an extension not listed will cause a
     * rejection.
     * @throws Exception
     */
    @Test
    public void testNotAcceptedExtensionPrevented() throws Exception {
        LOG.info("testNotAcceptedExtensionPrevented");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.addExtension(new ASN1ObjectIdentifier("1.2.7.9"), false, new DEROctetString("Value".getBytes("UTF-8")));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest = new GenericSignRequest(100, requestBytes);
        final GenericSignResponse res = (GenericSignResponse) processSession.process(
                new WorkerIdentifier(WORKER2), signRequest, new RemoteRequestContext());

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
                (byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);
        assertEquals("rejection", PKIStatus.REJECTION, timeStampResponse.getStatus());
        assertEquals("unacceptedExtension", PKIFailureInfo.unacceptedExtension, timeStampResponse.getFailInfo().intValue());
    }

    /**
     * Tests that a request including an extension listed will accept
     * the extension.
     * @throws Exception
     */
    @Test
    public void testAcceptedExtensions() throws Exception {
        LOG.info("testAcceptedExtensions");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.addExtension(new ASN1ObjectIdentifier("1.2.7.2"), false, new DEROctetString("Value".getBytes("UTF-8")));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest = new GenericSignRequest(100, requestBytes);
        final GenericSignResponse res = (GenericSignResponse) processSession.process(
                new WorkerIdentifier(WORKER2), signRequest, new RemoteRequestContext());

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
                (byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);
        assertEquals("granted", PKIStatus.GRANTED, timeStampResponse.getStatus());
        assertEquals("extensions in token",
                Arrays.toString(new ASN1ObjectIdentifier[] { new ASN1ObjectIdentifier("1.2.7.2") }),
                Arrays.toString(timeStampResponse.getTimeStampToken().getTimeStampInfo().toASN1Structure().getExtensions().getExtensionOIDs()));
    }

    /**
     * Tests that a request including an extension listed will accept
     * the extension also when ACCEPTEDEXTENSIONS contains spaces.
     * @throws Exception
     */
    @Test
    public void testAcceptedExtensionsWithSpaces() throws Exception {
        LOG.info("testAcceptedExtensionsWithSpaces");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.addExtension(new ASN1ObjectIdentifier("1.2.7.2"), false, new DEROctetString("Value".getBytes("UTF-8")));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest = new GenericSignRequest(100, requestBytes);
        final GenericSignResponse res = (GenericSignResponse) processSession.process(
                new WorkerIdentifier(WORKER4), signRequest, new RemoteRequestContext());

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
                (byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);
        assertEquals("granted", PKIStatus.GRANTED, timeStampResponse.getStatus());
        assertEquals("extensions in token",
                Arrays.toString(new ASN1ObjectIdentifier[] { new ASN1ObjectIdentifier("1.2.7.2") }),
                Arrays.toString(timeStampResponse.getTimeStampToken().getTimeStampInfo().toASN1Structure().getExtensions().getExtensionOIDs()));
    }

    /**
     * Tests that a request without extension is accepted also when the list of
     * extensions is empty.
     * @throws Exception
     */
    @Test
    public void testEmptyAcceptedExtensionsOk() throws Exception {
        LOG.info("testEmptyAcceptedExtensions");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest = new GenericSignRequest(100, requestBytes);
        final GenericSignResponse res = (GenericSignResponse) processSession.process(
                new WorkerIdentifier(WORKER3), signRequest, new RemoteRequestContext());

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
                (byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);
        assertEquals("granted", PKIStatus.GRANTED, timeStampResponse.getStatus());
        assertNull("extensions in token", timeStampResponse.getTimeStampToken().getTimeStampInfo().toASN1Structure().getExtensions());
    }

    /**
     * Tests that a request including an extension not listed will cause a
     * rejection also when the list of extensions is empty.
     * @throws Exception
     */
    @Test
    public void testEmptyAcceptedExtensionsPreventsExtension() throws Exception {
        LOG.info("testEmptyAcceptedExtensionsPreventsExtension");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.addExtension(new ASN1ObjectIdentifier("1.2.7.9"), false, new DEROctetString("Value".getBytes("UTF-8")));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest = new GenericSignRequest(100, requestBytes);
        final GenericSignResponse res = (GenericSignResponse) processSession.process(
                new WorkerIdentifier(WORKER3), signRequest, new RemoteRequestContext());

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
                (byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);
        assertEquals("rejection", PKIStatus.REJECTION, timeStampResponse.getStatus());
        assertEquals("unacceptedExtension", PKIFailureInfo.unacceptedExtension, timeStampResponse.getFailInfo().intValue());
    }
}

