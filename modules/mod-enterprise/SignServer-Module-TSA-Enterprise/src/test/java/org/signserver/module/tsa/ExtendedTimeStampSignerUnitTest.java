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
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import static org.signserver.common.util.PropertiesConstants.NAME;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.common.data.SignatureRequest;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.log.AdminInfo;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.MockedRequestContext;
import org.signserver.test.utils.mock.MockedServicesImpl;
import org.signserver.test.utils.mock.WorkerSessionMock;
import org.signserver.testutils.ModulesTestCase;

/**
 * Unit tests for the extended time stamp signer.
 * Tests the default behaviour and explicitly including a QC statemtent
 * extension.
 * 
 * @author Marcus Lundblad
 * @version $Id: ExtendedTimeStampSignerUnitTest.java 7216 2016-04-19 07:31:44Z malu9369 $
 */
public class ExtendedTimeStampSignerUnitTest extends ModulesTestCase {
    
    private final static int WORKER1 = 8895;
    private WorkerSessionMock workerSession;
    
    private final static String AUTHTYPE = "AUTHTYPE";
    private final static String CRYPTOTOKEN_CLASSNAME =
            "org.signserver.server.cryptotokens.KeystoreCryptoToken";
    private MockedServicesImpl services;
    private GlobalConfigurationSessionMock globalConfig;
    
    private static final String KEY_ALIAS = "TS Signer 1";
    
    @Before
    @Override
    public void setUp() throws Exception {
        setupWorkers();
        Security.addProvider(new BouncyCastleProvider());
    }
    
    /**
     * Test that the default behaviour is to not include any additional
     * extensions.
     * 
     * @throws Exception 
     */
    @Test
    public void testDefaultNoExtension() throws Exception {
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(requestBytes);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            SignatureRequest signRequest = new SignatureRequest(100, requestData, responseData);
            final RequestContext requestContext = new MockedRequestContext(services);
            workerSession.process(new AdminInfo("Client user", null, null),
                    new WorkerIdentifier(WORKER1), signRequest, requestContext);

            final TimeStampResponse timeStampResponse = new TimeStampResponse(responseData.toReadableData().getAsByteArray());
            timeStampResponse.validate(timeStampRequest);

            TimeStampTokenInfo timeStampInfo = timeStampResponse.getTimeStampToken().getTimeStampInfo();
            TSTInfo tstInfo = timeStampInfo.toASN1Structure();

            Extensions extensions = tstInfo.getExtensions();

            assertNull("No extensions", extensions);
        }
    }
    
    /**
     * Test that when setting the worker property to an empty value,
     * no additional extension is included.
     * 
     * @throws Exception 
     */
    @Test
    public void testEmptyPropertyNoExtension() throws Exception {
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(requestBytes);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            workerSession.setWorkerProperty(WORKER1,
                                            ExtendedTimeStampSigner.INCLUDE_QC_EXTENSION,
                                            "");
            workerSession.reloadConfiguration(WORKER1);

            
            SignatureRequest signRequest = new SignatureRequest(100, requestData, responseData);
            final RequestContext requestContext = new MockedRequestContext(services);
            workerSession.process(new AdminInfo("Client user", null, null),
                    new WorkerIdentifier(WORKER1), signRequest, requestContext);

            final TimeStampResponse timeStampResponse = new TimeStampResponse(
                    responseData.toReadableData().getAsByteArray());
            timeStampResponse.validate(timeStampRequest);

            TimeStampTokenInfo timeStampInfo = timeStampResponse.getTimeStampToken().getTimeStampInfo();
            TSTInfo tstInfo = timeStampInfo.toASN1Structure();

            Extensions extensions = tstInfo.getExtensions();

            assertNull("No extensions", extensions);
        } finally {
            workerSession.removeWorkerProperty(WORKER1,
                                               ExtendedTimeStampSigner.INCLUDE_QC_EXTENSION);
            workerSession.reloadConfiguration(WORKER1);
        }
    }

    /**
     * Test that explicitly setting INCLUDE_QC_EXTENSION to "false" gives
     * no additional extensions.
     * 
     * @throws Exception 
     */
    @Test
    public void testExplicitlyNoQualifiedExtension() throws Exception {
        TimeStampRequestGenerator timeStampRequestGenerator =
            new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(requestBytes);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            workerSession.setWorkerProperty(WORKER1,
                                            ExtendedTimeStampSigner.INCLUDE_QC_EXTENSION,
                                            "false");
            workerSession.reloadConfiguration(WORKER1);
            SignatureRequest signRequest = new SignatureRequest(100, requestData, responseData);
            final RequestContext requestContext = new MockedRequestContext(services);
            workerSession.process(new AdminInfo("Client user", null, null),
                    new WorkerIdentifier(WORKER1), signRequest, requestContext);

            final TimeStampResponse timeStampResponse = new TimeStampResponse(
                    responseData.toReadableData().getAsByteArray());
            timeStampResponse.validate(timeStampRequest);

            TimeStampTokenInfo timeStampInfo = timeStampResponse.getTimeStampToken().getTimeStampInfo();
            TSTInfo tstInfo = timeStampInfo.toASN1Structure();

            Extensions extensions = tstInfo.getExtensions();

            assertNull("No extensions", extensions);
        } finally {
            workerSession.removeWorkerProperty(WORKER1,
                                               ExtendedTimeStampSigner.INCLUDE_QC_EXTENSION);
            workerSession.reloadConfiguration(WORKER1);
        }
    }
    
    /**
     * Test that the extension is included when explicitly configured to be
     * included.
     *
     * @throws Exception 
     */
    @Test
    public void testQCExtensionEnabled() throws Exception {
        TimeStampRequestGenerator timeStampRequestGenerator =
            new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(requestBytes);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            workerSession.setWorkerProperty(WORKER1,
                                            ExtendedTimeStampSigner.INCLUDE_QC_EXTENSION,
                                            "true");
            workerSession.reloadConfiguration(WORKER1);
            SignatureRequest signRequest = new SignatureRequest(100, requestData, responseData);
            final RequestContext requestContext = new MockedRequestContext(services);
            workerSession.process(new AdminInfo("Client user", null, null),
                    new WorkerIdentifier(WORKER1), signRequest, requestContext);

            final TimeStampResponse timeStampResponse = new TimeStampResponse(
                    responseData.toReadableData().getAsByteArray());
            timeStampResponse.validate(timeStampRequest);

            TimeStampTokenInfo timeStampInfo = timeStampResponse.getTimeStampToken().getTimeStampInfo();
            TSTInfo tstInfo = timeStampInfo.toASN1Structure();

            Extensions extensions = tstInfo.getExtensions();

            assertEquals("Number of critical extensions", 0, extensions.getCriticalExtensionOIDs().length);
            assertEquals("Number of non-critical extensions", 1, extensions.getExtensionOIDs().length);
            
            final Extension extension = extensions.getExtension(Extension.qCStatements);
            
            assertNotNull("QC extension present", extension);
            
            final ASN1OctetString value = extension.getExtnValue();
            final ASN1Sequence seq =
                    ASN1Sequence.getInstance(value.getOctets());            
            assertNotNull("Extension contains sequence", seq);
            assertEquals("Number of objects in the sequence", 1, seq.size());
            
            final ASN1Sequence seq2 = ASN1Sequence.getInstance(seq.getObjectAt(0));
            
            assertEquals("Contains ETSI OID",
                         ExtendedTimeStampSigner.ID_ETSI_TSTS,
                         seq2.getObjectAt(0));
        } finally {
            workerSession.removeWorkerProperty(WORKER1,
                                               ExtendedTimeStampSigner.INCLUDE_QC_EXTENSION);
            workerSession.reloadConfiguration(WORKER1);
        }
    }
    
    private void setupWorkers() throws Exception {
        final GlobalConfigurationSessionMock globalMock
                = new GlobalConfigurationSessionMock();
        final WorkerSessionMock workerMock = new WorkerSessionMock();
        globalConfig = globalMock;
        workerSession = workerMock;
        
        globalConfig = globalMock;
        workerSession = workerMock;
        
        services = new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, globalMock);
        
        // WORKER1
        {
            final int workerId = WORKER1;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "ExtendedTestTimeStampSigner1");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty(TimeStampSigner.DEFAULTTSAPOLICYOID,
                               "1.3.6.1.4.1.22408.1.2.3.45");
            config.setProperty("DEFAULTKEY", KEY_ALIAS);
            config.setProperty("KEYSTOREPATH",
                getSignServerHome() + File.separator + "res" +
                        File.separator + "test" + File.separator + "dss10" +
                        File.separator + "dss10_tssigner1.p12");
            config.setProperty("KEYSTORETYPE", "PKCS12");
            config.setProperty("KEYSTOREPASSWORD", "foo123");
            config.setProperty("ACCEPTANYPOLICY", "true");

            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new ExtendedTimeStampSigner());
            workerSession.reloadConfiguration(workerId);
        }
    }
}
