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
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.data.Request;
import org.signserver.server.LocalComputerTimeSource;
import org.signserver.server.log.LogMap;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.WorkerSessionMock;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.server.IServices;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.common.data.SignatureRequest;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.log.AdminInfo;
import org.signserver.test.utils.mock.MockedRequestContext;
import org.signserver.test.utils.mock.MockedServicesImpl;

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
    private static final int WORKER5 = 8894;
    private static final int WORKER6 = 8895;
    private static final int WORKER7 = 8896;
    private static final int WORKER8 = 8897;
    private static final String NAME = "NAME";
    private static final String AUTHTYPE = "AUTHTYPE";
    private static final String CRYPTOTOKEN_CLASSNAME =
            "org.signserver.server.cryptotokens.KeystoreCryptoToken";

    private static final String KEY_ALIAS = "TS Signer 1";
    
    private GlobalConfigurationSessionLocal globalConfig;
    private WorkerSessionLocal workerSession;
    private WorkerSessionMock processSession;
    private IServices services;

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
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER1);
        timeStampResponse.validate(timeStampRequest);

        final LogMap logMap = LogMap.getInstance(processSession.getLastRequestContext());
        final Object loggable = logMap.get("TSA_TIMESOURCE");
        assertEquals("timesource", LocalComputerTimeSource.class.getSimpleName(),
                     String.valueOf(loggable));
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
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER1);
        timeStampResponse.validate(timeStampRequest);

        LogMap logMap = LogMap.getInstance(processSession.getLastRequestContext());
        final Object responseLoggable =
                logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPRESPONSE_ENCODED);
        assertNotNull("response", responseLoggable);
        
        assertEquals("log line doesn't contain newlines", -1,
                responseLoggable.toString().lastIndexOf('\n'));
        
        final Object requestLoggable =
                logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_ENCODED);
        assertNotNull("request", requestLoggable);
        assertEquals("log line doesn't contain newlines", -1,
                requestLoggable.toString().lastIndexOf('\n'));
    }

    private void setupWorkers() throws Exception {

        final GlobalConfigurationSessionMock globalMock
                = new GlobalConfigurationSessionMock();
        final WorkerSessionMock workerMock = new WorkerSessionMock();
        globalConfig = globalMock;
        workerSession = workerMock;
        processSession = workerMock;
        services = new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, globalMock);

        // WORKER1
        {
            final int workerId = WORKER1;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestTimeStampSigner1");
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
                    new TimeStampSigner());
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER2: some extensions accepted
        {
            final int workerId = WORKER2;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestTimeStampSigner3");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty(TimeStampSigner.DEFAULTTSAPOLICYOID,
                               "1.3.6.1.4.1.22408.1.2.3.45");
            config.setProperty("DEFAULTKEY", KEY_ALIAS);
            config.setProperty("ACCEPTEDEXTENSIONS", "1.2.74;1.2.7.2;1.2.7.8");
            config.setProperty("KEYSTOREPATH",
                getSignServerHome() + File.separator + "res" +
                        File.separator + "test" + File.separator + "dss10" +
                        File.separator + "dss10_tssigner1.p12");
            config.setProperty("KEYSTORETYPE", "PKCS12");
            config.setProperty("KEYSTOREPASSWORD", "foo123");
            config.setProperty("ACCEPTANYPOLICY", "true");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner());
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER3: empty list of extensions
        {
            final int workerId = WORKER3;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestTimeStampSigner2");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty(TimeStampSigner.DEFAULTTSAPOLICYOID,
                              "1.3.6.1.4.1.22408.1.2.3.45");
            config.setProperty("DEFAULTKEY", KEY_ALIAS);
            config.setProperty("ACCEPTEDEXTENSIONS", "");
            config.setProperty("KEYSTOREPATH",
                getSignServerHome() + File.separator + "res" +
                        File.separator + "test" + File.separator + "dss10" +
                        File.separator + "dss10_tssigner1.p12");
            config.setProperty("KEYSTORETYPE", "PKCS12");
            config.setProperty("KEYSTOREPASSWORD", "foo123");
            config.setProperty("ACCEPTANYPOLICY", "true");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner());
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER4: some extensions accepted (spaces between OIDs)
        {
            final int workerId = WORKER4;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestTimeStampSigner3");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty(TimeStampSigner.DEFAULTTSAPOLICYOID,
                               "1.3.6.1.4.1.22408.1.2.3.45");
            config.setProperty("DEFAULTKEY", KEY_ALIAS);
            config.setProperty("ACCEPTEDEXTENSIONS", "1.2.74; 1.2.7.2; 1.2.7.8");
            config.setProperty("KEYSTOREPATH",
                getSignServerHome() + File.separator + "res" +
                        File.separator + "test" + File.separator + "dss10" +
                        File.separator + "dss10_tssigner1.p12");
            config.setProperty("KEYSTORETYPE", "PKCS12");
            config.setProperty("KEYSTOREPASSWORD", "foo123");
            config.setProperty("ACCEPTANYPOLICY", "true");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner());
            workerSession.reloadConfiguration(workerId);
        }
        
        // WORKER5: with one additional extension
        {
            final int workerId = WORKER5;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestTimeStampSigner4");
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
                    new TimeStampSigner() {
                @Override
                protected Extensions getAdditionalExtensions(Request request, RequestContext context) {
                     final Extension ext =
                             new Extension(new ASN1ObjectIdentifier("1.2.7.9"),
                                           false,
                                           new DEROctetString("Value".getBytes()));
                     return new Extensions(ext);
                }
            });
            workerSession.reloadConfiguration(workerId);
        }
        
        // WORKER6: with additional extensions
        {
            final int workerId = WORKER6;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestTimeStampSigner4");
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
                    new TimeStampSigner() {
                @Override
                protected Extensions getAdditionalExtensions(Request request, RequestContext context) {
                     final Extension ext =
                             new Extension(new ASN1ObjectIdentifier("1.2.7.9"),
                                           false,
                                           new DEROctetString("Value".getBytes()));
                     // a critical extension
                     final Extension ext2 =
                             new Extension(new ASN1ObjectIdentifier("1.2.7.10"),
                                           true,
                                           new DEROctetString("Critical".getBytes()));
                     final Extension[] exts = {ext, ext2};
                     return new Extensions(exts);
                }
            });
            workerSession.reloadConfiguration(workerId);
        }
        
        // WORKER7: accepting only a specific request policy
        {
            final int workerId = WORKER7;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestTimeStampSigner7");
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
            config.setProperty("ACCEPTEDPOLICIES",
                               "1.3.6.1.4.1.22408.1.2.3.45");
            
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner());
            workerSession.reloadConfiguration(workerId);
        }
        
        // WORKER8: accepting only a specific set of request policies
        {
            final int workerId = WORKER8;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestTimeStampSigner8");
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
            config.setProperty("ACCEPTEDPOLICIES",
                               "1.3.6.1.4.1.22408.1.2.3.45; 1.3.6.1.4.1.22408.1.2.3.46");
            
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner());
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
        timeStampRequestGenerator.addExtension(new ASN1ObjectIdentifier("1.2.7.9"), false, new DEROctetString("Value".getBytes(StandardCharsets.UTF_8)));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        try (
                CloseableReadableData requestData = createRequestData(requestBytes);
                CloseableWritableData responseData = createResponseData(false);
            ) {
            SignatureRequest signRequest = new SignatureRequest(100, requestData, responseData);
            processSession.process(new AdminInfo("Client user", null, null),
                    new WorkerIdentifier(WORKER2), signRequest, new MockedRequestContext(services));

            final TimeStampResponse timeStampResponse = new TimeStampResponse(responseData.toReadableData().getAsByteArray());
            timeStampResponse.validate(timeStampRequest);
            assertEquals("rejection", PKIStatus.REJECTION, timeStampResponse.getStatus());
            assertEquals("unacceptedExtension", PKIFailureInfo.unacceptedExtension, timeStampResponse.getFailInfo().intValue());
        } finally {
            
        }
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
        timeStampRequestGenerator.addExtension(new ASN1ObjectIdentifier("1.2.7.2"), false, new DEROctetString("Value".getBytes(StandardCharsets.UTF_8)));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER2);
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
        timeStampRequestGenerator.addExtension(new ASN1ObjectIdentifier("1.2.7.2"), false, new DEROctetString("Value".getBytes(StandardCharsets.UTF_8)));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER4);
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
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER3);
        timeStampResponse.validate(timeStampRequest);
        assertEquals("granted", PKIStatus.GRANTED, timeStampResponse.getStatus());
        assertNull("extensions in token", timeStampResponse.getTimeStampToken().getTimeStampInfo().toASN1Structure().getExtensions());
    }
    
    private TimeStampResponse timestamp(TimeStampRequest timeStampRequest, int workerId) throws Exception {
        byte[] requestBytes = timeStampRequest.getEncoded();
        try (
                CloseableReadableData requestData = createRequestData(requestBytes);
                CloseableWritableData responseData = createResponseData(false);
            ) {
            SignatureRequest signRequest = new SignatureRequest(100, requestData, responseData);
        
            processSession.process(new AdminInfo("Client user", null, null), new WorkerIdentifier(workerId), signRequest, new MockedRequestContext(services));

            final TimeStampResponse timeStampResponse = new TimeStampResponse(responseData.toReadableData().getAsInputStream());
            return timeStampResponse;
        }
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
        timeStampRequestGenerator.addExtension(new ASN1ObjectIdentifier("1.2.7.9"), false, new DEROctetString("Value".getBytes(StandardCharsets.UTF_8)));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER3);
        timeStampResponse.validate(timeStampRequest);
        assertEquals("rejection", PKIStatus.REJECTION, timeStampResponse.getStatus());
        assertEquals("unacceptedExtension", PKIFailureInfo.unacceptedExtension, timeStampResponse.getFailInfo().intValue());
    }
    
    /**
     * Test with a custom time stamp signer adding an additional extension.
     * 
     * @throws Exception 
     */
    @Test
    public void testAdditionalExtension() throws Exception {
        LOG.info("testAdditionalExtension");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER5);
        timeStampResponse.validate(timeStampRequest);
    
        TimeStampTokenInfo timeStampInfo = timeStampResponse.getTimeStampToken().getTimeStampInfo();
        TSTInfo tstInfo = timeStampInfo.toASN1Structure();
        
        Extensions extensions = tstInfo.getExtensions();
        Extension extension = extensions.getExtension(new ASN1ObjectIdentifier("1.2.7.9"));
        
        assertEquals("Number of critical extensions", 0,
                     extensions.getCriticalExtensionOIDs().length);
        assertEquals("Number of extensions", 1,
                     extensions.getExtensionOIDs().length);
        assertNotNull("Should contain additional extension", extension);
        assertEquals("Should contain extension value", new DEROctetString("Value".getBytes()),
                extension.getExtnValue());
    }
    
    /**
     * Test with a custom time stamp signer adding two additional extensions.
     * 
     * @throws Exception 
     */
    @Test
    public void testTwoAdditionalExtensions() throws Exception {
        LOG.info("testAdditionalExtension");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER6);
        timeStampResponse.validate(timeStampRequest);
    
        TimeStampTokenInfo timeStampInfo = timeStampResponse.getTimeStampToken().getTimeStampInfo();
        TSTInfo tstInfo = timeStampInfo.toASN1Structure();
        
        Extensions extensions = tstInfo.getExtensions();
        Extension extension1 = extensions.getExtension(new ASN1ObjectIdentifier("1.2.7.9"));
        Extension extension2 = extensions.getExtension(new ASN1ObjectIdentifier("1.2.7.10"));
        assertEquals("Number of critical extensions", 1,
                     extensions.getCriticalExtensionOIDs().length);
        assertEquals("Number of extensions", 2,
                     extensions.getExtensionOIDs().length);
        assertNotNull("Should contain additional extension", extension1);
        assertNotNull("Should contain additional critical extension", extension2);
        assertEquals("Should contain extension value", new DEROctetString("Value".getBytes()),
                extension1.getExtnValue());
        assertEquals("Should contain extension value", new DEROctetString("Critical".getBytes()),
                extension2.getExtnValue());
    }
    
    /**
     * Test that setting an invalid value for INCLUDE_CERTID_ISSUERSERIAL
     * results in an error.
     *
     * @throws Exception 
     */
    @Test
    public void testIncludeCertIDIssuerSerialInvalid() throws Exception {
        LOG.info("testIncludeCertIDIssuerSerialInvalid"); 
        
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("INCLUDE_CERTID_ISSUERSERIAL", "_not_a_boolean_");
      
        final TimeStampSigner signer = new TimeStampSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };
        
        signer.init(WORKER1, config, null, null);
        
        final List<String> fatalErrors = signer.getFatalErrors(null);
        
        assertTrue("should contain configuration error but was " + fatalErrors,
                   fatalErrors.contains("Illegal value for property INCLUDE_CERTID_ISSUERSERIAL"));
    }
     
    /**
     * Test that the default for INCLUDE_CERTID_ISSUERSERIAL is to include
     * when the property is not set.
     * 
     * @throws Exception 
     */
    @Test
    public void testIncludeCertIDIssuerSerialDefaultUnset() throws Exception {
        LOG.info("testIncludeCertIDIssuerSerialDefaultUnset");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        workerSession.removeWorkerProperty(WORKER6, "INCLUDE_CERTID_ISSUERSERIAL");
        workerSession.reloadConfiguration(WORKER6);
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER6);
        timeStampResponse.validate(timeStampRequest);

        assertIncludeCertIDIssuerSerial("default", true, timeStampResponse);
    }

    /**
     * Test that the default for INCLUDE_CERTID_ISSUERSERIAL is to include
     * when an empty property value is specified.
     * 
     * @throws Exception 
     */
    @Test
    public void testIncludeCertIDIssuerSerialDefaultEmpty() throws Exception {
        LOG.info("testIncludeCertIDIssuerSerialDefaultEmpty");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        workerSession.setWorkerProperty(WORKER6, "INCLUDE_CERTID_ISSUERSERIAL", "");
        workerSession.reloadConfiguration(WORKER6);
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER6);
        timeStampResponse.validate(timeStampRequest);

        assertIncludeCertIDIssuerSerial("default", true, timeStampResponse);
    }
    
    /**
     * Test that INCLUDE_CERTID_ISSUERSERIAL=true includes the IssuerSerial.
     * 
     * @throws Exception 
     */
    @Test
    public void testIncludeCertIDIssuerSerialTrue() throws Exception {
        LOG.info("testIncludeCertIDIssuerSerialTrue");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        workerSession.setWorkerProperty(WORKER6, "INCLUDE_CERTID_ISSUERSERIAL", "TRUE");
        workerSession.reloadConfiguration(WORKER6);
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER6);
        timeStampResponse.validate(timeStampRequest);

        assertIncludeCertIDIssuerSerial("explicit true", true, timeStampResponse);
    }
    
    /**
     * Test that INCLUDE_CERTID_ISSUERSERIAL=false includes the IssuerSerial.
     * 
     * @throws Exception 
     */
    @Test
    public void testIncludeCertIDIssuerSerialFalse() throws Exception {
        LOG.info("testIncludeCertIDIssuerSerialFalse");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        workerSession.setWorkerProperty(WORKER6, "INCLUDE_CERTID_ISSUERSERIAL", "FALSE");
        workerSession.reloadConfiguration(WORKER6);
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER6);
        timeStampResponse.validate(timeStampRequest);

        assertIncludeCertIDIssuerSerial("explicit false", false, timeStampResponse);
    }
    
    private void assertIncludeCertIDIssuerSerial(String message, boolean expected, TimeStampResponse timeStampResponse) {
        IssuerSerial issuerSerial;
        
        AttributeTable attribs = timeStampResponse.getTimeStampToken().getSignedAttributes();
        Attribute attrib = attribs.get(PKCSObjectIdentifiers.id_aa_signingCertificate);
        if (attrib == null) {
            attrib = attribs.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
            SigningCertificateV2 signingCertificate = SigningCertificateV2.getInstance(attrib.getAttributeValues()[0]);
            issuerSerial = signingCertificate.getCerts()[0].getIssuerSerial();
        } else {
            SigningCertificate signingCertificate = SigningCertificate.getInstance(attrib.getAttributeValues()[0]);
            issuerSerial = signingCertificate.getCerts()[0].getIssuerSerial();
        }
        
        assertEquals(message, expected, issuerSerial != null);
    }

    /**
     * Test that setting an accepted policy works with that policy in the
     * request.
     * 
     * @throws Exception 
     */
    @Test
    public void testOnlyAcceptedPolicy() throws Exception {
        LOG.info("testOnlyAcceptedPolicy");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.3.6.1.4.1.22408.1.2.3.45"));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER7);
        timeStampResponse.validate(timeStampRequest);
        assertEquals("acceptance", PKIStatus.GRANTED, timeStampResponse.getStatus());
    }
    
    /**
     * Test that a request policy is accepted for a signer accepting a set
     * of request policies.
     *
     * @throws Exception 
     */
    @Test
    public void testOnlyAcceptedPolicyInSet() throws Exception {
        LOG.info("testAnyAcceptedPolicy");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.3.6.1.4.1.22408.1.2.3.45"));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER8);
        timeStampResponse.validate(timeStampRequest);
        assertEquals("acceptance", PKIStatus.GRANTED, timeStampResponse.getStatus());
    }
    
    /**
     * Test that requesting a policy not in the set of accepted policies is
     * rejected.
     *
     * @throws Exception 
     */
    @Test
    public void testNonAcceptedPolicy() throws Exception {
        LOG.info("testAnyAcceptedPolicy");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.3.6.1.4.1.22408.1.2.1.2"));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER7);
        timeStampResponse.validate(timeStampRequest);
        assertEquals("acceptance", PKIStatus.REJECTION, timeStampResponse.getStatus());
    }
    
    /**
     * Test that requesting a policy works with ACCEPTANYPOLICY set to true.
     *
     * @throws Exception 
     */
    @Test
    public void testAnyAcceptedPolicy() throws Exception {
        LOG.info("testAnyAcceptedPolicy");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.3.6.1.4.1.22408.1.2.1.2"));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER1);
        timeStampResponse.validate(timeStampRequest);
        assertEquals("acceptance", PKIStatus.GRANTED, timeStampResponse.getStatus());
    }
    
    /**
     * Test that setting both ACCEPTANYPOLICY and ACCEPTEDPOLICIES results in
     * a configuration error.
     *
     * @throws Exception 
     */
    @Test
    public void testBothAnyAcceptedAndAcceptedPoliciesError() throws Exception {
        LOG.info("testBothAnyAcceptedAndAcceptedPoliciesError"); 
        
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty("ACCEPTANYPOLICY", "true");
        config.setProperty("ACCEPTEDPOLICIES", "1.3.6.1.4.1.22408.1.2.3.45");
        
        final TimeStampSigner signer = new TimeStampSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };
        
        signer.init(WORKER1, config, null, null);
        
        final List<String> fatalErrors = signer.getFatalErrors(null);
        
        assertTrue("should contain configuration error",
                   fatalErrors.contains("Can not set ACCEPTANYPOLICY to true and ACCEPTEDPOLICIES at the same time"));
    }
    
    /**
     * Test that setting both ACCEPTANYPOLICY (with caps, TRUE) and ACCEPTEDPOLICIES results in
     * a configuration error for defining conflicts, but not for the ACCEPTANYPOLICY value.
     *
     * @throws Exception 
     */
    @Test
    public void testBothAnyAcceptedAndAcceptedPoliciesCapsError() throws Exception {
        LOG.info("testBothAnyAcceptedAndAcceptedPoliciesError"); 
        
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty("ACCEPTANYPOLICY", "TRUE");
        config.setProperty("ACCEPTEDPOLICIES", "1.3.6.1.4.1.22408.1.2.3.45");
        
        final TimeStampSigner signer = new TimeStampSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };
        
        signer.init(WORKER1, config, null, null);
        
        final List<String> fatalErrors = signer.getFatalErrors(null);
        
        assertTrue("should contain configuration error",
                   fatalErrors.contains("Can not set ACCEPTANYPOLICY to true and ACCEPTEDPOLICIES at the same time"));
        assertFalse("should not contain error about ACCEPTANYPOLICY",
                    fatalErrors.contains("Illegal value for ACCEPTANYPOLICY: TRUE"));
    }
    
    /**
     * Test that setting ACCEPTANYPOLICY to explicitely false and
     * ACCEPTEDPOLICIES is accepted.
     * 
     * @throws Exception 
     */
    @Test
    public void testAcceptAnyPolicyFalseAndAcceptedPolicies() throws Exception {
        LOG.info("testAcceptAnyPolicyFalseAndAcceptedPolicies"); 
        
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty("ACCEPTANYPOLICY", "false");
        config.setProperty("ACCEPTEDPOLICIES", "1.3.6.1.4.1.22408.1.2.3.45");
        
        final TimeStampSigner signer = new TimeStampSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };
        
        signer.init(WORKER1, config, null, null);
        
        final List<String> fatalErrors = signer.getFatalErrors(null);
        
        assertFalse("should not contain error",
                fatalErrors.contains("Can not set ACCEPTANYPOLICY to true and ACCEPTEDPOLICIES at the same time"));
        assertFalse("should not contain error",
                fatalErrors.contains("Must specify either ACCEPTEDPOLICIES or ACCEPTANYPOLICY true"));
        assertFalse("should not contain error",
                fatalErrors.contains("Illegal value for ACCEPTANYPOLICY: false"));
    }
    
    /**
     * Test that setting ACCEPTANYPOLICY to an empty value and
     * ACCEPTEDPOLICIES is accepted.
     * 
     * @throws Exception 
     */
    @Test
    public void testAcceptAnyPolicyEmptyAndAcceptedPolicies() throws Exception {
        LOG.info("testAcceptAnyPolicyEmptyAndAcceptedPolicies"); 
        
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty("ACCEPTANYPOLICY", "");
        config.setProperty("ACCEPTEDPOLICIES", "1.3.6.1.4.1.22408.1.2.3.45");
        
        final TimeStampSigner signer = new TimeStampSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };
        
        signer.init(WORKER1, config, null, null);
        
        final List<String> fatalErrors = signer.getFatalErrors(null);
        
        assertFalse("should not contain error",
                fatalErrors.contains("Can not set ACCEPTANYPOLICY to true and ACCEPTEDPOLICIES at the same time"));
        assertFalse("should not contain error",
                fatalErrors.contains("Must specify either ACCEPTEDPOLICIES or ACCEPTANYPOLICY true"));
    }
    
    /**
     * Test that not setting any of ACCEPTANYPOLICY or ACCEPTEDPOLICIES results in
     * a configuration error.
     *
     * @throws Exception 
     */
    @Test
    public void testNoneOfAnyAcceptedOrAcceptedPoliciesError() throws Exception {
        LOG.info("testBothAnyAcceptedAndAcceptedPoliciesError"); 
        
        final WorkerConfig config = new WorkerConfig();
      
        final TimeStampSigner signer = new TimeStampSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };
        
        signer.init(WORKER1, config, null, null);
        
        final List<String> fatalErrors = signer.getFatalErrors(null);
        
        assertTrue("should contain configuration error",
                   fatalErrors.contains("Must specify either ACCEPTEDPOLICIES or ACCEPTANYPOLICY true"));
    }
    
    /**
     * Test that not setting an invalid value for ACCEPTANYPOLICY results in
     * an error.
     *
     * @throws Exception 
     */
    @Test
    public void testAcceptAnyPolicyInvalid() throws Exception {
        LOG.info("testBothAnyAcceptedAndAcceptedPoliciesError"); 
        
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty("ACCEPTANYPOLICY", "foo");
      
        final TimeStampSigner signer = new TimeStampSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };
        
        signer.init(WORKER1, config, null, null);
        
        final List<String> fatalErrors = signer.getFatalErrors(null);
        
        assertTrue("should contain configuration error",
                   fatalErrors.contains("Illegal value for ACCEPTANYPOLICY: foo"));
    }
    
    /**
     * Test that setting ACCEPTANYPOLICY to false without setting ACCEPTEDPOLICIES
     * is not allowed.
     *
     * @throws Exception 
     */
    @Test
    public void testAcceptAnyPolicyFalseAndNoAcceptedPolicies() throws Exception {
        LOG.info("testAcceptAnyPolicyFalseAndNoAcceptedPolicies"); 
        
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty("ACCEPTANYPOLICY", "false");
      
        final TimeStampSigner signer = new TimeStampSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };
        
        signer.init(WORKER1, config, null, null);
        
        final List<String> fatalErrors = signer.getFatalErrors(null);
        
        assertTrue("should contain configuration error",
                   fatalErrors.contains("Must specify either ACCEPTEDPOLICIES or ACCEPTANYPOLICY true"));
    }
    
    /**
     * Test that setting ACCEPTANYPOLICY to FALSE (with caps) without setting ACCEPTEDPOLICIES
     * is not allowed.
     *
     * @throws Exception 
     */
    @Test
    public void testAcceptAnyPolicyFalseCapitalAndNoAcceptedPolicies() throws Exception {
        LOG.info("testAcceptAnyPolicyFalseAndNoAcceptedPolicies"); 
        
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty("ACCEPTANYPOLICY", "FALSE");
      
        final TimeStampSigner signer = new TimeStampSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };
        
        signer.init(WORKER1, config, null, null);
        
        final List<String> fatalErrors = signer.getFatalErrors(null);
        
        assertTrue("should contain configuration error",
                   fatalErrors.contains("Must specify either ACCEPTEDPOLICIES or ACCEPTANYPOLICY true"));
        assertFalse("should not contain error about ACCEPTANYPOLICY",
                    fatalErrors.contains("Illegal value for ACCEPTANYPOLICY: FALSE"));
    }
    
    /**
     * Test that setting ACCEPTANYPOLICY empty without setting ACCEPTEDPOLICIES
     * is not allowed.
     *
     * @throws Exception 
     */
    @Test
    public void testAcceptAnyPolicyEmptyAndNoAcceptedPolicies() throws Exception {
        LOG.info("testAcceptAnyPolicyEmptyAndNoAcceptedPolicies"); 
        
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty("ACCEPTANYPOLICY", "");
      
        final TimeStampSigner signer = new TimeStampSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };
        
        signer.init(WORKER1, config, null, null);
        
        final List<String> fatalErrors = signer.getFatalErrors(null);
        
        assertTrue("should contain configuration error",
                   fatalErrors.contains("Must specify either ACCEPTEDPOLICIES or ACCEPTANYPOLICY true"));
    }
    
    /**
     * Test that setting ACCEPTEDPOLICIES to an empty list is accepted without
     * setting ACCEPTANYPOLICY.
     *
     * @throws Exception 
     */
    @Test
    public void testAcceptedPoliciesEmpty() throws Exception {
        LOG.info("testAcceptedPoliciesEmpty"); 
        
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty("ACCEPTEDPOLICIES", "");
      
        final TimeStampSigner signer = new TimeStampSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };
        
        signer.init(WORKER1, config, null, null);
        
        final List<String> fatalErrors = signer.getFatalErrors(null);
        
        assertFalse("should not contain error",
                fatalErrors.contains("Must specify either ACCEPTEDPOLICIES or ACCEPTANYPOLICY true"));
    }
}

