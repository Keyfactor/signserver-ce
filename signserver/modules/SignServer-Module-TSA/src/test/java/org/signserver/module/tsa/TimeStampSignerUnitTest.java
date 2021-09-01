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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.tsp.TimeStampReq;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.data.Request;
import org.signserver.common.data.SignatureRequest;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.module.tsa.conf.TSAWorkerConfigBuilder;
import org.signserver.server.IServices;
import org.signserver.server.LocalComputerTimeSource;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.log.LogMap;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.MockedRequestContext;
import org.signserver.test.utils.mock.MockedServicesImpl;
import org.signserver.test.utils.mock.WorkerSessionMock;
import org.signserver.testutils.ModulesTestCase;

import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for the TimeStampSigner.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TimeStampSignerUnitTest extends ModulesTestCase {

    private static final Logger LOG = Logger.getLogger(TimeStampSignerUnitTest.class);

    private static final int WORKER1 = 8890;
    private static final int WORKER2 = 8891;
    private static final int WORKER3 = 8892;
    private static final int WORKER4 = 8893;
    private static final int WORKER5 = 8894;
    private static final int WORKER6 = 8895;
    private static final int WORKER7 = 8896;
    private static final int WORKER8 = 8897;

    private static final String CRYPTOTOKEN_CLASSNAME =
            "org.signserver.server.cryptotokens.KeystoreCryptoToken";

    // OID description: we sign anything that arrives
    private static final String DEFAULT_TSA_POLICY_OID = "1.3.6.1.4.1.22408.1.2.3.45";

    private WorkerSessionLocal workerSession;
    private WorkerSessionMock processSession;
    private IServices services;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @BeforeClass
    public static void beforeClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Before
    public void setUp() throws Exception {
        setupWorkers();
    }

    private void setupWorkers() throws Exception {
        final WorkerSessionMock workerMock = new WorkerSessionMock();
        workerSession = workerMock;
        processSession = workerMock;
        services = new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, new GlobalConfigurationSessionMock());

        // WORKER1
        {
            final WorkerConfig config = TSAWorkerConfigBuilder.builder()
                    .withWorkerId(WORKER1)
                    .withWorkerName("TestTimeStampSigner1")
                    .withNoAuthAuthType()
                    .withDefaultTsaPolicyOid(DEFAULT_TSA_POLICY_OID)
                    .withDss10p12Keystore()
                    .withAcceptAnyPolicy(true)
                    .build();

            workerMock.setupWorker(WORKER1, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner());
            workerSession.reloadConfiguration(WORKER1);
        }

        // WORKER2: some extensions accepted
        {
            final WorkerConfig config = TSAWorkerConfigBuilder.builder()
                    .withWorkerId(WORKER2)
                    .withWorkerName("TestTimeStampSigner2")
                    .withNoAuthAuthType()
                    .withDefaultTsaPolicyOid(DEFAULT_TSA_POLICY_OID)
                    .withAcceptedExtensions("1.2.74;1.2.7.2;1.2.7.8")
                    .withDss10p12Keystore()
                    .withAcceptAnyPolicy(true)
                    .build();

            workerMock.setupWorker(WORKER2, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner());
            workerSession.reloadConfiguration(WORKER2);
        }

        // WORKER3: empty list of extensions
        {
            final WorkerConfig config = TSAWorkerConfigBuilder.builder()
                    .withWorkerId(WORKER3)
                    .withWorkerName("TestTimeStampSigner3")
                    .withNoAuthAuthType()
                    .withDefaultTsaPolicyOid(DEFAULT_TSA_POLICY_OID)
                    .withAcceptedExtensions("")
                    .withDss10p12Keystore()
                    .withAcceptAnyPolicy(true)
                    .build();

            workerMock.setupWorker(WORKER3, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner());
            workerSession.reloadConfiguration(WORKER3);
        }

        // WORKER4: some extensions accepted (spaces between OIDs)
        {
            final WorkerConfig config = TSAWorkerConfigBuilder.builder()
                    .withWorkerId(WORKER4)
                    .withWorkerName("TestTimeStampSigner4")
                    .withNoAuthAuthType()
                    .withDefaultTsaPolicyOid(DEFAULT_TSA_POLICY_OID)
                    .withAcceptedExtensions("1.2.74; 1.2.7.2; 1.2.7.8")
                    .withDss10p12Keystore()
                    .withAcceptAnyPolicy(true)
                    .build();

            workerMock.setupWorker(WORKER4, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner());
            workerSession.reloadConfiguration(WORKER4);
        }

        // WORKER5: with one additional extension
        {
            final WorkerConfig config = TSAWorkerConfigBuilder.builder()
                    .withWorkerId(WORKER5)
                    .withWorkerName("TestTimeStampSigner5")
                    .withNoAuthAuthType()
                    .withDefaultTsaPolicyOid(DEFAULT_TSA_POLICY_OID)
                    .withDss10p12Keystore()
                    .withAcceptAnyPolicy(true)
                    .build();

            workerMock.setupWorker(WORKER5, CRYPTOTOKEN_CLASSNAME, config,
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
            workerSession.reloadConfiguration(WORKER5);
        }

        // WORKER6: with additional extensions
        {
            final WorkerConfig config = TSAWorkerConfigBuilder.builder()
                    .withWorkerId(WORKER6)
                    .withWorkerName("TestTimeStampSigner6")
                    .withNoAuthAuthType()
                    .withDefaultTsaPolicyOid(DEFAULT_TSA_POLICY_OID)
                    .withDss10p12Keystore()
                    .withAcceptAnyPolicy(true)
                    .build();

            workerMock.setupWorker(WORKER6, CRYPTOTOKEN_CLASSNAME, config,
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
            workerSession.reloadConfiguration(WORKER6);
        }

        // WORKER7: accepting only a specific request policy
        {
            final WorkerConfig config = TSAWorkerConfigBuilder.builder()
                    .withWorkerId(WORKER7)
                    .withWorkerName("TestTimeStampSigner7")
                    .withNoAuthAuthType()
                    .withDefaultTsaPolicyOid(DEFAULT_TSA_POLICY_OID)
                    .withAcceptedPolicies(DEFAULT_TSA_POLICY_OID)
                    .withDss10p12Keystore()
                    .build();

            workerMock.setupWorker(WORKER7, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner());
            workerSession.reloadConfiguration(WORKER7);
        }

        // WORKER8: accepting only a specific set of request policies
        {
            final WorkerConfig config = TSAWorkerConfigBuilder.builder()
                    .withWorkerId(WORKER8)
                    .withWorkerName("TestTimeStampSigner8")
                    .withNoAuthAuthType()
                    .withDefaultTsaPolicyOid(DEFAULT_TSA_POLICY_OID)
                    .withAcceptedPolicies("1.3.6.1.4.1.22408.1.2.3.45; 1.3.6.1.4.1.22408.1.2.3.46")
                    .withDss10p12Keystore()
                    .build();

            workerMock.setupWorker(WORKER8, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner());
            workerSession.reloadConfiguration(WORKER8);
        }
    }

    /**
     * Tests that the log contains the TSA_TIMESOURCE entry.
     */
    @Test
    public void testLogTimeSource() throws Exception {
        LOG.info("testLogTimeSource");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
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
     */
    @Test
    public void testLogBase64Entries() throws Exception {
        LOG.info("testLogBase64Entries");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[2000], BigInteger.valueOf(100));
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

    /**
     * Tests that a request including an extension not listed will cause a
     * rejection.
     */
    @Test
    public void testNotAcceptedExtensionPrevented() throws Exception {
        LOG.info("testNotAcceptedExtensionPrevented");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.addExtension(new ASN1ObjectIdentifier("1.2.7.9"), false, new DEROctetString("Value".getBytes(StandardCharsets.UTF_8)));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        try (
                CloseableReadableData requestData = createRequestData(requestBytes);
                CloseableWritableData responseData = createResponseData(false)
            ) {
            SignatureRequest signRequest = new SignatureRequest(100, requestData, responseData);
            processSession.process(new AdminInfo("Client user", null, null),
                    new WorkerIdentifier(WORKER2), signRequest, new MockedRequestContext(services));

            final TimeStampResponse timeStampResponse = new TimeStampResponse(responseData.toReadableData().getAsByteArray());
            timeStampResponse.validate(timeStampRequest);
            assertEquals("rejection", PKIStatus.REJECTION, timeStampResponse.getStatus());
            assertEquals("unacceptedExtension", PKIFailureInfo.unacceptedExtension, timeStampResponse.getFailInfo().intValue());
        }
    }

    /**
     * Tests that a request including an extension listed will accept
     * the extension.
     */
    @Test
    public void testAcceptedExtensions() throws Exception {
        LOG.info("testAcceptedExtensions");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.addExtension(new ASN1ObjectIdentifier("1.2.7.2"), false, new DEROctetString("Value".getBytes(StandardCharsets.UTF_8)));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
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
     */
    @Test
    public void testAcceptedExtensionsWithSpaces() throws Exception {
        LOG.info("testAcceptedExtensionsWithSpaces");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.addExtension(new ASN1ObjectIdentifier("1.2.7.2"), false, new DEROctetString("Value".getBytes(StandardCharsets.UTF_8)));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
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
     */
    @Test
    public void testEmptyAcceptedExtensionsOk() throws Exception {
        LOG.info("testEmptyAcceptedExtensions");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER3);
        timeStampResponse.validate(timeStampRequest);
        assertEquals("granted", PKIStatus.GRANTED, timeStampResponse.getStatus());
        assertNull("extensions in token", timeStampResponse.getTimeStampToken().getTimeStampInfo().toASN1Structure().getExtensions());
    }

    private TimeStampResponse timestamp(TimeStampRequest timeStampRequest, int workerId) throws Exception {
        byte[] requestBytes = timeStampRequest.getEncoded();
        try (
                CloseableReadableData requestData = createRequestData(requestBytes);
                CloseableWritableData responseData = createResponseData(false)
            ) {
            SignatureRequest signRequest = new SignatureRequest(100, requestData, responseData);

            processSession.process(new AdminInfo("Client user", null, null), new WorkerIdentifier(workerId), signRequest, new MockedRequestContext(services));

            return new TimeStampResponse(responseData.toReadableData().getAsInputStream());
        }
    }

    /**
     * Tests that a request including an extension not listed will cause a
     * rejection also when the list of extensions is empty.
     */
    @Test
    public void testEmptyAcceptedExtensionsPreventsExtension() throws Exception {
        LOG.info("testEmptyAcceptedExtensionsPreventsExtension");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.addExtension(new ASN1ObjectIdentifier("1.2.7.9"), false, new DEROctetString("Value".getBytes(StandardCharsets.UTF_8)));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER3);
        timeStampResponse.validate(timeStampRequest);
        assertEquals("rejection", PKIStatus.REJECTION, timeStampResponse.getStatus());
        assertEquals("unacceptedExtension", PKIFailureInfo.unacceptedExtension, timeStampResponse.getFailInfo().intValue());
    }

    /**
     * Test with a custom time stamp signer with additional extension.
     */
    @Test
    public void testAdditionalExtension() throws Exception {
        LOG.info("testAdditionalExtension");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
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
     */
    @Test
    public void testTwoAdditionalExtensions() throws Exception {
        LOG.info("testAdditionalExtension");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
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
     */
    @Test
    public void testIncludeCertIDIssuerSerialInvalid() {
        LOG.info("testIncludeCertIDIssuerSerialInvalid");

        final WorkerConfig config = new WorkerConfig();
        config.setProperty("INCLUDE_CERTID_ISSUERSERIAL", "_not_a_boolean_");

        final TimeStampSigner signer = new NullICryptoTokenV4TimeStampSigner();

        signer.init(WORKER1, config, null, null);

        final List<String> fatalErrors = signer.getFatalErrors(null);

        assertTrue("should contain configuration error but was " + fatalErrors,
                   fatalErrors.contains("Illegal value for property INCLUDE_CERTID_ISSUERSERIAL"));
    }

    /**
     * Test that the default for INCLUDE_CERTID_ISSUERSERIAL is to include
     * when the property is not set.
     */
    @Test
    public void testIncludeCertIDIssuerSerialDefaultUnset() throws Exception {
        LOG.info("testIncludeCertIDIssuerSerialDefaultUnset");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        workerSession.removeWorkerProperty(WORKER6, "INCLUDE_CERTID_ISSUERSERIAL");
        workerSession.reloadConfiguration(WORKER6);
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER6);
        timeStampResponse.validate(timeStampRequest);

        assertIncludeCertIDIssuerSerial("default", true, timeStampResponse);
    }

    /**
     * Test that the default for INCLUDE_CERTID_ISSUERSERIAL is to include
     * when an empty property value is specified.
     */
    @Test
    public void testIncludeCertIDIssuerSerialDefaultEmpty() throws Exception {
        LOG.info("testIncludeCertIDIssuerSerialDefaultEmpty");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        workerSession.setWorkerProperty(WORKER6, "INCLUDE_CERTID_ISSUERSERIAL", "");
        workerSession.reloadConfiguration(WORKER6);
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER6);
        timeStampResponse.validate(timeStampRequest);

        assertIncludeCertIDIssuerSerial("default", true, timeStampResponse);
    }

    /**
     * Test that INCLUDE_CERTID_ISSUERSERIAL=true includes the IssuerSerial.
     */
    @Test
    public void testIncludeCertIDIssuerSerialTrue() throws Exception {
        LOG.info("testIncludeCertIDIssuerSerialTrue");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        workerSession.setWorkerProperty(WORKER6, "INCLUDE_CERTID_ISSUERSERIAL", "TRUE");
        workerSession.reloadConfiguration(WORKER6);
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER6);
        timeStampResponse.validate(timeStampRequest);

        assertIncludeCertIDIssuerSerial("explicit true", true, timeStampResponse);
    }

    /**
     * Test that INCLUDE_CERTID_ISSUERSERIAL=false includes the IssuerSerial.
     */
    @Test
    public void testIncludeCertIDIssuerSerialFalse() throws Exception {
        LOG.info("testIncludeCertIDIssuerSerialFalse");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        workerSession.setWorkerProperty(WORKER6, "INCLUDE_CERTID_ISSUERSERIAL", "FALSE");
        workerSession.reloadConfiguration(WORKER6);
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER6);
        timeStampResponse.validate(timeStampRequest);

        assertIncludeCertIDIssuerSerial("explicit false", false, timeStampResponse);
    }

    /**
     * Tests the default value for INCLUDECMSALGORITHMPROTECT.
     * @throws Exception in case of error
     */
    @Test
    public void testIncludeCmsProtectAlgorithmAttribute_default() throws Exception {
        LOG.info("testIncludeCmsProtectAlgorithmAttribute_default");
        includeCmsProtectAlgorithmAttribute(null);
    }

    /**
     * Tests for INCLUDECMSALGORITHMPROTECT=true.
     * @throws Exception in case of error
     */
    @Test
    public void testIncludeCmsProtectAlgorithmAttribute_true() throws Exception {
        LOG.info("testIncludeCmsProtectAlgorithmAttribute_true");
        includeCmsProtectAlgorithmAttribute(true);
    }

    /**
     * Tests for INCLUDECMSALGORITHMPROTECT=false.
     * @throws Exception in case of error
     */
    @Test
    public void testIncludeCmsProtectAlgorithmAttribute_false() throws Exception {
        LOG.info("testIncludeCmsProtectAlgorithmAttribute_false");
        includeCmsProtectAlgorithmAttribute(false);
    }

    private void includeCmsProtectAlgorithmAttribute(Boolean includeCmsProtectAlgorithmAttribute) throws Exception {
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        if (includeCmsProtectAlgorithmAttribute == null) {
            workerSession.removeWorkerProperty(WORKER6, "INCLUDECMSALGORITHMPROTECTATTRIBUTE");
        } else {
            workerSession.setWorkerProperty(WORKER6, "INCLUDECMSALGORITHMPROTECTATTRIBUTE", includeCmsProtectAlgorithmAttribute ? "TRUE" : "FALSE");
        }
        workerSession.reloadConfiguration(WORKER6);
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER6);
        timeStampResponse.validate(timeStampRequest);

        // check the signingTime signed attribute
        final AttributeTable attrs = timeStampResponse.getTimeStampToken().getSignedAttributes();
        final Attribute attr = attrs.get(CMSAttributes.cmsAlgorithmProtect);

        if (includeCmsProtectAlgorithmAttribute == null || includeCmsProtectAlgorithmAttribute) {
            assertNotNull("Should contain cmsProtectAlgorithmAttribute signed attribute", attr);
        } else {
            assertNull("Should not contain cmsProtectAlgorithmAttribute signed attribute", attr);
        }
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
     */
    @Test
    public void testOnlyAcceptedPolicy() throws Exception {
        LOG.info("testOnlyAcceptedPolicy");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.3.6.1.4.1.22408.1.2.3.45"));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER7);
        timeStampResponse.validate(timeStampRequest);
        assertEquals("acceptance", PKIStatus.GRANTED, timeStampResponse.getStatus());
    }

    /**
     * Test that a request policy is accepted for a signer accepting a set
     * of request policies.
     */
    @Test
    public void testOnlyAcceptedPolicyInSet() throws Exception {
        LOG.info("testAnyAcceptedPolicy");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.3.6.1.4.1.22408.1.2.3.45"));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER8);
        timeStampResponse.validate(timeStampRequest);
        assertEquals("acceptance", PKIStatus.GRANTED, timeStampResponse.getStatus());
    }

    /**
     * Test that requesting a policy not in the set of accepted policies is
     * rejected.
     */
    @Test
    public void testNonAcceptedPolicy() throws Exception {
        LOG.info("testAnyAcceptedPolicy");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.3.6.1.4.1.22408.1.2.1.2"));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER7);
        timeStampResponse.validate(timeStampRequest);
        assertEquals("acceptance", PKIStatus.REJECTION, timeStampResponse.getStatus());
    }

    /**
     * Test that requesting a policy works with ACCEPTANYPOLICY set to true.
     */
    @Test
    public void testAnyAcceptedPolicy() throws Exception {
        LOG.info("testAnyAcceptedPolicy");
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("1.3.6.1.4.1.22408.1.2.1.2"));
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER1);
        timeStampResponse.validate(timeStampRequest);
        assertEquals("acceptance", PKIStatus.GRANTED, timeStampResponse.getStatus());
    }

    /**
     * Test that setting both ACCEPTANYPOLICY and ACCEPTEDPOLICIES results in
     * a configuration error.
     */
    @Test
    public void testBothAnyAcceptedAndAcceptedPoliciesError() {
        LOG.info("testBothAnyAcceptedAndAcceptedPoliciesError");

        final WorkerConfig config = TSAWorkerConfigBuilder.builder()
                .withAcceptAnyPolicy(true)
                .withAcceptedPolicies(DEFAULT_TSA_POLICY_OID)
                .build();

        final TimeStampSigner signer = new NullICryptoTokenV4TimeStampSigner();

        signer.init(WORKER1, config, null, null);

        final List<String> fatalErrors = signer.getFatalErrors(null);

        assertTrue("should contain configuration error",
                   fatalErrors.contains("Can not set ACCEPTANYPOLICY to true and ACCEPTEDPOLICIES at the same time"));
    }

    /**
     * Test that setting both ACCEPTANYPOLICY (with caps, TRUE) and ACCEPTEDPOLICIES results in
     * a configuration error for defining conflicts, but not for the ACCEPTANYPOLICY value.
     */
    @Test
    public void testBothAnyAcceptedAndAcceptedPoliciesCapsError() {
        LOG.info("testBothAnyAcceptedAndAcceptedPoliciesError");

        final WorkerConfig config = new WorkerConfig();
        config.setProperty("ACCEPTANYPOLICY", "TRUE");
        config.setProperty("ACCEPTEDPOLICIES", DEFAULT_TSA_POLICY_OID);

        final TimeStampSigner signer = new NullICryptoTokenV4TimeStampSigner();

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
     */
    @Test
    public void testAcceptAnyPolicyFalseAndAcceptedPolicies() {
        LOG.info("testAcceptAnyPolicyFalseAndAcceptedPolicies");

        final WorkerConfig config = TSAWorkerConfigBuilder.builder()
                .withAcceptAnyPolicy(false)
                .withAcceptedPolicies(DEFAULT_TSA_POLICY_OID)
                .build();

        final TimeStampSigner signer = new NullICryptoTokenV4TimeStampSigner();

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
     */
    @Test
    public void testAcceptAnyPolicyEmptyAndAcceptedPolicies() {
        LOG.info("testAcceptAnyPolicyEmptyAndAcceptedPolicies");

        final WorkerConfig config = new WorkerConfig();
        config.setProperty("ACCEPTANYPOLICY", "");
        config.setProperty("ACCEPTEDPOLICIES", DEFAULT_TSA_POLICY_OID);

        final TimeStampSigner signer = new NullICryptoTokenV4TimeStampSigner();

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
     */
    @Test
    public void testNoneOfAnyAcceptedOrAcceptedPoliciesError() {
        LOG.info("testBothAnyAcceptedAndAcceptedPoliciesError");

        final WorkerConfig config = new WorkerConfig();

        final TimeStampSigner signer = new NullICryptoTokenV4TimeStampSigner();

        signer.init(WORKER1, config, null, null);

        final List<String> fatalErrors = signer.getFatalErrors(null);

        assertTrue("should contain configuration error",
                   fatalErrors.contains("Must specify either ACCEPTEDPOLICIES or ACCEPTANYPOLICY true"));
    }

    /**
     * Test that not setting an invalid value for ACCEPTANYPOLICY results in
     * an error.
     */
    @Test
    public void testAcceptAnyPolicyInvalid() {
        LOG.info("testBothAnyAcceptedAndAcceptedPoliciesError");

        final WorkerConfig config = new WorkerConfig();
        config.setProperty("ACCEPTANYPOLICY", "foo");

        final TimeStampSigner signer = new NullICryptoTokenV4TimeStampSigner();

        signer.init(WORKER1, config, null, null);

        final List<String> fatalErrors = signer.getFatalErrors(null);

        assertTrue("should contain configuration error",
                   fatalErrors.contains("Illegal value for ACCEPTANYPOLICY: foo"));
    }

    /**
     * Test that setting ACCEPTANYPOLICY to false without setting ACCEPTEDPOLICIES
     * is not allowed.
     */
    @Test
    public void testAcceptAnyPolicyFalseAndNoAcceptedPolicies() {
        LOG.info("testAcceptAnyPolicyFalseAndNoAcceptedPolicies");

        final WorkerConfig config = TSAWorkerConfigBuilder.builder()
                .withAcceptAnyPolicy(false)
                .build();

        final TimeStampSigner signer = new NullICryptoTokenV4TimeStampSigner();

        signer.init(WORKER1, config, null, null);

        final List<String> fatalErrors = signer.getFatalErrors(null);

        assertTrue("should contain configuration error",
                   fatalErrors.contains("Must specify either ACCEPTEDPOLICIES or ACCEPTANYPOLICY true"));
    }

    /**
     * Test that setting ACCEPTANYPOLICY to FALSE (with caps) without setting ACCEPTEDPOLICIES
     * is not allowed.
     */
    @Test
    public void testAcceptAnyPolicyFalseCapitalAndNoAcceptedPolicies() {
        LOG.info("testAcceptAnyPolicyFalseAndNoAcceptedPolicies");

        final WorkerConfig config = new WorkerConfig();
        config.setProperty("ACCEPTANYPOLICY", "FALSE");

        final TimeStampSigner signer = new NullICryptoTokenV4TimeStampSigner();

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
     */
    @Test
    public void testAcceptAnyPolicyEmptyAndNoAcceptedPolicies() {
        LOG.info("testAcceptAnyPolicyEmptyAndNoAcceptedPolicies");

        final WorkerConfig config = new WorkerConfig();
        config.setProperty("ACCEPTANYPOLICY", "");

        final TimeStampSigner signer = new NullICryptoTokenV4TimeStampSigner();

        signer.init(WORKER1, config, null, null);

        final List<String> fatalErrors = signer.getFatalErrors(null);

        assertTrue("should contain configuration error",
                   fatalErrors.contains("Must specify either ACCEPTEDPOLICIES or ACCEPTANYPOLICY true"));
    }

    /**
     * Test that setting ACCEPTEDPOLICIES to an empty list is accepted without
     * setting ACCEPTANYPOLICY.
     */
    @Test
    public void testAcceptedPoliciesEmpty() {
        LOG.info("testAcceptedPoliciesEmpty");

        final WorkerConfig config = TSAWorkerConfigBuilder.builder()
                .withAcceptedPolicies("")
                .build();

        final TimeStampSigner signer = new NullICryptoTokenV4TimeStampSigner();

        signer.init(WORKER1, config, null, null);

        final List<String> fatalErrors = signer.getFatalErrors(null);

        assertFalse("should not contain error",
                fatalErrors.contains("Must specify either ACCEPTEDPOLICIES or ACCEPTANYPOLICY true"));
    }

    /**
     * Tests for the certificate requirements.
     */
    @Test
    public void testCertificateIssues() throws Exception {
        LOG.info(">testCertificateIssues");

        TimeStampSigner instance = new TimeStampSigner();

        // Certificate without id_kp_timeStamping
        final Certificate certNoEku = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=Without EKU").build());
        assertEquals(Arrays.asList("Missing extended key usage timeStamping", "The extended key usage extension must be present and marked as critical"), instance.getCertificateIssues(Collections.singletonList(certNoEku)));

        // Certificate with non-critical id_kp_timeStamping
        boolean critical = false;
        final Certificate certEku = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=With non-critical EKU").addExtension(new CertExt(Extension.extendedKeyUsage, critical, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping))).build());
        assertEquals(Collections.singletonList("The extended key usage extension must be present and marked as critical"), instance.getCertificateIssues(Collections.singletonList(certEku)));

        // Certificate with critical id_kp_timeStamping but also with codeSigning
        critical = true;
        final Certificate certCritEkuButAlsoOther = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=With critical EKU and other").addExtension(new CertExt(Extension.extendedKeyUsage, critical, new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId.id_kp_timeStamping, KeyPurposeId.id_kp_codeSigning }))).build());
        assertEquals(Collections.singletonList("No other extended key usages than timeStamping is allowed"), instance.getCertificateIssues(Collections.singletonList(certCritEkuButAlsoOther)));

        // OK: Certificate with critical id_kp_timeStamping
        critical = true;
        final Certificate certCritEku = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=With critical EKU").addExtension(new CertExt(Extension.extendedKeyUsage, critical, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping))).build());
        assertEquals(Collections.<String>emptyList(), instance.getCertificateIssues(Collections.singletonList(certCritEku)));

    }

    /**
     * Test that Signing works with parameters specified as empty values.
     */
    @Test
    public void testEmptyParamsWorks() throws Exception {
        LOG.info("testEmptyParamsOK");
        TimeStampRequestGenerator timeStampRequestGenerator
                = new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        workerSession.setWorkerProperty(WORKER1, "ACCEPTEDALGORITHMS", "  ");
        workerSession.setWorkerProperty(WORKER1, "SIGNATUREALGORITHM", "  ");
        workerSession.setWorkerProperty(WORKER1, "REQUIREVALIDCHAIN", "  ");
        workerSession.setWorkerProperty(WORKER1, "ACCEPTEDEXTENSIONS", "  ");
        workerSession.setWorkerProperty(WORKER1, "TIMESOURCE", "  ");
        workerSession.setWorkerProperty(WORKER1, "MAXSERIALNUMBERLENGTH", "  ");
        workerSession.setWorkerProperty(WORKER1, "ACCURACYMICROS", "   ");
        workerSession.setWorkerProperty(WORKER1, "INCLUDE_CERTID_ISSUERSERIAL", "   ");
        workerSession.setWorkerProperty(WORKER1, "INCLUDESTATUSSTRING", "   ");
        workerSession.setWorkerProperty(WORKER1, "MINREMAININGCERTVALIDITY", "   ");
        workerSession.reloadConfiguration(WORKER1);
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER1);
        timeStampResponse.validate(timeStampRequest);
    }

    /**
     * Tests the TimeStampSigner for bad request that cannot be parsed (null).
     * @throws Exception in case of failure.
     */
    @Test
    public void badTimeStampRequest0() throws Exception {
        LOG.info("badTimeStampRequest0");
        // given
        // then
        expectedException.expect(IllegalRequestException.class);
        expectedException.expectMessage("Request must contain data");
        // when
        timestamp(new BadTimeStampRequest(BadTimeStampRequest.BadTimeStampRequestType.NULL), WORKER1);
    }

    /**
     * Tests the TimeStampSigner for bad request that cannot be parsed (empty).
     * @throws Exception in case of failure.
     */
    @Test
    public void badTimeStampRequest1() throws Exception {
        LOG.info("badTimeStampRequest1");
        // given
        // then
        expectedException.expect(IllegalRequestException.class);
        expectedException.expectMessage("Request must contain data");
        // when
        timestamp(new BadTimeStampRequest(BadTimeStampRequest.BadTimeStampRequestType.EMPTY), WORKER1);
    }

    /**
     * Tests the TimeStampSigner for bad request that cannot be parsed (single byte).
     * @throws Exception in case of failure.
     */
    @Test
    public void badTimeStampRequest2() throws Exception {
        LOG.info("badTimeStampRequest2");
        // given
        // when
        final TimeStampResponse timeStampResponse = timestamp(
                new BadTimeStampRequest(BadTimeStampRequest.BadTimeStampRequestType.ONE), WORKER1);
        // then
        assertEquals("status: rejected", PKIStatus.REJECTION, timeStampResponse.getStatus());
        assertTrue("Expected message: The request could not be parsed.", timeStampResponse.getStatusString().contains("The request could not be parsed."));
    }

    /**
     * Tests the TimeStampSigner for bad request that has wrong length (extra boolean). Expects the TSPException.
     * @throws Exception in case of failure.
     */
    @Test
    public void badTimeStampRequest3() throws Exception {
        LOG.info("badTimeStampRequest3");
        // given
        // when
        final TimeStampResponse timeStampResponse = timestamp(
                new BadTimeStampRequest(BadTimeStampRequest.BadTimeStampRequestType.EXTRA), WORKER1);
        //  then
        assertEquals("status: rejected", PKIStatus.REJECTION, timeStampResponse.getStatus());
        assertTrue("Expected message: imprint digest the wrong length", timeStampResponse.getStatusString().contains("imprint digest the wrong length"));
    }

    /**
     * Tests for TSA Timestamp Request fields:
     * <ul>
     *     <li>ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_CERTREQ</li>
     *     <li>ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_CRITEXTOIDS</li>
     *     <li>ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_NONCRITEXTOIDS</li>
     *     <li>ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_NONCE</li>
     *     <li>ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_VERSION</li>
     *     <li>ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_MESSAGEIMPRINTALGOID</li>
     *     <li>ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_MESSAGEIMPRINTDIGEST</li>
     * </ul>
     * @throws Exception in case of failure.
     */
    @Test
    public void logTsaTimestampRequestFields() throws Exception {
        LOG.info("logTsaTimestampRequestFields");
        // given
        final TimeStampRequest timeStampRequest = new TimeStampRequestGenerator().generate(
                TSPAlgorithms.SHA256, new byte[2000], BigInteger.valueOf(100));
        // when
        final TimeStampResponse timeStampResponse = timestamp(timeStampRequest, WORKER1);
        // then
        timeStampResponse.validate(timeStampRequest);
        final LogMap logMap = LogMap.getInstance(processSession.getLastRequestContext());
        final Object logTsaTimestampRequestCertreq = logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_CERTREQ);
        assertNotNull("ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_CERTREQ", logTsaTimestampRequestCertreq);
        final Object logTsaTimestampRequestCritExtOids = logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_CRITEXTOIDS);
        assertNotNull("ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_CRITEXTOIDS", logTsaTimestampRequestCritExtOids);
        final Object logTsaTimestampRequestNonCritExtOids = logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_NONCRITEXTOIDS);
        assertNotNull("ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_NONCRITEXTOIDS", logTsaTimestampRequestNonCritExtOids);
        final Object logTsaTimestampRequestNonce = logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_NONCE);
        assertNotNull("ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_NONCE", logTsaTimestampRequestNonce);
        final Object logTsaTimestampRequestVersion = logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_VERSION);
        assertNotNull("ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_VERSION", logTsaTimestampRequestVersion);
        final Object logTsaTimestampRequestMessageImprintAlgOid = logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_MESSAGEIMPRINTALGOID);
        assertNotNull("ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_MESSAGEIMPRINTALGOID", logTsaTimestampRequestMessageImprintAlgOid);
        final Object logTsaTimestampRequestMessageImprintDigest = logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_MESSAGEIMPRINTDIGEST);
        assertNotNull("ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_MESSAGEIMPRINTDIGEST", logTsaTimestampRequestMessageImprintDigest);
    }

    private static class NullICryptoTokenV4TimeStampSigner extends TimeStampSigner {
        @Override
        public ICryptoTokenV4 getCryptoToken(final IServices services) {
            return null;
        }
    }

    /**
     * TimeStampRequest containing corrupt data.
     */
    private static class BadTimeStampRequest extends TimeStampRequest {

        public enum BadTimeStampRequestType {
            NULL,
            EMPTY,
            ONE,
            EXTRA
        }

        private final BadTimeStampRequestType type;

        public BadTimeStampRequest(BadTimeStampRequestType type) {
            super(new TimeStampReq(null, null, null, null, null));
            this.type = type;
        }

        @Override
        public byte[] getEncoded() throws IOException {
            switch (type) {
                case NULL:
                    return null;
                case EMPTY:
                    return new byte[0];
                case ONE:
                    return new byte[1];
                case EXTRA:
                    return getModifiedSequenceWithExtraBoolean();
            }
            throw new IOException("Cannot find proper type.");
        }

        /**
         * Returns a modified ASN1Sequence with extra boolean element.
         * Normal request:
         * <pre>
         *    0 2025: SEQUENCE {
         *    4    1:   INTEGER 1
         *    7 2015:   SEQUENCE {
         *   11    9:     SEQUENCE {
         *   13    5:       OBJECT IDENTIFIER sha1 (1 3 14 3 2 26)
         *   20    0:       NULL
         *          :       }
         *   22 2000:     OCTET STRING
         *          :       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *          :       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *          :       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *          :       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *          :       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *          :       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *          :       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *          :       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *          :               [ Another 1872 bytes skipped ]
         *          :     }
         * 2026    1:   INTEGER 100
         *          :   }
         * </pre>
         * After modification:
         * <pre>
         *    0 2028: SEQUENCE {
         *    4    1:   INTEGER 1
         *    7 2015:   SEQUENCE {
         *   11    9:     SEQUENCE {
         *   13    5:       OBJECT IDENTIFIER sha1 (1 3 14 3 2 26)
         *   20    0:       NULL
         *          :       }
         *   22 2000:     OCTET STRING
         *          :       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *          :       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *          :       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *          :       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *          :       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *          :       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *          :       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *          :       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *          :               [ Another 1872 bytes skipped ]
         *          :     }
         * 2026    1:   INTEGER 100
         * 2029    1:   BOOLEAN TRUE
         *          :   }
         * </pre>
         */
        private byte[] getModifiedSequenceWithExtraBoolean() throws IOException {
            // Generate
            final TimeStampRequest timeStampRequest = new TimeStampRequestGenerator().generate(
                    TSPAlgorithms.SHA256, new byte[2000], BigInteger.valueOf(100));
            // Read typical TimeStampRequest
            final ASN1Primitive asn1Primitive = new ASN1InputStream(
                    new ByteArrayInputStream(timeStampRequest.getEncoded())).readObject();
            final ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(asn1Primitive.getEncoded());
            // Recreate sequence through vector (0-2 original elements)
            final ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
            asn1EncodableVector.add(asn1Sequence.getObjectAt(0));
            asn1EncodableVector.add(asn1Sequence.getObjectAt(1));
            asn1EncodableVector.add(asn1Sequence.getObjectAt(2));
            // Extra boolean
            asn1EncodableVector.add(ASN1Boolean.getInstance(true));
            // Return new sequence from vector
            return new DERSequence(asn1EncodableVector).getEncoded();
        }
    }
}
