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
import java.security.Security;
import java.util.Arrays;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.LocalComputerTimeSource;
import org.signserver.server.cryptotokens.HardCodedCryptoTokenAliases;
import org.signserver.server.log.LogMap;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.WorkerSessionMock;

/**
 * Unit tests for the TimeStampSigner.
 *
 * System tests can be put in the Test-System project instead.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TimeStampSignerUnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TimeStampSignerUnitTest.class);

    private static final int WORKER1 = 8890;
    private static final int WORKER2 = 8891;
    private static final int WORKER3 = 8892;
    private static final int WORKER4 = 8893;
    private static final int WORKER5 = 8894;
    private static final int WORKER6 = 8895;
    private static final String NAME = "NAME";
    private static final String AUTHTYPE = "AUTHTYPE";
    private static final String CRYPTOTOKEN_CLASSNAME = "org.signserver.server.cryptotokens.HardCodedCryptoToken";

    private IGlobalConfigurationSession.IRemote globalConfig;
    private IWorkerSession.IRemote workerSession;

    @Before
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
        final RequestContext requestContext = new RequestContext();
        final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                WORKER1, signRequest, requestContext);

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
                (byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);

        LogMap logMap = LogMap.getInstance(requestContext);
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
        final RequestContext requestContext = new RequestContext();
        final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                WORKER1, signRequest, requestContext);

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
                (byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);

        LogMap logMap = LogMap.getInstance(requestContext);
        assertNotNull("response",
                logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPRESPONSE_ENCODED));
        assertEquals("log line doesn't contain newlines", -1,
                logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPRESPONSE_ENCODED).lastIndexOf('\n'));
        assertNotNull("request",
                logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_ENCODED));
        assertEquals("log line doesn't contain newlines", -1,
                logMap.get(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_ENCODED).lastIndexOf('\n'));
    }

    private void setupWorkers() {

        final GlobalConfigurationSessionMock globalMock
                = new GlobalConfigurationSessionMock();
        final WorkerSessionMock workerMock = new WorkerSessionMock(globalMock);
        globalConfig = globalMock;
        workerSession = workerMock;

        // WORKER1
        {
            final int workerId = WORKER1;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestTimeStampSigner1");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty(TimeStampSigner.DEFAULTTSAPOLICYOID, "1.2.3.4");
            config.setProperty("DEFAULTKEY", HardCodedCryptoTokenAliases.KEY_ALIAS_4);

            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
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
            config.setProperty("DEFAULTKEY", HardCodedCryptoTokenAliases.KEY_ALIAS_4);
            config.setProperty("ACCEPTEDEXTENSIONS", "1.2.74;1.2.7.2;1.2.7.8");

            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
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
            config.setProperty("DEFAULTKEY", HardCodedCryptoTokenAliases.KEY_ALIAS_4);
            config.setProperty("ACCEPTEDEXTENSIONS", "");

            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
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
            config.setProperty("DEFAULTKEY", HardCodedCryptoTokenAliases.KEY_ALIAS_4);
            config.setProperty("ACCEPTEDEXTENSIONS", "1.2.74; 1.2.7.2; 1.2.7.8");

            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }
        
        // WORKER5: with one additional extension
        {
            final int workerId = WORKER5;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestTimeStampSigner4");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty(TimeStampSigner.DEFAULTTSAPOLICYOID, "1.2.3.4");
            config.setProperty("DEFAULTKEY", HardCodedCryptoTokenAliases.KEY_ALIAS_4);
            
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }

                @Override
                protected Extensions getAdditionalExtensions(ProcessRequest request, RequestContext context) {
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
            config.setProperty(TimeStampSigner.DEFAULTTSAPOLICYOID, "1.2.3.4");
            config.setProperty("DEFAULTKEY", HardCodedCryptoTokenAliases.KEY_ALIAS_4);
            
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new TimeStampSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }

                @Override
                protected Extensions getAdditionalExtensions(ProcessRequest request, RequestContext context) {
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
        final RequestContext requestContext = new RequestContext();
        final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                WORKER2, signRequest, requestContext);

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
        final RequestContext requestContext = new RequestContext();
        final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                WORKER2, signRequest, requestContext);

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
        final RequestContext requestContext = new RequestContext();
        final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                WORKER4, signRequest, requestContext);

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
        final RequestContext requestContext = new RequestContext();
        final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                WORKER3, signRequest, requestContext);

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
        final RequestContext requestContext = new RequestContext();
        final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                WORKER3, signRequest, requestContext);

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
                (byte[]) res.getProcessedData());
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
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest = new GenericSignRequest(100, requestBytes);
        final RequestContext requestContext = new RequestContext();
        final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                WORKER5, signRequest, requestContext);

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
                (byte[]) res.getProcessedData());
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
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest = new GenericSignRequest(100, requestBytes);
        final RequestContext requestContext = new RequestContext();
        final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                WORKER6, signRequest, requestContext);

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
                (byte[]) res.getProcessedData());
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
}

