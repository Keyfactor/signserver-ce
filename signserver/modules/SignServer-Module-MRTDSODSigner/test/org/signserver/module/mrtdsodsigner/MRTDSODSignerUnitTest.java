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
package org.signserver.module.mrtdsodsigner;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.module.mrtdsodsigner.jmrtd.SODFile;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SODSignRequest;
import org.signserver.common.SODSignResponse;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.IProcessable;
import org.signserver.server.cryptotokens.HardCodedCryptoToken;
import org.signserver.test.mock.GlobalConfigurationSessionMock;
import org.signserver.test.mock.WorkerSessionMock;

/**
 * Unit tests for MRTDSODSigner.
 *
 * This tests uses a mockup and does not require an running application
 * server. Tests that require that can be placed among the system tests.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class MRTDSODSignerUnitTest extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            MRTDSODSignerUnitTest.class.getName());

    private static final String AUTHTYPE = "AUTHTYPE";
    private static final String CRYPTOTOKEN_CLASSNAME
            = "org.signserver.server.cryptotokens.HardCodedCryptoToken";
    private static final String NAME = "NAME";

    /** Worker7897: Default algorithms, default hashing setting. */
    private static final int WORKER1 = 7897;

    /** Worker7898: SHA512, default hashing setting. */
    private static final int WORKER2 = 7898;

    /** Worker7899: Default algorithms, DODATAGROUPHASHING=true. */
    private static final int WORKER3 = 7899;

    /** Worker7900: SHA512, DODATAGROUPHASHING=true. */
    private static final int WORKER4 = 7900;

    /** Worker7910: ldsVersion=1.8, unicodeVersion=4.0.0. */
    private static final int WORKER5 = 7910;

    /** Worker7911: SHA1withRSAandMGF1 */
    private static final int WORKER11 = 7911;

    /** Worker7912: SHA256withRSAandMGF1 */
    private static final int WORKER12 = 7912;

    /** Worker7913: SHA384withRSAandMGF1 */
    private static final int WORKER13 = 7913;

    /** Worker7914: SHA512withRSAandMGF1 */
    private static final int WORKER14 = 7914;

    /** Worker7915: SHA1, SHA256withRSAandMGF1 */
    private static final int WORKER15 = 7915;

    private IGlobalConfigurationSession.IRemote globalConfig;
    private IWorkerSession.IRemote workerSession;
    
    public MRTDSODSignerUnitTest() {
        SignServerUtil.installBCProvider();
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        setupWorkers();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Creates and verifies a simple SODFile
     * @throws Exception
     */
    public void test01SODFile() throws Exception {
    	Map<Integer, byte[]> dataGroupHashes = new HashMap<Integer, byte[]>();
    	dataGroupHashes.put(Integer.valueOf(1), "12345".getBytes());
    	dataGroupHashes.put(Integer.valueOf(4), "abcdef".getBytes());

    	KeyPair keys = KeyTools.genKeys("1024", "RSA");
    	X509Certificate cert = CertTools.genSelfCert("CN=mrtdsodtest", 33, null, keys.getPrivate(), keys.getPublic(), "SHA256WithRSA", false);
        SODFile sod = new SODFile("SHA256", "SHA256withRSA", dataGroupHashes, keys.getPrivate(), cert);
        assertNotNull(sod);
        boolean verify = sod.checkDocSignature(cert);
        assertTrue(verify);
        byte[] encoded = sod.getEncoded();
        SODFile sod2 = new SODFile(new ByteArrayInputStream(encoded));
        verify = sod2.checkDocSignature(cert);
        assertTrue(verify);
    }

    /**
     * Requests signing of some data group hashes, using two different signers
     * with different algorithms and verifies the result.
     * @throws Exception
     */
    public void test02SignData() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));
        signHelper(WORKER1, 12, dataGroups1, false, "SHA256", "SHA256withRSA");

        // DG3, DG7, DG8, DG13 and default values
        Map<Integer, byte[]> dataGroups2 = new LinkedHashMap<Integer, byte[]>();
        dataGroups2.put(3, digestHelper("Dummy Value 3".getBytes(), "SHA256"));
        dataGroups2.put(7, digestHelper("Dummy Value 4".getBytes(), "SHA256"));
        dataGroups2.put(8, digestHelper("Dummy Value 5".getBytes(), "SHA256"));
        dataGroups2.put(13, digestHelper("Dummy Value 6".getBytes(), "SHA256"));
        signHelper(WORKER1, 13, dataGroups2, false, "SHA256", "SHA256withRSA");

        // DG1, DG2 with the other worker which uses SHA512 and SHA512withRSA
        Map<Integer, byte[]> dataGroups3 = new LinkedHashMap<Integer, byte[]>();
        dataGroups3.put(1, digestHelper("Dummy Value 7".getBytes(), "SHA512"));
        dataGroups3.put(2, digestHelper("Dummy Value 8".getBytes(), "SHA512"));
        signHelper(WORKER2, 14, dataGroups3, false, "SHA512", "SHA512withRSA");
    }

    /**
     * Requests signing of some data groups, using two different signers
     * with different algorithms and verifies the result. The signer does the
     * hashing.
     * @throws Exception
     */
    public void test03SignUnhashedData() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, "Dummy Value 1".getBytes());
        dataGroups1.put(2, "Dummy Value 2".getBytes());
        signHelper(WORKER3, 15, dataGroups1, true, "SHA256", "SHA256withRSA");

        // DG3, DG7, DG8, DG13 and default values
        Map<Integer, byte[]> dataGroups2 = new LinkedHashMap<Integer, byte[]>();
        dataGroups2.put(3, "Dummy Value 3".getBytes());
        dataGroups2.put(7, "Dummy Value 4".getBytes());
        dataGroups2.put(8, "Dummy Value 5".getBytes());
        dataGroups2.put(13, "Dummy Value 6".getBytes());
        signHelper(WORKER3, 16, dataGroups2, true, "SHA256", "SHA256withRSA");

        // DG1, DG2 with the other worker which uses SHA512 and SHA512withRSA
        Map<Integer, byte[]> dataGroups3 = new LinkedHashMap<Integer, byte[]>();
        dataGroups3.put(1, "Dummy Value 7".getBytes());
        dataGroups3.put(2, "Dummy Value 8".getBytes());
        signHelper(WORKER4, 17, dataGroups3, true, "SHA512", "SHA512withRSA");
    }

    public void test04LdsConfigVersion17_ok() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));
        final SODFile sod = signHelper(WORKER1, 12, dataGroups1, false,
                "SHA256", "SHA256withRSA");

        // ASN.1 Dump SODFile
        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(sod.getEncoded()));
        DERObject object = in.readObject();
        LOG.info("Object: " + ASN1Dump.dumpAsString(object, true));

//        // ANS.1 Dump LDSSecurityObject
//        in = new ASN1InputStream(new ByteArrayInputStream(sod.getSecurityObject()));
//        object = in.readObject();
//        LOG.info("LDSSecurityObject: " + ASN1Dump.dumpAsString(object, true));

        assertNull("LDS version", sod.getLdsVersion());
        assertNull("Unicode version", sod.getUnicodeVersion());
    }

    public void test05LdsConfigVersion18_ok() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));
        final SODFile sod = signHelper(WORKER5, 12, dataGroups1, false,
                "SHA256", "SHA256withRSA");

        // ASN.1 Dump
        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(sod.getEncoded()));
        DERObject object = in.readObject();
        LOG.info("Object: " + ASN1Dump.dumpAsString(object, true));

//        // ANS.1 Dump LDSSecurityObject
//        in = new ASN1InputStream(new ByteArrayInputStream(sod.getSecurityObject()));
//        object = in.readObject();
//        LOG.info("LDSSecurityObject: " + ASN1Dump.dumpAsString(object, true));

        assertEquals("LDS version", "0108", sod.getLdsVersion());
        assertEquals("Unicode version", "040000", sod.getUnicodeVersion());
    }
    
    public void test05LdsConfigVersion18_noUnicode() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));

        // Missing unicode version
        workerSession.removeWorkerProperty(WORKER5, "UNICODEVERSION");
        workerSession.reloadConfiguration(WORKER5);

        try {
            signHelper(WORKER5, 12, dataGroups1, false,
                "SHA256", "SHA256withRSA");
            fail("Should have failed");
        } catch (IllegalRequestException ignored) {
            // OK
            LOG.debug("Message was: " + ignored.getMessage());
        }
    }

    public void test05LdsConfigVersionUnsupported() throws Exception {

        // Unsupported version
        workerSession.setWorkerProperty(WORKER5, "LDSVERSION", "4711");
        workerSession.reloadConfiguration(WORKER5);

        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));
        try {
            signHelper(WORKER5, 12, dataGroups1, false, "SHA256",
                    "SHA256withRSA");
            fail("Should have failed");
        } catch (IllegalRequestException ignored) {
            // OK
            LOG.debug("Message was: " + ignored.getMessage());
        }
    }

    /**
     * Requests signing of some data group hashes and verifies the result.
     * @throws Exception
     */
    public void test06SignData_SHA1withRSAandMGF1() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA1"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA1"));
        signHelper(WORKER11, 12, dataGroups1, false, "SHA1",
                "SHA1withRSAandMGF1");
    }
    
    /**
     * Requests signing of some data group hashes and verifies the result.
     * @throws Exception
     */
    public void test06SignData_SHA256withRSAandMGF1() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));
        signHelper(WORKER12, 12, dataGroups1, false, "SHA256",
                "SHA256withRSAandMGF1");

        // DG1, DG2 and default values, other hash than in algorithm
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA1"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA1"));
        signHelper(WORKER15, 12, dataGroups1, false, "SHA1",
                "SHA256withRSAandMGF1");
    }

    /**
     * Requests signing of some data group hashes and verifies the result.
     * @throws Exception
     */
    public void test06SignData_SHA384withRSAandMGF1() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA384"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA384"));
        signHelper(WORKER13, 12, dataGroups1, false, "SHA384",
                "SHA384withRSAandMGF1");
    }

    /**
     * Requests signing of some data group hashes and verifies the result.
     * @throws Exception
     */
    public void test06SignData_SHA512withRSAandMGF1() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA512"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA512"));
        signHelper(WORKER14, 12, dataGroups1, false, "SHA512",
                "SHA512withRSAandMGF1");
    }


    private SODFile signHelper(int workerId, int requestId, Map<Integer, byte[]> dataGroups, boolean signerDoesHashing, String digestAlg, String sigAlg) throws Exception {

        // Create expected hashes
    	Map<Integer, byte[]> expectedHashes;
    	if(signerDoesHashing) {
            MessageDigest d = MessageDigest.getInstance(digestAlg, "BC");
            expectedHashes = new HashMap<Integer, byte[]>();
            for(Map.Entry<Integer, byte[]> entry : dataGroups.entrySet()) {
                expectedHashes.put(entry.getKey(), d.digest(entry.getValue()));
                d.reset();
            }
    	} else {
            expectedHashes = dataGroups;
    	}

        SODSignResponse res = (SODSignResponse) workerSession.process(workerId,
                new SODSignRequest(requestId, dataGroups),
                new RequestContext());
        assertNotNull(res);
        assertEquals(requestId, res.getRequestID());
        Certificate signercert = res.getSignerCertificate();
        assertNotNull(signercert);

        byte[] sodBytes = res.getProcessedData();
        SODFile sod = new SODFile(new ByteArrayInputStream(sodBytes));
        boolean verify = sod.checkDocSignature(signercert);
        assertTrue("Signature verification", verify);

        // Check the SOD
        Map<Integer, byte[]> actualDataGroupHashes = sod.getDataGroupHashes();
        assertEquals(expectedHashes.size(), actualDataGroupHashes.size());
        for(Map.Entry<Integer, byte[]> entry : actualDataGroupHashes.entrySet()) {
            assertTrue("DG"+entry.getKey(), Arrays.equals(expectedHashes.get(entry.getKey()), entry.getValue()));
        }
        assertEquals(digestAlg, sod.getDigestAlgorithm());
        assertEquals(sigAlg, sod.getDigestEncryptionAlgorithm());
        return sod;
    }

    private byte[] digestHelper(byte[] data, String digestAlgorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(digestAlgorithm);
        return md.digest(data);
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
            config.setProperty(NAME, "TestMRTDSODSigner1");
            config.setProperty(AUTHTYPE, "NOAUTH");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER2 - Worker7898: SHA512, default hashing setting
        {
            final int workerId = WORKER2;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner2");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DIGESTALGORITHM", "SHA512");
            config.setProperty("SIGNATUREALGORITHM", "SHA512withRSA");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER3 - Worker7899: Default algorithms, DODATAGROUPHASHING=true
        {
            final int workerId = WORKER3;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner1");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DODATAGROUPHASHING", "true");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER4 - Worker7900: SHA512, DODATAGROUPHASHING=true
        {
            final int workerId = WORKER4;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner1");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DIGESTALGORITHM", "SHA512");
            config.setProperty("SIGNATUREALGORITHM", "SHA512withRSA");
            config.setProperty("DODATAGROUPHASHING", "true");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER5 - With LDS version 1.8
        {
            final int workerId = WORKER5;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner5");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("LDSVERSION", "0108");
            config.setProperty("UNICODEVERSION", "040000");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER11
        {
            final int workerId = WORKER11;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner11");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DIGESTALGORITHM", "SHA1");
            config.setProperty("SIGNATUREALGORITHM", "SHA1withRSAandMGF1");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER12
        {
            final int workerId = WORKER12;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner12");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DIGESTALGORITHM", "SHA256");
            config.setProperty("SIGNATUREALGORITHM", "SHA256withRSAandMGF1");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER13
        {
            final int workerId = WORKER13;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner13");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DIGESTALGORITHM", "SHA384");
            config.setProperty("SIGNATUREALGORITHM", "SHA384withRSAandMGF1");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER14
        {
            final int workerId = WORKER14;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner14");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DIGESTALGORITHM", "SHA512");
            config.setProperty("SIGNATUREALGORITHM", "SHA512withRSAandMGF1");
            config.setProperty("defaultKey", HardCodedCryptoToken.KEY_ALIAS_2); // Use a larger key
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER15
        {
            final int workerId = WORKER15;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner15");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DIGESTALGORITHM", "SHA1");
            config.setProperty("SIGNATUREALGORITHM", "SHA256withRSAandMGF1");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }
    }
}
