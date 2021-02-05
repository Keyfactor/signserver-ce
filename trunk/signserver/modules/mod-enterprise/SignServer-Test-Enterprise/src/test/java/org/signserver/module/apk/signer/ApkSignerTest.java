/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.apk.signer;

import com.android.apksig.ApkVerifier;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.TimeUnit;
import javax.naming.NamingException;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.*;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.signserver.cli.CommandLineInterface;
import org.signserver.cli.spi.CommandContext;
import org.signserver.cli.spi.CommandFactoryContext;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.client.cli.ClientCLI;
import org.signserver.client.cli.defaultimpl.DocumentSigner;
import org.signserver.client.cli.defaultimpl.DocumentSignerFactory;
import org.signserver.client.cli.defaultimpl.HTTPDocumentSigner;
import org.signserver.client.cli.defaultimpl.HostManager;
import org.signserver.client.cli.defaultimpl.KeyStoreOptions;
import org.signserver.client.cli.defaultimpl.SignDocumentCommand;
import org.signserver.common.*;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.module.jarchive.signer.JArchiveSignerTest;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;

import static junit.framework.TestCase.*;

/**
 * System tests for ApkSigner.
 *
 * This tests requires a running SignServer. For standalone unit tests
 * preferably use ApkSignerUnitTest instead.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@SuppressWarnings("PMD.UnusedFormalParameter") // JUnit requires parameter in constructor
@RunWith(Parameterized.class)
public class ApkSignerTest {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ApkSignerTest.class);

    private static final int WORKER_ID_NORMAL = 8909;
    private static final String WORKER_NAME_NORMAL = "TestApkSigner";
    private static final int WORKER_ID_NORMAL2 = 8910;
    private static final String WORKER_NAME_NORMAL2 = "TestApkSigner2";
    private static final int WORKER_ID_NORMAL3 = 8911;
    private static final String WORKER_NAME_NORMAL3 = "TestApkSigner3";

    private final File apkFile;

    private static WorkerSessionRemote workerSession = getWorkerSessionS();
    private static ProcessSessionRemote processSession = getProcessSessionS();

    private static final CLITestHelper CLI = new CLITestHelper(ClientCLI.class);

    private final ModulesTestCase helper = new ModulesTestCase();

    private final boolean clientSide;
    private final String title;
    private final String workerNameNormal;
    private final String workerNameNormal2;
    private final String workerNameNormal3;

    private static long lastSize = 0;
    private final ModulesTestCase testCase = new ModulesTestCase();
    public ApkSignerTest(final boolean clientSide, final String title) throws Exception {
        this.clientSide = clientSide;
        this.title = title;

        apkFile = new File(PathUtil.getAppHome() + File.separator + "res" +
                File.separator + "test" + File.separator +
                "HelloApk.apk");
        if (!apkFile.exists()) {
            throw new Exception("Missing sample binary: " + apkFile);
        }
        this.workerNameNormal = WORKER_NAME_NORMAL  + "_" + title;
        this.workerNameNormal2 = WORKER_NAME_NORMAL2  + "_" + title;
        this.workerNameNormal3 = WORKER_NAME_NORMAL3  + "_" + title;
    }

    @Parameterized.Parameters(name = "{1}")
    public static Collection<Object[]> generateData() throws FileNotFoundException {
        final ArrayList<Object[]> data = new ArrayList<>();
        //data.add(new Object[] { true, "clientSide" } );
        data.add(new Object[] { false, "serverSide" });
        data.add(new Object[] { true, "clientSide" });
        return data;
    }
    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }
    @After
    public void tearDown() throws Exception {
        testCase.removeWorker(getWorkerId());

    }
    protected static WorkerSessionRemote getWorkerSessionS() {
        if (workerSession == null) {
            try {
                workerSession = ServiceLocator.getInstance().lookupRemote(
                        WorkerSessionRemote.class);
            } catch (NamingException ex) {
                fail("Could not lookup WorkerSession: " + ex.getMessage());
            }
        }
        return workerSession;
    }

    protected static ProcessSessionRemote getProcessSessionS() {
        if (processSession == null) {
            try {
                processSession = ServiceLocator.getInstance().lookupRemote(
                        ProcessSessionRemote.class);
            } catch (NamingException ex) {
                fail("Could not lookup WorkerSession: " + ex.getMessage());
            }
        }
        return processSession;
    }

    private void addSigner(boolean clientSide) throws Exception {
        if (clientSide) {
            helper.addApkHashSigner(WORKER_ID_NORMAL, workerNameNormal, true);
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_NORMAL,
                    "SIGNATUREALGORITHM",
                    "NONEwithRSA");
        } else {
            helper.addApkSigner(WORKER_ID_NORMAL, workerNameNormal, true);
        }
    }

    private void addSigner2(boolean clientSide) throws Exception {
        if (clientSide) {
            helper.addApkHashSigner(WORKER_ID_NORMAL2, workerNameNormal2, true);
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_NORMAL2,
                    "SIGNATUREALGORITHM",
                    "NONEwithRSA");
        } else {
            helper.addApkSigner(WORKER_ID_NORMAL2, workerNameNormal2, true);
        }
        helper.getWorkerSession().setWorkerProperty(WORKER_ID_NORMAL2,
                "DEFAULTKEY",
                helper.getSigner1KeyAlias());
    }

    private void addSigner3(boolean clientSide) throws Exception {
        if (clientSide) {
            helper.addApkHashSigner(WORKER_ID_NORMAL3, workerNameNormal3, true);
            helper.getWorkerSession().setWorkerProperty(WORKER_ID_NORMAL3,
                    "SIGNATUREALGORITHM",
                    "NONEwithECDSA");
        } else {
            helper.addApkSigner(WORKER_ID_NORMAL3, workerNameNormal3, true);
        }
        helper.getWorkerSession().setWorkerProperty(WORKER_ID_NORMAL3,
                "DEFAULTKEY", "apk00002");
    }

    private int getWorkerId() {
        return WORKER_ID_NORMAL;
    }

    private int getWorkerIdEcdsa() {
        return WORKER_ID_NORMAL3;
    }

    /**
     * Tests signing and verify the signature using an ECDSA key.
     * @throws Exception
     */
    @Test
    public void testSigning() throws Exception {
        LOG.info("testSigning");

        try {
            addSigner(clientSide);
            workerSession.reloadConfiguration(getWorkerId());

            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", null);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Tests signing and verify the signature using an ECDSA key.
     * @throws Exception
     */
    @Test
    public void testSigningExplicitFileTypeForClientSide() throws Exception {
        LOG.info("testSigning");

        Assume.assumeTrue("Setting -filetype is not relevant for server-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.reloadConfiguration(getWorkerId());

            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", null, true);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Tests signing and verify the signature.
     * @throws Exception
     */
    @Test
    public void testSigningEcdsa() throws Exception {
        LOG.info("testSigningEcdsa");

        try {
            addSigner3(clientSide);
            workerSession.reloadConfiguration(getWorkerIdEcdsa());

            signAndAssertOk(getWorkerIdEcdsa(), clientSide, true, true, true, false,
                    "APK_SIGN.EC", null);
        } finally {
            helper.removeWorker(getWorkerIdEcdsa());
        }
    }

    /**
     * Tests signing and verify the signature.
     * Disable V3 scheme.
     *
     * @throws Exception
     */
    @Test
    public void testSigningV3SignatureFalse() throws Exception {
        LOG.info("testSigningV3SignatureFalse");

        Map<String, String> metadata = null;

        try {
            addSigner(clientSide);
            if (clientSide) {
                metadata = new HashMap<>();
                metadata.put("V3_SIGNATURE", "false");
            } else {
                workerSession.setWorkerProperty(WORKER_ID_NORMAL, "V3_SIGNATURE",
                        "false");
            }
            workerSession.reloadConfiguration(getWorkerId());

            signAndAssertOk(getWorkerId(), clientSide, true, true, false, false,
                    "APK_SIGN.RSA", metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Tests signing and verify the signature.
     * Disable V2 scheme.
     *
     * @throws Exception
     */
    @Test
    public void testSigningV2SignatureFalse() throws Exception {
        LOG.info("testSigningV2SignatureFalse");

        Map<String, String> metadata = null;

        try {
            addSigner(clientSide);
            if (clientSide) {
                metadata = new HashMap<>();
                metadata.put("V2_SIGNATURE", "false");
            } else {
                workerSession.setWorkerProperty(WORKER_ID_NORMAL, "V2_SIGNATURE",
                        "false");
            }
            workerSession.reloadConfiguration(getWorkerId());

            signAndAssertOk(getWorkerId(), clientSide, true, false, true, false,
                    "APK_SIGN.RSA", metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Tests signing and verify the signature.
     * Disable V1 scheme.
     *
     * @throws Exception
     */
    @Test
    public void testSigningV1SignatureFalse() throws Exception {
        LOG.info("testSigningV1SignatureFalse");

        Map<String, String> metadata = null;

        try {
            addSigner(clientSide);
            if (clientSide) {
                metadata = new HashMap<>();
                metadata.put("V1_SIGNATURE", "false");
            } else {
                workerSession.setWorkerProperty(WORKER_ID_NORMAL, "V1_SIGNATURE",
                        "false");
            }
            workerSession.reloadConfiguration(getWorkerId());

            signAndAssertOk(getWorkerId(), clientSide, false, true, true, true,
                    null, metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Tests signing and verify the signature.
     * Only V1 scheme.
     *
     * @throws Exception
     */
    @Test
    public void testSigningOnlyV1() throws Exception {
        LOG.info("testSigningOnlyV1");

        Map<String, String> metadata = null;

        try {
            addSigner(clientSide);
            if (clientSide) {
                metadata = new HashMap<>();
                metadata.put("V1_SIGNATURE", "true");
                metadata.put("V2_SIGNATURE", "false");
                metadata.put("V3_SIGNATURE", "false");
            } else {
                workerSession.setWorkerProperty(WORKER_ID_NORMAL, "V1_SIGNATURE",
                        "true");
                workerSession.setWorkerProperty(WORKER_ID_NORMAL, "V2_SIGNATURE",
                        "false");
                workerSession.setWorkerProperty(WORKER_ID_NORMAL, "V3_SIGNATURE",
                        "false");
            }
            workerSession.reloadConfiguration(getWorkerId());

            // expect 19 bytes RSA SHA-256 padding + 32 bytes diest (SHA-256)
            signAndAssertOk(getWorkerId(), clientSide, true, false, false, false,
                    "APK_SIGN.RSA", Optional.of(32L + 19), metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Tests signing and verify the signature.
     * Only V1 scheme.
     *
     * @throws Exception
     */
    @Test
    public void testSigningOnlyV1Ecdsa() throws Exception {
        LOG.info("testSigningOnlyV1Ecdsa");

        Map<String, String> metadata = null;

        try {
            addSigner3(clientSide);
            if (clientSide) {
                metadata = new HashMap<>();
                metadata.put("V1_SIGNATURE", "true");
                metadata.put("V2_SIGNATURE", "false");
                metadata.put("V3_SIGNATURE", "false");
            } else {
                workerSession.setWorkerProperty(WORKER_ID_NORMAL3, "V1_SIGNATURE",
                        "true");
                workerSession.setWorkerProperty(WORKER_ID_NORMAL3, "V2_SIGNATURE",
                        "false");
                workerSession.setWorkerProperty(WORKER_ID_NORMAL3, "V3_SIGNATURE",
                        "false");
            }
            workerSession.reloadConfiguration(getWorkerIdEcdsa());

            // expect 32 bytes diest (SHA-256) (no padding for ECDSA)
            signAndAssertOk(getWorkerIdEcdsa(), clientSide, true, false, false, false,
                    "APK_SIGN.EC", Optional.of(32L), metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Tests signing and verify the signature.
     * Only V1 scheme with minimum SDK version 10. Should use SHA1 digest.
     *
     * @throws Exception
     */
    @Test
    public void testSigningOnlyV1MinSdk10() throws Exception {
        LOG.info("testSigningOnlyV1MinSdk10");

        Map<String, String> metadata = null;

        try {
            addSigner(clientSide);
            if (clientSide) {
                metadata = new HashMap<>();
                metadata.put("V1_SIGNATURE", "true");
                metadata.put("V2_SIGNATURE", "false");
                metadata.put("V3_SIGNATURE", "false");
                metadata.put("MIN_SDK_VERSION", "10");
            } else {
                workerSession.setWorkerProperty(WORKER_ID_NORMAL, "V1_SIGNATURE",
                        "true");
                workerSession.setWorkerProperty(WORKER_ID_NORMAL, "V2_SIGNATURE",
                        "false");
                workerSession.setWorkerProperty(WORKER_ID_NORMAL, "V3_SIGNATURE",
                        "false");
                workerSession.setWorkerProperty(WORKER_ID_NORMAL, "MIN_SDK_VERSION",
                        "10");
            }
            workerSession.reloadConfiguration(getWorkerId());

            // expect 15 bytes RSA SHA1 padding + 20 bytes diest (SHA1)
            signAndAssertOk(getWorkerId(), clientSide, true, false, false, false,
                    "APK_SIGN.RSA", Optional.of(20L + 15), metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Tests signing and verify the signature.
     * Disable V3 scheme and use two signers.
     *
     * @throws Exception
     */
    @Test
    public void testSigningTwoSignersV1andV2() throws Exception {
        LOG.info("testSigningTwoSignersV1andV2");

        Map<String, String> metadata = null;

        try {
            addSigner(clientSide); // APK00001
            addSigner2(clientSide); // signer00003
            workerSession.setWorkerProperty(WORKER_ID_NORMAL, "OTHER_SIGNERS",
                    workerNameNormal2);
            if (clientSide) {
                metadata = new HashMap<>();
                metadata.put("V3_SIGNATURE", "false");
            } else {
                workerSession.setWorkerProperty(WORKER_ID_NORMAL, "V3_SIGNATURE",
                        "false");
            }
            workerSession.reloadConfiguration(WORKER_ID_NORMAL);
            workerSession.reloadConfiguration(WORKER_ID_NORMAL2);

            signAndAssertOk(WORKER_ID_NORMAL, clientSide, true, true, false, false,
                    2, new HashSet<>(Arrays.asList("APK_SIGN.RSA", "SIGNER00.RSA")),
                    metadata);
        } finally {
            helper.removeWorker(WORKER_ID_NORMAL);
            helper.removeWorker(WORKER_ID_NORMAL2);
        }
    }

    /**
     * Tests signing and verify the signature. Use two signers.
     *
     * @throws Exception
     */
    @Test
    public void testSigningTwoSigners() throws Exception {
        LOG.info("testSigningTwoSigners");

        try {
            addSigner(clientSide); // APK00001
            addSigner2(clientSide); // signer00003
            workerSession.setWorkerProperty(WORKER_ID_NORMAL, "OTHER_SIGNERS",
                    workerNameNormal2);
            workerSession.reloadConfiguration(WORKER_ID_NORMAL);
            workerSession.reloadConfiguration(WORKER_ID_NORMAL2);

            signAndAssertOk(WORKER_ID_NORMAL, clientSide, true, true, false, false,
                    2, new HashSet<>(Arrays.asList("APK_SIGN.RSA", "SIGNER00.RSA")), null);
        } finally {
            helper.removeWorker(WORKER_ID_NORMAL);
            helper.removeWorker(WORKER_ID_NORMAL2);
        }
    }

    /**
     * Tests signing and verify the signature.
     * Disable V3 and V2 scheme and use two signers.
     *
     * @throws Exception
     */
    @Test
    public void testSigningTwoSignersV1() throws Exception {
        LOG.info("testSigningTwoSignersV1");

        Map<String, String> metadata = null;

        try {
            addSigner(clientSide); // APK00001
            addSigner2(clientSide); // signer00003
            workerSession.setWorkerProperty(WORKER_ID_NORMAL, "OTHER_SIGNERS",
                    workerNameNormal2);
            if (clientSide) {
                metadata = new HashMap<>();
                metadata.put("V3_SIGNATURE", "false");
                metadata.put("V2_SIGNATURE", "false");
            } else {
                workerSession.setWorkerProperty(WORKER_ID_NORMAL, "V3_SIGNATURE",
                        "false");
                workerSession.setWorkerProperty(WORKER_ID_NORMAL, "V2_SIGNATURE",
                        "false");
            }
            workerSession.reloadConfiguration(WORKER_ID_NORMAL);
            workerSession.reloadConfiguration(WORKER_ID_NORMAL2);

            signAndAssertOk(WORKER_ID_NORMAL, clientSide, true, false, false, false,
                    2, new HashSet<>(Arrays.asList("APK_SIGN.RSA", "SIGNER00.RSA")),
                    metadata);
        } finally {
            helper.removeWorker(WORKER_ID_NORMAL);
            helper.removeWorker(WORKER_ID_NORMAL2);
        }
    }

    /**
     * Tests signing and verify the signature.
     * Disable V3 scheme and use three signers.
     *
     * @throws Exception
     */
    @Test
    public void testSigningThreeSignersV1andV2() throws Exception {
        LOG.info("testSigningThreeSignersV1andV2");

        try {
            addSigner(clientSide); // APK00001
            addSigner2(clientSide); // signer00003
            addSigner3(clientSide); // APK00002
            workerSession.setWorkerProperty(WORKER_ID_NORMAL, "OTHER_SIGNERS",
                    " " + workerNameNormal2 + " ," + workerNameNormal3 + " ");
            workerSession.setWorkerProperty(WORKER_ID_NORMAL, "V3_SIGNATURE",
                    "false");
            workerSession.reloadConfiguration(WORKER_ID_NORMAL);
            workerSession.reloadConfiguration(WORKER_ID_NORMAL2);
            workerSession.reloadConfiguration(WORKER_ID_NORMAL3);

            signAndAssertOk(WORKER_ID_NORMAL, clientSide, true, true, false, false,
                    3, new HashSet<>(Arrays.asList("APK_SIGN.RSA", "SIGNER00.RSA", "APK_SIG2.EC")),
                    null);
        } finally {
            helper.removeWorker(WORKER_ID_NORMAL);
            helper.removeWorker(WORKER_ID_NORMAL2);
            helper.removeWorker(WORKER_ID_NORMAL3);
        }
    }

    /**
     * Tests signing and verify the signature. Use three signers.
     *
     * @throws Exception
     */
    @Test
    public void testSigningThreeSigners() throws Exception {
        LOG.info("testSigningThreeSigners");

        try {
            addSigner(clientSide); // APK00001
            addSigner2(clientSide); // signer00003
            addSigner3(clientSide); // APK00002
            workerSession.setWorkerProperty(WORKER_ID_NORMAL, "OTHER_SIGNERS",
                    " " + workerNameNormal2 + " ," + workerNameNormal3 + " ");
            workerSession.reloadConfiguration(WORKER_ID_NORMAL);
            workerSession.reloadConfiguration(WORKER_ID_NORMAL2);
            workerSession.reloadConfiguration(WORKER_ID_NORMAL3);

            signAndAssertOk(WORKER_ID_NORMAL, clientSide, true, true, false, false,
                    3, new HashSet<>(Arrays.asList("APK_SIGN.RSA", "SIGNER00.RSA", "APK_SIG2.EC")),
                    null);
        } finally {
            helper.removeWorker(WORKER_ID_NORMAL);
            helper.removeWorker(WORKER_ID_NORMAL2);
            helper.removeWorker(WORKER_ID_NORMAL3);
        }
    }

    /**
     * Tests signing and verify the signature.
     * Disable V3 scheme and use three+1 signers.
     *
     * @throws Exception
     */
    @Test
    public void testSigningFourSignersV1andV2() throws Exception {
        LOG.info("testSigningFourSignersV1andV2");

        try {
            addSigner(clientSide); // APK00001
            addSigner2(clientSide); // signer00003
            addSigner3(clientSide); // APK00002
            workerSession.setWorkerProperty(WORKER_ID_NORMAL, "OTHER_SIGNERS",
                    " " + workerNameNormal2 + " ," + workerNameNormal3 + ", " + workerNameNormal2);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL, "V3_SIGNATURE",
                    "false");
            workerSession.reloadConfiguration(WORKER_ID_NORMAL);
            workerSession.reloadConfiguration(WORKER_ID_NORMAL2);
            workerSession.reloadConfiguration(WORKER_ID_NORMAL3);

            signAndAssertOk(WORKER_ID_NORMAL, clientSide, true, true, false, false,
                    4, new HashSet<>(Arrays.asList("APK_SIGN.RSA", "SIGNER00.RSA", "APK_SIG2.EC", "SIGNER02.RSA")),
                    null);
        } finally {
            helper.removeWorker(WORKER_ID_NORMAL);
            helper.removeWorker(WORKER_ID_NORMAL2);
            helper.removeWorker(WORKER_ID_NORMAL3);
        }
    }

    /**
     * Tests signing and verify the signature.
     * Disable V3 scheme and use 2+1 signers and configure a signature name.
     *
     * @throws Exception
     */
    @Test
    public void testSigningThreeSignersV1andV2_V1SignatureName() throws Exception {
        LOG.info("testSigningThreeSignersV1andV2_V1SignatureName");

        Map<String, String> metadata = null;

        try {
            addSigner(clientSide); // APK00001
            addSigner2(clientSide); // signer00003
            workerSession.setWorkerProperty(WORKER_ID_NORMAL, "OTHER_SIGNERS",
                    " " + workerNameNormal2 + " ," + workerNameNormal2);
            if (clientSide) {
                metadata = new HashMap<>();
                metadata.put("V3_SIGNATURE", "false");
                metadata.put("V1_SIGNATURE_NAME", "custom2");
            } else {
                workerSession.setWorkerProperty(WORKER_ID_NORMAL, "V3_SIGNATURE",
                        "false");
                workerSession.setWorkerProperty(WORKER_ID_NORMAL, "V1_SIGNATURE_NAME",
                        "custom2");
            }
            workerSession.reloadConfiguration(WORKER_ID_NORMAL);
            workerSession.reloadConfiguration(WORKER_ID_NORMAL2);
            workerSession.reloadConfiguration(WORKER_ID_NORMAL3);

            signAndAssertOk(WORKER_ID_NORMAL, clientSide, true, true, false, false,
                    3, new HashSet<>(Arrays.asList("CUSTOM2.RSA", "CUSTOM22.RSA", "CUSTOM23.RSA")),
                    metadata);
        } finally {
            helper.removeWorker(WORKER_ID_NORMAL);
            helper.removeWorker(WORKER_ID_NORMAL2);
            helper.removeWorker(WORKER_ID_NORMAL3);
        }
    }


    /**
     * Tests signing and verify the signature.
     * Setting a custom V1 signature name.
     *
     * @throws Exception
     */
    @Test
    public void testSigningV1SignatureName() throws Exception {
        LOG.info("testSigningV1SignatureName");

        Map<String, String> metadata = null;

        try {
            addSigner(clientSide);
            if (clientSide) {
                metadata = new HashMap<>();
                metadata.put("V1_SIGNATURE_NAME", "custom");
            } else {
                workerSession.setWorkerProperty(WORKER_ID_NORMAL, "V1_SIGNATURE_NAME",
                        "custom");
            }
            workerSession.reloadConfiguration(getWorkerId());

            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "CUSTOM.RSA", metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Tests signing and verify the signature.
     * Overriding disabling V1_SIGNATURE in the request.
     *
     * @throws Exception
     */
    @Test
    public void testSigningV1SignatureOverrideFalse() throws Exception {
        LOG.info("testSigningV1SignatureOverrideFalse");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL,
                    "ALLOW_V1_SIGNATURE_OVERRIDE",
                    "true");
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("V1_SIGNATURE", "false");
            signAndAssertOk(getWorkerId(), clientSide, false, true, true, true,
                    null, metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Tests signing and verify the signature.
     * Overriding disabling V2_SIGNATURE in the request.
     *
     * @throws Exception
     */
    @Test
    public void testSigningV2SignatureOverrideFalse() throws Exception {
        LOG.info("testSigningV2SignatureOverrideFalse");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL,
                    "ALLOW_V2_SIGNATURE_OVERRIDE",
                    "true");
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("V2_SIGNATURE", "false");
            signAndAssertOk(getWorkerId(), clientSide, true, false, true, false,
                    "APK_SIGN.RSA", metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Tests signing and verify the signature.
     * Overriding disabling V3_SIGNATURE in the request.
     *
     * @throws Exception
     */
    @Test
    public void testSigningV3SignatureOverrideFalse() throws Exception {
        LOG.info("testSigningV3SignatureOverrideFalse");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL,
                    "ALLOW_V3_SIGNATURE_OVERRIDE",
                    "true");
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("V3_SIGNATURE", "false");
            signAndAssertOk(getWorkerId(), clientSide, true, true, false, false,
                    "APK_SIGN.RSA", metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test overriding V1_SIGNATURE_NAME from the client.
     *
     * @throws Exception
     */
    @Test
    public void testSigningV1SignatureNameOverride() throws Exception {
        LOG.info("testSigningV1SignatureNameOverrideFalse");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL,
                    "ALLOW_V1_SIGNATURE_NAME_OVERRIDE",
                    "true");
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("V1_SIGNATURE_NAME", "custom");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "CUSTOM.RSA", metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test that overriding V1_SIGNATURE works when overriding with the same
     * value as configured, even when not explicitly allowed.
     *
     * @throws Exception
     */
    @Test
    public void testV1SignatureOverrideExplicit() throws Exception {
        LOG.info("testV1SignatureOverrideExplicit");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL,
                    "V1_SIGNATURE",
                    "true");
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("V1_SIGNATURE", "true");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test that overriding V2_SIGNATURE works when overriding with the same
     * value as configured, even when not explicitly allowed.
     *
     * @throws Exception
     */
    @Test
    public void testV2SignatureOverrideExplicit() throws Exception {
        LOG.info("testV2SignatureOverrideExplicit");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL,
                    "V2_SIGNATURE",
                    "true");
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("V2_SIGNATURE", "true");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test that overriding V3_SIGNATURE works when overriding with the same
     * value as configured, even when not explicitly allowed.
     *
     * @throws Exception
     */
    @Test
    public void testV3SignatureOverrideExplicit() throws Exception {
        LOG.info("testV3SignatureOverrideExplicit");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL,
                    "V3_SIGNATURE",
                    "true");
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("V3_SIGNATURE", "true");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test that by default overriding V1_SIGNATURE in the request is not allowed.
     *
     * @throws Exception
     */
    @Test
    public void testV1SignatureOverrideNotAllowed() throws Exception {
        LOG.info("testV1SignatureOverrideNotAllowed");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("V1_SIGNATURE", "true");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", metadata);
            fail("Should throw IllegalRequestException");
        } catch (IllegalRequestException ex) { // NOPMD
            // expected
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test that by default overriding V2_SIGNATURE in the request is not allowed.
     *
     * @throws Exception
     */
    @Test
    public void testV2SignatureOverrideNotAllowed() throws Exception {
        LOG.info("testV2SignatureOverrideNotAllowed");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("V2_SIGNATURE", "true");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", metadata);
            fail("Should throw IllegalRequestException");
        } catch (IllegalRequestException ex) { // NOPMD
            // expected
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test that by default overriding V3_SIGNATURE in the request is not allowed.
     *
     * @throws Exception
     */
    @Test
    public void testV3SignatureOverrideNotAllowed() throws Exception {
        LOG.info("testV3SignatureOverrideNotAllowed");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("V3_SIGNATURE", "true");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", metadata);
            fail("Should throw IllegalRequestException");
        } catch (IllegalRequestException ex) { // NOPMD
            // expected
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test setting MIN_SDK_VERSION to a value acceptable for the sample APK.
     *
     * @throws Exception
     */
    @Test
    public void testMinSDKVersion() throws Exception {
        LOG.info("testMinSDKVersion");

        Map<String, String> metadata = null;

        try {
            addSigner(clientSide);
            if (clientSide) {
                metadata = new HashMap<>();
                metadata.put("MIN_SDK_VERSION", "23");
            } else {
                workerSession.setWorkerProperty(WORKER_ID_NORMAL,
                        "MIN_SDK_VERSION", "23");
            }
            workerSession.reloadConfiguration(getWorkerId());

            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test overriding MIN_SDK_VERSION to a value acceptable for the sample APK.
     *
     * @throws Exception
     */
    @Test
    public void testMinSDKVersionOverride() throws Exception {
        LOG.info("testMinSDKVersionOverride");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL,
                    "ALLOW_MIN_SDK_VERSION_OVERRIDE",
                    "true");
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("MIN_SDK_VERSION", "23");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test overriding MIN_SDK_VERSION not allowed.
     *
     * @throws Exception
     */
    @Test
    public void testMinSDKVersionOverrideNotAllowed() throws Exception {
        LOG.info("testMinSDKVersionOverrideNotAllowed");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("MIN_SDK_VERSION", "23");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    null, metadata);
            fail("Should throw IllegalRequestException");
        } catch (IllegalRequestException ex) { // NOPMD
            // expected
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test overriding MIN_SDK_VERSION with the same value as configured
     * not explicitly allowing override, should work.
     *
     * @throws Exception
     */
    @Test
    public void testMinSDKVersionOverrideExplicit() throws Exception {
        LOG.info("testMinSDKVersionOverrideExplicit");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL, "MIN_SDK_VERSION",
                    "23");
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("MIN_SDK_VERSION", "23");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test overriding MIN_SDK_VERSION with an illegal value.
     *
     * @throws Exception
     */
    @Test
    public void testMinSDKVersionOverrideIllegalValue() throws Exception {
        LOG.info("testMinSDKVersionOverrideIllegalValue");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL,
                    "ALLOW_MIN_SDK_VERSION_OVERRIDE",
                    "true");
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("MIN_SDK_VERSION", "illegal");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", metadata);
            fail("Should fail");
        } catch (IllegalRequestException e) {
            assertEquals("Exception message",
                    "Illegal value for MIN_SDK_VERSION in request: illegal",
                    e.getMessage());
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test overriding MIN_SDK_VERSION with a negative value.
     *
     * @throws Exception
     */
    @Test
    public void testMinSDKVersionOverrideNegativeValue() throws Exception {
        LOG.info("testMinSDKVersionOverrideNegativeValue");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL,
                    "ALLOW_MIN_SDK_VERSION_OVERRIDE",
                    "true");
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("MIN_SDK_VERSION", "-1");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", metadata);
            fail("Should fail");
        } catch (IllegalRequestException e) {
            assertEquals("Exception message",
                    "Illegal value for MIN_SDK_VERSION in request: -1",
                    e.getMessage());
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test setting MAX_SDK_VERSION to a value acceptable for the sample APK.
     *
     * @throws Exception
     */
    @Test
    public void testMaxSDKVersion() throws Exception {
        LOG.info("testMaxSDKVersion");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL,
                    "MAX_SDK_VERSION", "29");
            workerSession.reloadConfiguration(getWorkerId());

            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", null);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test overriding MAX_SDK_VERSION not allowed.
     *
     * @throws Exception
     */
    @Test
    public void testMaxSDKVersionOverrideNotAllowed() throws Exception {
        LOG.info("testMaxSDKVersionOverrideNotAllowed");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("MAX_SDK_VERSION", "29");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    null, metadata);
            fail("Should throw IllegalRequestException");
        } catch (IllegalRequestException ex) { // NOPMD
            // expected
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test overriding MAX_SDK_VERSION with the same value as configured
     * not explicitly allowing override, should work.
     *
     * @throws Exception
     */
    @Test
    public void testMaxSDKVersionOverrideExplicit() throws Exception {
        LOG.info("testMaxSDKVersionOverrideExplicit");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL, "MAX_SDK_VERSION",
                    "29");
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("MAX_SDK_VERSION", "29");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test overriding MAX_SDK_VERSION with an illegal value.
     *
     * @throws Exception
     */
    @Test
    public void testMaxSDKVersionOverrideIllegalValue() throws Exception {
        LOG.info("testMaxSDKVersionOverrideIllegalValue");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL,
                    "ALLOW_MAX_SDK_VERSION_OVERRIDE",
                    "true");
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("MAX_SDK_VERSION", "illegal");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", metadata);
            fail("Should fail");
        } catch (IllegalRequestException e) {
            assertEquals("Exception message",
                    "Illegal value for MAX_SDK_VERSION in request: illegal",
                    e.getMessage());
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test overriding MAX_SDK_VERSION with a negative value.
     *
     * @throws Exception
     */
    @Test
    public void testMaxSDKVersionOverrideNegativeValue() throws Exception {
        LOG.info("testMaxSDKVersionOverrideNegativeValue");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL,
                    "ALLOW_MAX_SDK_VERSION_OVERRIDE",
                    "true");
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("MAX_SDK_VERSION", "-1");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", metadata);
            fail("Should fail");
        } catch (IllegalRequestException e) {
            assertEquals("Exception message",
                    "Illegal value for MAX_SDK_VERSION in request: -1",
                    e.getMessage());
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test setting DEBUGGABLE_APK_PERMITTED to true.
     *
     * @throws Exception
     */
    @Test
    public void testDebuggableApkPermittedTrue() throws Exception {
        LOG.info("testDebuggableApkPermittedTrue");

        Map<String, String> metadata = null;

        try {
            addSigner(clientSide);
            if (clientSide) {
                metadata = new HashMap<>();
                metadata.put("DEBUGGABLE_APK_PERMITTED", "true");
            } else {
                workerSession.setWorkerProperty(WORKER_ID_NORMAL,
                        "DEBUGGABLE_APK_PERMITTED", "true");
            }
            workerSession.reloadConfiguration(getWorkerId());

            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test overriding DEBUGGABLE_APK_PERMITTED not allowed.
     *
     * @throws Exception
     */
    @Test
    public void testDebuggableApkPermittedOverrideNotAllowed() throws Exception {
        LOG.info("testDebuggableApkPermittedOverrideNotAllowed");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("DEBUGGABLE_APK_PERMITTED", "true");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    null, metadata);
            fail("Should throw IllegalRequestException");
        } catch (IllegalRequestException ex) { // NOPMD
            // expected
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test overriding DEBUGGABLE_APK_PERMITTED with the same value as configured
     * not explicitly allowing override, should work.
     *
     * @throws Exception
     */
    @Test
    public void testDebuggableApkPermittedOverrideExplicit() throws Exception {
        LOG.info("testDebuggableApkPermittedOverrideExplicit");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL,
                    "DEBUGGABLE_APK_PERMITTED", "true");
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("DEBUGGABLE_APK_PERMITTED", "true");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", metadata);
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Test overriding DEBUGGABLE_APK_PERMITTED with an illegal value.
     *
     * @throws Exception
     */
    @Test
    public void testDebuggableApkPermittedOverrideIllegalValue() throws Exception {
        LOG.info("testDebuggableApkPermittedOverrideIllegalValue");

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);
            workerSession.setWorkerProperty(WORKER_ID_NORMAL,
                    "ALLOW_DEBUGGABLE_APK_PERMITTEDs_OVERRIDE",
                    "true");
            workerSession.reloadConfiguration(getWorkerId());

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("DEBUGGABLE_APK_PERMITTED", "illegal");
            signAndAssertOk(getWorkerId(), clientSide, true, true, true, false,
                    "APK_SIGN.RSA", metadata);
            fail("Should fail");
        } catch (IllegalRequestException e) {
            assertEquals("Exception message",
                    "Illegal value for DEBUGGABLE_APK_PERMITTED in request: illegal",
                    e.getMessage());
        } finally {
            helper.removeWorker(getWorkerId());
        }
    }

    /**
     * Tests signing and verify the signature using an RSA key self signed certificate.
     * @throws Exception
     */
    @Test
    public void testSigningWithSelfSignedCert() throws Exception {
        LOG.info("testSigningWithSelfSignedCert");

        int workerId = getWorkerId();
        String key = "testKey";

        Assume.assumeFalse("Request metadata override is not relevant for client-side",
                clientSide);

        try {
            addSigner(clientSide);

            workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", key, "foo123".toCharArray());
            workerSession.setWorkerProperty(workerId, "DEFAULTKEY", key);
            workerSession.setWorkerProperty(workerId, "SIGNATUREALGORITHM", "NONEwithRSA");
            workerSession.reloadConfiguration(workerId);

            // Generate CSR
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=APK_SIGN.RSA", null);
            AbstractCertReqData reqData = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

            // Issue certificate
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
            KeyPair issuerKeyPair = CryptoUtils.generateRSA(1024);
            X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

            // Install certificate and chain
            workerSession.uploadSignerCertificate(workerId, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(workerId, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(workerId);

            signAndAssertOk(workerId, clientSide, true, true, true, false,
                    "APK_SIGN.RSA", null);

        } finally {
            workerSession.removeKey(new WorkerIdentifier(workerId), key);
        }
    }

    private void signAndAssertOk(final int workerId, final boolean clientSide,
                                 final boolean expectV1, final boolean expectV2,
                                 final boolean expectV3,
                                 final boolean expectNotVerified,
                                 final String expectedV1SignatureName,
                                 final Map<String, String> metadata) throws Exception {
        final HashSet<String> expectedV1SigntureNames = new HashSet<>();
        if (expectedV1SignatureName != null) {
            expectedV1SigntureNames.add(expectedV1SignatureName);
        }
        signAndAssertOk(workerId, clientSide, expectV1, expectV2, expectV3,
                expectNotVerified, 1, expectedV1SigntureNames,
                Optional.empty(), metadata);
    }

    private void signAndAssertOk(final int workerId, final boolean clientSide,
                                 final boolean expectV1, final boolean expectV2,
                                 final boolean expectV3,
                                 final boolean expectNotVerified,
                                 final String expectedV1SignatureName,
                                 final Map<String, String> metadata,
                                 final boolean explicitFileType) throws Exception {
        final HashSet<String> expectedV1SigntureNames = new HashSet<>();
        if (expectedV1SignatureName != null) {
            expectedV1SigntureNames.add(expectedV1SignatureName);
        }
        signAndAssertOk(FileUtils.readFileToByteArray(apkFile),
                workerId, clientSide, expectV1, expectV2, expectV3,
                expectNotVerified, 1, expectedV1SigntureNames,
                Optional.empty(), metadata, explicitFileType);
    }

    private void signAndAssertOk(final int workerId, final boolean clientSide,
                                 final boolean expectV1, final boolean expectV2,
                                 final boolean expectV3,
                                 final boolean expectNotVerified,
                                 final String expectedV1SignatureName,
                                 final Optional<Long> expectedSize,
                                 final Map<String, String> metadata) throws Exception {
        final HashSet<String> expectedV1SigntureNames = new HashSet<>();
        if (expectedV1SignatureName != null) {
            expectedV1SigntureNames.add(expectedV1SignatureName);
        }
        signAndAssertOk(workerId, clientSide, expectV1, expectV2, expectV3,
                expectNotVerified, 1, expectedV1SigntureNames,
                expectedSize, metadata);
    }

    private void signAndAssertOk(final int workerId, final boolean clientSide,
                                 final boolean expectV1, final boolean expectV2,
                                 final boolean expectV3,
                                 final boolean expectNotVerified,
                                 final int expectedNumberOfSigners,
                                 final HashSet<String> expectedV1SignatureNames,
                                 final Map<String, String> metadata) throws Exception {
        signAndAssertOk(FileUtils.readFileToByteArray(apkFile), workerId,
                clientSide, expectV1,
                expectV2, expectV3,
                expectNotVerified,
                expectedNumberOfSigners,
                expectedV1SignatureNames,
                Optional.empty(),
                metadata, false);
    }

    private void signAndAssertOk(final int workerId, final boolean clientSide,
                                 final boolean expectV1, final boolean expectV2,
                                 final boolean expectV3,
                                 final boolean expectNotVerified,
                                 final int expectedNumberOfSigners,
                                 final HashSet<String> expectedV1SignatureNames,
                                 final Optional<Long> expectedSize,
                                 final Map<String, String> metadata) throws Exception {
        signAndAssertOk(FileUtils.readFileToByteArray(apkFile), workerId,
                clientSide, expectV1,
                expectV2, expectV3,
                expectNotVerified,
                expectedNumberOfSigners,
                expectedV1SignatureNames,
                expectedSize,
                metadata, false);
    }

    public static byte[] signAndAssertOk(final byte[] sampleFile,
                                         final int workerId,
                                         final boolean clientSide,
                                         final boolean expectV1,
                                         final boolean expectV2,
                                         final boolean expectV3,
                                         final boolean expectNotVerified,
                                         final int expectedNumberOfSigners,
                                         final HashSet<String> expectedV1SignatureNames,
                                         final Map<String, String> metadata)
            throws Exception {
        return signAndAssertOk(sampleFile, workerId, clientSide, expectV1,
                expectV2, expectV3, expectNotVerified,
                expectedNumberOfSigners, expectedV1SignatureNames,
                Optional.empty(), metadata, false);
    }

    /**
     * Submits the APK (as byte array) to the signer and
     * then checks that the signature seems to be made by the right signer etc.
     *
     * @param sampleFile binary to sign
     * @param workerId JArchiveSigner
     * @param clientSide True to use client-side hashing
     * @param expectV1 Expect result to be signed with V1 signature scheme
     * @param expectV2 Expect result to be signed with V2 signature scheme
     * @param expectV3 Expect result to be signed with V3 signature scheme
     * @param expectNotVerified If true, don't expect overall verified result,
     *                         to allow checking individual scheme verification
     *                         for sample APK with low minimum SDK that requires
     *                         V1 signature to be overall verified
     * @param expectedNumberOfSigners The number of expected signers
     * @param expectedV1SignatureNames If not null, expect to find exactly this V1 signature names in the file
     * @param expectedSize Expected size message sent (only applicable/useable for clientSide with one request)
     * @param metadata Additional client metadata to send, when using clientside, these will map to -extraoptionS
     * @param explicitFileType If true, and clientSide is true, include an explicit -filetype APK argument in command
     * @return the signed binary
     * @throws Exception
     */
    public static byte[] signAndAssertOk(final byte[] sampleFile,
                                         final int workerId,
                                         final boolean clientSide,
                                         final boolean expectV1,
                                         final boolean expectV2,
                                         final boolean expectV3,
                                         final boolean expectNotVerified,
                                         final int expectedNumberOfSigners,
                                         final HashSet<String> expectedV1SignatureNames,
                                         final Optional<Long> expectedSize,
                                         final Map<String, String> metadata,
                                         final boolean explicitFileType)
            throws Exception {
        byte[] signedBinary;
        File signedFile = null;

        try {
            if (clientSide) {
                // call the CLI
                File inputFile = File.createTempFile("test-file", ".original");
                FileUtils.writeByteArrayToFile(inputFile, sampleFile);
                signedFile = File.createTempFile("test-file", ".signed");
                final List<String> args =
                        new ArrayList<String>(Arrays.asList(
                                "signdocument", "-workerid",
                                Integer.toString(workerId), "-clientside",
                                "-infile", inputFile.getAbsolutePath(),
                                "-outfile", signedFile.getAbsolutePath(),
                                "-digestalgorithm", "SHA-1"));
                if (metadata != null) {
                    for (final String option : metadata.keySet()) {
                        final String value = metadata.get(option);

                        args.add("-extraoption");
                        args.add(option + "=" + value);
                    }
                }

                if (explicitFileType) {
                    args.add("-filetype");
                    args.add("APK");
                }

                assertEquals("Status code", CommandLineInterface.RETURN_SUCCESS,
                        execute(args.toArray(new String[args.size()])));
                signedBinary = FileUtils.readFileToByteArray(signedFile);

                if (expectedSize.isPresent()) {
                    assertEquals("Request size", expectedSize.get().longValue(),
                            lastSize);
                }
            } else {
                final GenericSignRequest request = new GenericSignRequest(200, sampleFile);
                final RemoteRequestContext context = new RemoteRequestContext();

                if (metadata != null) {
                    final RequestMetadata requestMetadata = new RequestMetadata();

                    metadata.keySet().forEach((key) -> {
                        requestMetadata.put(key, metadata.get(key));
                    });

                    context.setMetadata(requestMetadata);
                }

                GenericSignResponse response = (GenericSignResponse) processSession.process(new WorkerIdentifier(workerId), request, context);

                signedBinary = response.getProcessedData();
                signedFile = File.createTempFile("test-file", ".signed");
                FileUtils.writeByteArrayToFile(signedFile, signedBinary);
            }

            ApkVerifier.Builder apkVerifierBuilder = new ApkVerifier.Builder(signedFile);

            ApkVerifier apkVerifier = apkVerifierBuilder.build();
            ApkVerifier.Result result = apkVerifier.verify();

            boolean verified = result.isVerified();

            if (verified || expectNotVerified) {
                List<X509Certificate> signerCerts = result.getSignerCertificates();

                assertEquals("Signed with V1", expectV1,
                        result.isVerifiedUsingV1Scheme());
                assertEquals("Signed with V2", expectV2,
                        result.isVerifiedUsingV2Scheme());
                assertEquals("Signed with V3", expectV3,
                        result.isVerifiedUsingV3Scheme());
                List<ApkVerifier.Result.V1SchemeSignerInfo> v1SchemeSigners = result.getV1SchemeSigners();

                if (expectedV1SignatureNames != null) {
                    Set<String> foundNames = new HashSet<>();

                    v1SchemeSigners.forEach((v1SchemeSigner) -> {
                        foundNames.add(v1SchemeSigner.getName());
                    });

                    assertEquals("V1 signature names", expectedV1SignatureNames,
                            foundNames);
                }

                if (expectNotVerified) {
                    assertEquals("Number of signers", 0, signerCerts.size());
                }

                if (expectV1) {
                    assertEquals("Number of V1 signers", expectedNumberOfSigners, result.getV1SchemeSigners().size());
                }
                if (expectV2) {
                    assertEquals("Number of V2 signers", expectedNumberOfSigners, result.getV2SchemeSigners().size());
                }
                if (expectV3) {
                    assertEquals("Number of V3 signers", expectedNumberOfSigners, result.getV3SchemeSigners().size());
                }

            } else {
                LOG.error("Errors: " + result.getWarnings());
                LOG.error("Warnings: " + result.getWarnings());

                for (ApkVerifier.Result.V1SchemeSignerInfo signer : result.getV1SchemeIgnoredSigners()) {
                    LOG.error("Ignored V1 signer " + signer.getName() + " Errors: " + signer.getErrors());
                    LOG.error("Ignored V1 signer " + signer.getName() + " Warnings: " + signer.getWarnings());
                }

                LOG.error("V1 signers: " + result.getV1SchemeSigners().size());
                for (ApkVerifier.Result.V1SchemeSignerInfo signer : result.getV1SchemeSigners()) {
                    LOG.error("V1 signer " + signer.getName() + " Errors: " + signer.getErrors());
                    LOG.error("V1 signer " + signer.getName() + " Warnings: " + signer.getWarnings());
                }

                LOG.error("V2 signers: " + result.getV2SchemeSigners().size());
                for (ApkVerifier.Result.V2SchemeSignerInfo signer : result.getV2SchemeSigners()) {
                    LOG.error("V2 signer " + signer.getIndex() + " Errors: " + signer.getErrors());
                    LOG.error("V2 signer " + signer.getIndex() + " Warnings: " + signer.getWarnings());
                }

                LOG.error("V3 signers: " + result.getV3SchemeSigners().size());
                for (ApkVerifier.Result.V3SchemeSignerInfo signer : result.getV3SchemeSigners()) {
                    LOG.error("V3 signer " + signer.getIndex() + " Errors: " + signer.getErrors());
                    LOG.error("V3 signer " + signer.getIndex() + " Warnings: " + signer.getWarnings());
                }

                // Fallback to do our JAR signature verification to see if the 
                // failure is generic for jar signing or an ApkSigner/Verifier issue.
                JArchiveSignerTest.assertJarSignatureOk(signedFile);

                fail("DOES NOT VERIFY: " + result.getErrors());
            }

            return signedBinary;
        } finally {
            if (signedFile != null) {
                signedFile.delete();
            }
        }
    }

    private static int execute(String... args) throws IOException, IllegalCommandArgumentsException, CommandFailureException {
        return execute(new ApkSignerTestSignDocumentCommand(), args);
    }

    private static int execute(SignDocumentCommand instance, String... args) throws IOException, IllegalCommandArgumentsException, CommandFailureException {
        int result = -1;
        final PrintStream origOut = System.out;
        final PrintStream origErr = System.err;

        final ByteArrayOutputStream bStdOut = new ByteArrayOutputStream();
        final PrintStream stdOut = new PrintStream(bStdOut);
        System.setOut(stdOut);

        final ByteArrayOutputStream bErrOut = new ByteArrayOutputStream();
        final PrintStream errOut = new PrintStream(bErrOut);
        System.setErr(errOut);

        instance.init(new CommandContext("group1", "signdocument", new CommandFactoryContext(new Properties(), stdOut, errOut)));
        try {
            result = instance.execute(args);
        } catch (Exception e) {
            LOG.error("Failed executing command", e);
            throw e;
        } finally {
            System.setOut(origOut);
            System.setErr(origErr);
            System.out.write(result);

            byte[] error = bErrOut.toByteArray();
            System.err.write(error);
        }
        return result;
    }

    /**
     * Mock implementation of SignDocumentCommand to be used by tests requiring
     * the use of the mock document signer to instrument the size of the sent
     * message.
     */
    private static class ApkSignerTestSignDocumentCommand extends SignDocumentCommand {

        @Override
        protected DocumentSignerFactory createDocumentSignerFactory(Protocol protocol, KeyStoreOptions keyStoreOptions, String host, String servlet, Integer port, String digestAlgorithm, String username, String currentPassword, String accessToken, String pdfPassword, HostManager hostsManager, int timeoutLimit) {
            return new ApkSignerTestDocumentSignerFactory(protocol,
                    keyStoreOptions, host,
                    servlet, port,
                    digestAlgorithm,
                    username,
                    currentPassword,
                    accessToken,
                    pdfPassword,
                    hostsManager,
                    timeoutLimit);
        }
    }

    /**
     * Mock implementation of DocumentSignerFactory generating mocked HTTPDocumentSignerS
     * recording the size of the last sent message. Will only implement the HTPP
     * protocol case.
     */
    private static class ApkSignerTestDocumentSignerFactory extends DocumentSignerFactory {

        private final String digestAlgorithm;
        private final String servlet;
        private final HostManager hostsManager;
        private final Integer port;
        private final String username;
        private final String currentPassword;
        private final String accessToken;
        private final int timeOutLimit;

        public ApkSignerTestDocumentSignerFactory(final SignDocumentCommand.Protocol protocol,
                                                  final KeyStoreOptions keyStoreOptions,
                                                  final String host,
                                                  final String servlet,
                                                  final Integer port,
                                                  final String digestAlgorithm,
                                                  final String username,
                                                  final String currentPassword,
                                                  final String accessToken,
                                                  final String pdfPassword,
                                                  final HostManager hostsManager,
                                                  final int timeOutLimit) {
            super(protocol, keyStoreOptions, host, servlet, port,
                    digestAlgorithm, username, currentPassword, accessToken,
                    pdfPassword,
                    hostsManager, timeOutLimit);
            this.digestAlgorithm = digestAlgorithm;
            this.servlet = servlet;
            this.hostsManager = hostsManager;
            this.port = port;
            this.username = username;
            this.currentPassword = currentPassword;
            this.accessToken = accessToken;
            this.timeOutLimit = timeOutLimit;
        }

        @Override
        public DocumentSigner createSigner(String workerName, Map<String, String> metadata, boolean clientSide, boolean isSignatureInputHash, String typeId) {
            if (clientSide) {
                if (isSignatureInputHash) {
                    metadata.put("USING_CLIENTSUPPLIED_HASH", "true");
                }
                metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", digestAlgorithm);
            }

            if (typeId != null) {
                metadata.put("FILE_TYPE", typeId);
            }
            return new ApkSignerTestHTTPDocumentSigner(hostsManager, port,
                    servlet, false,
                    workerName, username,
                    currentPassword,
                    accessToken, null,
                    metadata, timeOutLimit);
        }

        @Override
        public DocumentSigner createSigner(int workerId, Map<String, String> metadata, boolean clientSide, boolean isSignatureInputHash, String typeId) {
            if (clientSide) {
                if (isSignatureInputHash) {
                    metadata.put("USING_CLIENTSUPPLIED_HASH", "true");
                }
                metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", digestAlgorithm);
            }

            if (typeId != null) {
                metadata.put("FILE_TYPE", typeId);
            }
            return new ApkSignerTestHTTPDocumentSigner(hostsManager, port,
                    servlet, false,
                    workerId, username,
                    currentPassword,
                    accessToken, null,
                    metadata, timeOutLimit);
        }



    }

    /**
     * Mock implementation of HTTPDocumentSigner that records the size of
     * the last sent messge. Used by tests checking the expected hashed
     * and padded message is sent from the client.
     */
    private static final class ApkSignerTestHTTPDocumentSigner extends HTTPDocumentSigner {

        public ApkSignerTestHTTPDocumentSigner(HostManager hostsManager,
                                               Integer port,
                                               String servlet,
                                               boolean useHTTPS,
                                               String workerName,
                                               String username,
                                               String password,
                                               String accessToken,
                                               String pdfPassword,
                                               Map<String, String> metadata,
                                               int timeOutLimit) {
            super(hostsManager, port != null ? port : KeyStoreOptions.DEFAULT_HTTP_PORT,
                    servlet, useHTTPS, workerName, username, password, accessToken,
                    pdfPassword, metadata, timeOutLimit);
        }

        public ApkSignerTestHTTPDocumentSigner(HostManager hostsManager,
                                               Integer port,
                                               String servlet,
                                               boolean useHTTPS,
                                               int workerId,
                                               String username,
                                               String password,
                                               String accessToken,
                                               String pdfPassword,
                                               Map<String, String> metadata,
                                               int timeOutLimit) {
            super(hostsManager, port != null ? port : KeyStoreOptions.DEFAULT_HTTP_PORT,
                    servlet, useHTTPS, workerId, username, password, accessToken,
                    pdfPassword, metadata, timeOutLimit);
        }

        @Override
        protected void doSign(InputStream in, long size, String encoding, OutputStream out, Map<String, Object> requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException {
            ApkSignerTest.lastSize = size;
            super.doSign(in, size, encoding, out, requestContext);
            LOG.info("doSign, size: " + size);
        }
    }
}
