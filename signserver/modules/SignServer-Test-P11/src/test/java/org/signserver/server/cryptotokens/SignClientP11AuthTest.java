/** ***********************************************************************
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
 ************************************************************************ */
package org.signserver.server.cryptotokens;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import static junit.framework.TestCase.assertEquals;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.util.CertTools;
import org.junit.Assert;
import static org.junit.Assert.assertTrue;
import org.junit.Assume;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runners.MethodSorters;
import org.signserver.admin.cli.AdminCLI;
import org.signserver.common.AbstractCertReqData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ComplianceTestUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * Test signing with Client CLI using authentication key in PKCS11 keystore.
 *
 * @author Vinay Singh
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SignClientP11AuthTest {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(SignClientP11AuthTest.class);

    private static final int CRYPTO_TOKEN_ID = 40100;

    private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenP11Auth";
    private static final int WORKER_PLAIN = 40020;
    private static final String TEST_AUTH_KEY = "testAuthKey";
    private static final String TEST_AUTH_ALT_KEY = "testAuthKeyAlt";

    private final String sharedLibraryName;
    private final String sharedLibraryPath;
    private final String slot;
    private final String slotIndex;
    private final String pin;
    private final String existingKey1;

    private final ModulesTestCase testCase = new ModulesTestCase();
    private final WorkerSession workerSession = testCase.getWorkerSession();
    
    private final CLITestHelper adminCLI = new CLITestHelper(AdminCLI.class);    
    
    private final String ISSUER_DN = "CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE";
    private final String DESCRIPTION = "Test auth client";
    
    private final String AUTH_KEY_CERT_CN = "Worker" + CRYPTO_TOKEN_ID + "P11Auth";
    private final String AUTH_KEY_ALT_CERT_CN = "Worker" + CRYPTO_TOKEN_ID + "P11AuthAlt";

    final String dss10Path = testCase.getSignServerHome().getAbsolutePath()
            + File.separator + "res"
            + File.separator + "test"
            + File.separator + "dss10";    
    final String trustoreFilePath = dss10Path + File.separator + "dss10_truststore.jks";    
    final String dss10RootCAPemPath = dss10Path + File.separator + "DSSRootCA10.cacert.pem";
    final String signClientCLI = testCase.getSignServerHome().getAbsolutePath() + File.separator + "bin" + File.separator + "signclient";
    
    @Rule
    public final TemporaryFolder inDir = new TemporaryFolder();
    
    @Rule
    public final TemporaryFolder outDir = new TemporaryFolder();


    public SignClientP11AuthTest() throws FileNotFoundException {
        final File home = PathUtil.getAppHome();
        sharedLibraryName = testCase.getConfig().getProperty("test.p11.sharedLibraryName");
        sharedLibraryPath = testCase.getConfig().getProperty("test.p11.sharedLibraryPath");
        slot = testCase.getConfig().getProperty("test.p11.slot");
        slotIndex = testCase.getConfig().getProperty("test.p11.slotindex");
        pin = testCase.getConfig().getProperty("test.p11.pin");
        existingKey1 = testCase.getConfig().getProperty("test.p11.existingkey1");
    }

    @Before
    public void setUp() throws Exception {
        Assume.assumeFalse("P11NG".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.provider")));
        SignServerUtil.installBCProvider();
    }

    private void setupCryptoTokenProperties(final int tokenId, final boolean cache) throws Exception {
        // Setup token
        workerSession.setWorkerProperty(tokenId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(tokenId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(tokenId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(tokenId, "SHAREDLIBRARYNAME", sharedLibraryName);
        if (!StringUtils.isBlank(slot)) {
            LOG.debug("setting slot: " + slot);
            workerSession.setWorkerProperty(tokenId, CryptoTokenHelper.PROPERTY_SLOTLABELTYPE, Pkcs11SlotLabelType.SLOT_NUMBER.getKey());
            workerSession.setWorkerProperty(tokenId, CryptoTokenHelper.PROPERTY_SLOTLABELVALUE, slot);
        } else {
            LOG.debug("setting slotIndex: " + slotIndex);
            workerSession.setWorkerProperty(tokenId, CryptoTokenHelper.PROPERTY_SLOTLABELTYPE, Pkcs11SlotLabelType.SLOT_INDEX.getKey());
            workerSession.setWorkerProperty(tokenId, CryptoTokenHelper.PROPERTY_SLOTLABELVALUE, slotIndex);
        }
        workerSession.setWorkerProperty(tokenId, "PIN", pin);
        workerSession.setWorkerProperty(tokenId, "DEFAULTKEY", existingKey1); // Test key
        workerSession.reloadConfiguration(tokenId);
    }

    /**
     * Creates a new key in P11 keystore, issue a certificate by DSSRootCA10,
     * imports it in token associating with generated key and performs signing
     * operation by same key through PlainSigner.
     *
     *
     * @throws Exception
     */
   @Test
    public void testPlainSigner_P11AuthKey() throws Exception {
        LOG.info("testPlainSigner_P11AuthKey"); 
        
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN_ID, false);
            createP11AuthKey();

            setPlainSignerProperties(WORKER_PLAIN, true);
            workerSession.reloadConfiguration(WORKER_PLAIN);

            plainSigner(WORKER_PLAIN);
        } finally {
            workerSession.removeKey(new WorkerIdentifier(CRYPTO_TOKEN_ID), TEST_AUTH_KEY);
            testCase.removeWorker(CRYPTO_TOKEN_ID);
            testCase.removeWorker(WORKER_PLAIN);
        }
    }
    
    /**
     * Creates a new TLS client authentication key in P11 keystore, issue a
     * certificate by DSSRootCA10, imports it in token associating with
     * generated key and performs signing operation through CLI using same key
     * for client authentication while connecting to server.
     *
     *
     * @throws Exception
     */
    @Test
    public void testSigningFixedP11AuthKey() throws Exception {
        LOG.info("testSigningFixedP11AuthKey");
        File p11ConfigFile = null;

        try {
            p11ConfigFile = File.createTempFile("sunpkcs11-", "cfg");
            createPKCS11ConfigFile(p11ConfigFile);

            setupCryptoTokenProperties(CRYPTO_TOKEN_ID, false);
            createP11AuthKey();

            setPlainSignerProperties(WORKER_PLAIN, true);            
            workerSession.setWorkerProperty(WORKER_PLAIN, "AUTHTYPE",
                    "org.signserver.server.ClientCertAuthorizer");

            // Add CLIENT AUTH rule in worker
            assertEquals("execute add", 0,
                    adminCLI.execute("authorizedclients", "-worker", String.valueOf(WORKER_PLAIN),
                            "-add",
                            "-matchSubjectWithType", "SUBJECT_RDN_CN",
                            "-matchSubjectWithValue", AUTH_KEY_CERT_CN,
                            "-matchIssuerWithValue", ISSUER_DN,
                            "-description", DESCRIPTION));

            workerSession.reloadConfiguration(WORKER_PLAIN);

            ComplianceTestUtils.ProcResult res
                    = ComplianceTestUtils.execute(signClientCLI, "signdocument", "-workername", "TestPlainSignerP11",
                            "-data", "<data/>",
                            "-keystoretype", "PKCS11_CONFIG",
                            "-keyalias", TEST_AUTH_KEY,
                            "-keystore", p11ConfigFile.getAbsolutePath(),
                            "-keystorepwd", pin,
                            "-truststore", trustoreFilePath,
                            "-truststorepwd", "changeit");
            Assert.assertEquals("result: " + res.getErrorMessage(), 0, res.getExitValue());

        } finally {
            workerSession.removeKey(new WorkerIdentifier(CRYPTO_TOKEN_ID), TEST_AUTH_KEY);
            testCase.removeWorker(CRYPTO_TOKEN_ID);
            testCase.removeWorker(WORKER_PLAIN);
            FileUtils.deleteQuietly(p11ConfigFile);
            inDir.delete();
            outDir.delete();
        }
    }

    /**
     * Creates two new TLS client authentication keys in P11 keystore, issue
     * certificates by DSSRootCA10, imports them in token associating with
     * generated keys and performs signing operation through CLI using one of
     * the keys as an authorized client certificate for client authentication
     * while connecting to server.
     *
     * @throws Exception
     */
    @Test
    public void testSigningFixedP11AuthKeyProptForAlias() throws Exception {
        LOG.info("testSigningFixedP11AuthKey");
        File p11ConfigFile = null;

        try {
            p11ConfigFile = File.createTempFile("sunpkcs11-", "cfg");
            createPKCS11ConfigFile(p11ConfigFile);

            setupCryptoTokenProperties(CRYPTO_TOKEN_ID, false);
            createP11AuthKey();
            createP11AltAuthKey();

            setPlainSignerProperties(WORKER_PLAIN, true);            
            workerSession.setWorkerProperty(WORKER_PLAIN, "AUTHTYPE",
                    "org.signserver.server.ClientCertAuthorizer");

            // Add CLIENT AUTH rule in worker
            assertEquals("execute add", 0,
                    adminCLI.execute("authorizedclients", "-worker", String.valueOf(WORKER_PLAIN),
                            "-add",
                            "-matchSubjectWithType", "SUBJECT_RDN_CN",
                            "-matchSubjectWithValue", AUTH_KEY_CERT_CN,
                            "-matchIssuerWithValue", ISSUER_DN,
                            "-description", DESCRIPTION));

            workerSession.reloadConfiguration(WORKER_PLAIN);
            
            ComplianceTestUtils.ProcResult res =
                    execute(TEST_AUTH_KEY, TEST_AUTH_ALT_KEY,
                            signClientCLI, "signdocument",
                            "-workername", "TestPlainSignerP11",
                            "-data", "<data/>",
                            "-keystoretype", "PKCS11_CONFIG",
                            "-keyaliasprompt",
                            "-keystore", p11ConfigFile.getAbsolutePath(),
                            "-keystorepwd", pin,
                            "-truststore", trustoreFilePath,
                            "-truststorepwd", "changeit");
            LOG.debug("output: " + res.getOutput().toString());
            Assert.assertEquals("result: " + res.getErrorMessage(), 0, res.getExitValue());
        } finally {
            workerSession.removeKey(new WorkerIdentifier(CRYPTO_TOKEN_ID), TEST_AUTH_KEY);
            workerSession.removeKey(new WorkerIdentifier(CRYPTO_TOKEN_ID), TEST_AUTH_ALT_KEY);
            testCase.removeWorker(CRYPTO_TOKEN_ID);
            testCase.removeWorker(WORKER_PLAIN);
            FileUtils.deleteQuietly(p11ConfigFile);
            inDir.delete();
            outDir.delete();
        }
    }

    private static ComplianceTestUtils.ProcResult execute(final String aliasToUse,
                                                          final String altAlias,
                                                          final String... arguments)
            throws IOException {
        Process proc;
        BufferedReader stdIn = null;
        BufferedReader errIn = null;
        OutputStream stdOut = null;

        try {
            Runtime runtime = Runtime.getRuntime();
            
            LOG.info(Arrays.toString(arguments));

            proc = runtime.exec(arguments, null);
            stdIn = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            errIn = new BufferedReader(new InputStreamReader(proc.getErrorStream()));
            stdOut = proc.getOutputStream();

            List<String> lines = new LinkedList<>();
            String line;
            boolean foundAuthKey = false;
            boolean foundAltAuthKey = false;
            boolean foundPrompt = false;

            while ((line = stdIn.readLine()) != null) {
                if (line.endsWith(aliasToUse)) {
                    LOG.debug("Found expected alias line: " + line);
                    if (line.charAt(0) == '[') {
                        final int endIndexOffset = line.indexOf(']');
                        if (endIndexOffset != -1) {
                            foundAuthKey = true;
                            final String answerToPrompt = line.substring(1, endIndexOffset);
                            LOG.debug("Parsed answer: " + answerToPrompt);
                            // answer prompt
                            stdOut.write(answerToPrompt.getBytes(StandardCharsets.UTF_8));
                            stdOut.write('\n');
                            stdOut.close();
                        }
                    }
                    
                } else if (line.endsWith(altAlias)) {
                    LOG.debug("Found line with alt key: " + line);
                    if (line.charAt(0) == '[' &&
                        line.indexOf(']') != -1) {
                        foundAltAuthKey = true;
                    }
                } else if (line.startsWith("Choose [")) {
                    foundPrompt = true;
                }
                lines.add(line);
            }

            final String allLines = lines.toString();
            LOG.debug("lines printed: " + allLines);
            assertTrue("Found authkey in list", foundAuthKey);
            assertTrue("Found alternative key", foundAltAuthKey);
            assertTrue("Found prompt", foundPrompt);

            StringBuilder errBuff = new StringBuilder();
            while ((line = errIn.readLine()) != null) {
                errBuff.append(line).append("\n");
            }
            try {
                proc.waitFor();
                return new ComplianceTestUtils.ProcResult(proc.exitValue(), errBuff.toString(), lines);
            } catch (InterruptedException ex) {
                LOG.error("Command interrupted", ex);
                return new ComplianceTestUtils.ProcResult(-1, errBuff.toString(), lines);
            }
        } finally {
            if (stdOut != null) {
                try {
                    stdOut.close();
                } catch (IOException ignored) {} // NOPMD
            }
            if (stdIn != null) {
                try {
                    stdIn.close();
                } catch (IOException ignored) {} // NOPMD
            }
            if (errIn != null) {
                try {
                    errIn.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }
    
    /**
     * Creates a new TLS client authentication key in P11 keystore, issue a
     * certificate by DSSRootCA10, imports it in token associating with
     * generated key and performs signing operation (batch mode)through CLI using same key
     * for client authentication while connecting to server.
     *
     *
     * @throws Exception
     */
    @Test
    public void testSigningFixedP11AuthKeyFromInDir() throws Exception {
        LOG.info("testSigningFixedP11AuthKeyFromInDir");
        File p11ConfigFile = null;

        try {
            p11ConfigFile = File.createTempFile("sunpkcs11-", "cfg");
            createPKCS11ConfigFile(p11ConfigFile);
            
            setupCryptoTokenProperties(CRYPTO_TOKEN_ID, false);
            createP11AuthKey();

            setPlainSignerProperties(WORKER_PLAIN, true);            
            workerSession.setWorkerProperty(WORKER_PLAIN, "AUTHTYPE",
                    "org.signserver.server.ClientCertAuthorizer");
            workerSession.setWorkerProperty(WORKER_PLAIN, "DISABLEKEYUSAGECOUNTER", "TRUE");

            // Add CLIENT AUTH rule in worker
            assertEquals("execute add", 0,
                    adminCLI.execute("authorizedclients", "-worker", String.valueOf(WORKER_PLAIN),
                            "-add",
                            "-matchSubjectWithType", "SUBJECT_RDN_CN",
                            "-matchSubjectWithValue", AUTH_KEY_CERT_CN,
                            "-matchIssuerWithValue", ISSUER_DN,
                            "-description", DESCRIPTION));

            workerSession.reloadConfiguration(WORKER_PLAIN);

            // Create 200 input files
            inDir.create();
            outDir.create();
            final ArrayList<File> files = createInputFiles(200);

            ComplianceTestUtils.ProcResult res
                    = ComplianceTestUtils.execute(signClientCLI, "signdocument", "-workername", "TestPlainSignerP11",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath(),
                            "-keystoretype", "PKCS11_CONFIG",
                            "-keyalias", TEST_AUTH_KEY,
                            "-keystore", p11ConfigFile.getAbsolutePath(),
                            "-keystorepwd", pin,
                            "-truststore", trustoreFilePath,
                            "-truststorepwd", "changeit");
            Assert.assertEquals("result: " + res.getErrorMessage(), 0, res.getExitValue());

        } finally {
            workerSession.removeKey(new WorkerIdentifier(CRYPTO_TOKEN_ID), TEST_AUTH_KEY);
            testCase.removeWorker(CRYPTO_TOKEN_ID);
            testCase.removeWorker(WORKER_PLAIN);
            FileUtils.deleteQuietly(p11ConfigFile);
            inDir.delete();
            outDir.delete();
        }
    }
    
    /**
     * Creates a new TLS client authentication key in P11 keystore, issue a
     * certificate by DSSRootCA10, imports it in token associating with
     * generated key and performs signing operation (batch mode and multiple threads) through CLI using same key
     * for client authentication while connecting to server.
     *
     *
     * @throws Exception
     */
    @Test
    public void testSigningFixedP11AuthKeyFromInDirWith100Threads() throws Exception {
        LOG.info("testSigningFixedP11AuthKeyFromInDirWith100Threads");        
        File p11ConfigFile = null;

        try {
            p11ConfigFile = File.createTempFile("sunpkcs11-", "cfg");
            createPKCS11ConfigFile(p11ConfigFile);
            
            setupCryptoTokenProperties(CRYPTO_TOKEN_ID, false);
            createP11AuthKey();

            setPlainSignerProperties(WORKER_PLAIN, true);            
            workerSession.setWorkerProperty(WORKER_PLAIN, "AUTHTYPE",
                    "org.signserver.server.ClientCertAuthorizer");
            workerSession.setWorkerProperty(WORKER_PLAIN, "DISABLEKEYUSAGECOUNTER", "TRUE");

            // Add CLIENT AUTH rule in worker
            assertEquals("execute add", 0,
                    adminCLI.execute("authorizedclients", "-worker", String.valueOf(WORKER_PLAIN),
                            "-add",
                            "-matchSubjectWithType", "SUBJECT_RDN_CN",
                            "-matchSubjectWithValue", AUTH_KEY_CERT_CN,
                            "-matchIssuerWithValue", ISSUER_DN,
                            "-description", DESCRIPTION));

            workerSession.reloadConfiguration(WORKER_PLAIN);

            // Create 200 input files
            inDir.create();
            outDir.create();
            final ArrayList<File> files = createInputFiles(200);

            ComplianceTestUtils.ProcResult res
                    = ComplianceTestUtils.execute(signClientCLI, "signdocument",
                            "-workername", "TestPlainSignerP11",
                            "-indir", inDir.getRoot().getAbsolutePath(),
                            "-outdir", outDir.getRoot().getAbsolutePath(),
                            "-threads", "100",
                            "-keystoretype", "PKCS11_CONFIG",
                            "-keyalias", TEST_AUTH_KEY,
                            "-keystore", p11ConfigFile.getAbsolutePath(),
                            "-keystorepwd", pin,
                            "-truststore", trustoreFilePath,
                            "-truststorepwd", "changeit");
            Assert.assertEquals("result: " + res.getErrorMessage(), 0, res.getExitValue());

        } finally {
            workerSession.removeKey(new WorkerIdentifier(CRYPTO_TOKEN_ID), TEST_AUTH_KEY);
            testCase.removeWorker(CRYPTO_TOKEN_ID);
            testCase.removeWorker(WORKER_PLAIN);
            FileUtils.deleteQuietly(p11ConfigFile);
            inDir.delete();
            outDir.delete();
        }
    }


    private void setPlainSignerProperties(final int workerId, final boolean cached) throws IOException {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.cmssigner.PlainSigner");
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(workerId, "NAME", "TestPlainSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", TEST_AUTH_KEY);
    }

    private void plainSigner(final int workerId) throws Exception {        
        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        byte[] plainText = "some-data".getBytes("ASCII");

        // Test signing
        testCase.signGenericDocument(workerId, plainText);

    }

    private List<byte[]> getCertByteArrayList(final List<Certificate> chain) throws CertificateEncodingException {
        final List<byte[]> result = new LinkedList<>();

        for (final Certificate cert : chain) {
            result.add(cert.getEncoded());
        }

        return result;
    }

    private PrivateKey getdss10CAPrivateKey() throws FileNotFoundException, KeyStoreException, IOException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
       
        final KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        final String ksPath = dss10Path + File.separator + "DSSRootCA10.p12";

        ks.load(new FileInputStream(ksPath), "foo123".toCharArray());
        PrivateKey issuerPrivKey = (PrivateKey) ks.getKey("SignatureKeyAlias", "foo123".toCharArray());

        return issuerPrivKey;
    }

    private void createP11AuthKey()
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
                   IOException, FileNotFoundException, KeyStoreException,
                   CertificateParsingException, NoSuchProviderException,
                   NoSuchAlgorithmException, CertificateException,
                   UnrecoverableKeyException, OperatorCreationException,
                   OperationUnsupportedException {
        createP11Key(TEST_AUTH_KEY, AUTH_KEY_CERT_CN);
    }

    private void createP11AltAuthKey()
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
                   IOException, FileNotFoundException, KeyStoreException,
                   NoSuchProviderException, NoSuchAlgorithmException,
                   CertificateException, CertificateParsingException,
                   UnrecoverableKeyException, OperatorCreationException,
                   OperationUnsupportedException {
        createP11Key(TEST_AUTH_ALT_KEY, AUTH_KEY_ALT_CERT_CN);
    }

    private void createP11Key(final String keyAlias, final String CN)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
                   IOException, FileNotFoundException, KeyStoreException,
                   CertificateParsingException, NoSuchProviderException,
                   NoSuchAlgorithmException, CertificateException,
                   UnrecoverableKeyException, OperatorCreationException,
                   OperationUnsupportedException {
        workerSession.generateSignerKey(new WorkerIdentifier(CRYPTO_TOKEN_ID), "RSA", "2048", keyAlias, pin.toCharArray());

        // Generate CSR
        final ISignerCertReqInfo req
                = new PKCS10CertReqInfo("SHA256WithRSA", "CN=" + CN, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(CRYPTO_TOKEN_ID), req, false, keyAlias);
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        
        // Get CA cert from file
        File caPemFile = new File(dss10RootCAPemPath);
        X509Certificate caCert = SignServerUtil.getCertFromFile(caPemFile.getAbsolutePath());
         
        // Issue certificate
        final X509CertificateHolder certHolder = new X509v3CertificateBuilder(new X500Name(caCert.getIssuerDN().getName()), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_codeSigning })).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(getdss10CAPrivateKey()));
        Certificate signerCert = CertTools.getCertfromByteArray(certHolder.getEncoded());
        
        List certChain = Arrays.asList(signerCert, caCert);        

        // Import certificate chain in token
        testCase.getWorkerSession().importCertificateChain(new WorkerIdentifier(CRYPTO_TOKEN_ID), getCertByteArrayList(certChain), keyAlias, null);
        testCase.getWorkerSession().reloadConfiguration(CRYPTO_TOKEN_ID);
    }
    
    private ArrayList<File> createInputFiles(int count) throws IOException {
        ArrayList<File> result = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            File f = inDir.newFile("file" + i + ".txt");
            FileUtils.writeStringToFile(f, "<doc" + i + "/>");
            result.add(f);
        }
        return result;
    }
    
    private void createPKCS11ConfigFile(File p11ConfigFile) throws IOException {
        final StringBuilder config = new StringBuilder();
        config.append("name=PKCS11\n");
        config.append("library=").append(sharedLibraryPath).append("\n");
        if (!StringUtils.isBlank(slot)) {
            config.append("slot=").append(slot);
        } else {
            config.append("slotListIndex=").append(slotIndex);
        }
        FileUtils.writeStringToFile(p11ConfigFile, config.toString(), StandardCharsets.UTF_8);
    }

}
