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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
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
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.signserver.client.cli.ClientCLI;
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
import org.signserver.testutils.ModulesTestCase;

/**
 * Test signing with Client CLI using authentication key in PKCS11 keystore.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class P11AuthKeyTest {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(P11AuthKeyTest.class);

    private static final int CRYPTO_TOKEN_ID = 40100;

    private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenP11Auth";
    private static final int WORKER_PLAIN = 40020;
    private static final String TEST_AUTH_KEY = "testAuthKey";

    private final String sharedLibraryName;
    private final String sharedLibraryPath;
    private final String slot;
    private final String slotIndex;
    private final String pin;
    private final String existingKey1;

    private final ModulesTestCase testCase = new ModulesTestCase();
    private final WorkerSession workerSession = testCase.getWorkerSession();
    private static final CLITestHelper CLI = new CLITestHelper(ClientCLI.class);
    
    final String dss10Path = testCase.getSignServerHome().getAbsolutePath()
            + File.separator + "res"
            + File.separator + "test"
            + File.separator + "dss10";
    
    final String trustoreFilePath = dss10Path + File.separator + "dss10_truststore.jks";
    
    final String dss10RootCAPemPath = dss10Path + File.separator + "DSSRootCA10.cacert.pem";


    public P11AuthKeyTest() throws FileNotFoundException {
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

   @Test
    public void testPlainSigner_P11AuthKey() throws Exception {
        final int workerId = WORKER_PLAIN;

        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN_ID, false);
            createP11AuthKey();

            setPlainSignerProperties(workerId, true);
            workerSession.reloadConfiguration(workerId);

            plainSigner(workerId);
        } finally {
            workerSession.removeKey(new WorkerIdentifier(CRYPTO_TOKEN_ID), TEST_AUTH_KEY);
            testCase.removeWorker(CRYPTO_TOKEN_ID);
            testCase.removeWorker(workerId);
        }
    }
    
    @Test
    public void testSigningFixedP11AuthKey() throws Exception {
        final int workerId = WORKER_PLAIN;
        File p11ConfigFile = File.createTempFile("sunpkcs11-", "cfg");
        final StringBuilder config = new StringBuilder();
        config.append("name=PKCS11\n");
        config.append("library=").append(sharedLibraryPath).append("\n");
        if (!StringUtils.isBlank(slot)) {
            config.append("slot=").append(slot);
        } else {
            config.append("slotListIndex=").append(slotIndex);
        }
        FileUtils.writeStringToFile(p11ConfigFile, config.toString(), StandardCharsets.UTF_8);
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN_ID, false);
            createP11AuthKey();

            setPlainSignerProperties(workerId, true);
            workerSession.setWorkerProperty(workerId, "DEFAULTKEY", TEST_AUTH_KEY);
            workerSession.reloadConfiguration(workerId);

            assertEquals("Status code", 0, 
                    CLI.execute("signdocument", "-workername", "TestPlainSignerP11",
                    "-data", "<data/>",
                    "-keystoretype", "PKCS11_CONFIG",
                    "-keyalias", TEST_AUTH_KEY,
                    "-keystore", p11ConfigFile.getAbsolutePath(),
                    "-keystorepwd", pin,
                    "-truststore", trustoreFilePath,
                    "-truststorepwd", "changeit"));
            
        } finally {
            workerSession.removeKey(new WorkerIdentifier(CRYPTO_TOKEN_ID), TEST_AUTH_KEY);
            testCase.removeWorker(CRYPTO_TOKEN_ID);
            testCase.removeWorker(workerId);
            FileUtils.deleteQuietly(p11ConfigFile);
        }
    }

    private void setPlainSignerProperties(final int workerId, final boolean cached) throws IOException {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.cmssigner.PlainSigner");
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(workerId, "NAME", "TestPlainSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
    }

    private void plainSigner(final int workerId) throws Exception {

        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", TEST_AUTH_KEY);
        workerSession.reloadConfiguration(workerId);

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

    private void createP11AuthKey() throws CryptoTokenOfflineException, InvalidWorkerIdException, IOException, FileNotFoundException, KeyStoreException, CertificateParsingException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, OperatorCreationException, OperationUnsupportedException {
        workerSession.generateSignerKey(new WorkerIdentifier(CRYPTO_TOKEN_ID), "RSA", "2048", TEST_AUTH_KEY, pin.toCharArray());

        // Generate CSR
        final ISignerCertReqInfo req
                = new PKCS10CertReqInfo("SHA256WithRSA", "CN=Worker" + CRYPTO_TOKEN_ID, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(CRYPTO_TOKEN_ID), req, false, TEST_AUTH_KEY);
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        
        // Get CA cert from file
        File caPemFile = new File(dss10RootCAPemPath);
        X509Certificate caCert = SignServerUtil.getCertFromFile(caPemFile.getAbsolutePath());
         
        // Issue certificate
        // Extension certExt = (Extension) new CertExt(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_codeSigning }));
        final X509CertificateHolder certHolder = new X509v3CertificateBuilder(new X500Name(caCert.getIssuerDN().getName()), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_codeSigning })).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(getdss10CAPrivateKey()));
        Certificate signerCert = CertTools.getCertfromByteArray(certHolder.getEncoded());
        
        List certChain = Arrays.asList(signerCert, caCert);        

        // Import certificate chain in token
        testCase.getWorkerSession().importCertificateChain(new WorkerIdentifier(CRYPTO_TOKEN_ID), getCertByteArrayList(certChain), TEST_AUTH_KEY, null);
        testCase.getWorkerSession().reloadConfiguration(CRYPTO_TOKEN_ID);
    }

}
