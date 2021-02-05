/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.msauthcode.signer;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.AbstractCertReqData;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.server.FixedTimeSource;
import org.signserver.server.cryptotokens.PKCS11CryptoToken;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * System tests for MSAuthCodeSigner using PKCS#11.
 *
 * This tests requires a running SignServer. For standalone unit tests
 * preferably use MSAuthCodeSignerUnitTest instead.
 * 
 * See also MSAuthCodeSignerTest for tests that are not PKCS#11 specific.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class MSAuthCodeSignerP11Test {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(MSAuthCodeSignerP11Test.class);

    private static final int WORKER_ID = 8901;
    private static final String WORKER_NAME = "TestAuthenticodeSignerP11";
    private static final int TS_ID = 8902;
    private static final String TS_NAME = "TestAuthenticodeTimeStampSigner";
    private static final int CRYPTO_TOKEN_ID = 8903;
    private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenP11";
    private static final String TEST_KEY_ALIAS = "testkey123";
    
    private final String sharedLibraryName;
    private final String slot;
    private final String pin;
    private final String existingKey1;
    
    private final File executableFile;
    private final File msiFile;
    private final File appxFile;
    private final File ps1File;

    private final ModulesTestCase testCase = new ModulesTestCase();
    private final WorkerSession workerSession = testCase.getWorkerSession();
    
    private enum FileType {
        PE,
        MSI,
        APPX,
        PS1
    }
    
    public MSAuthCodeSignerP11Test() throws Exception {
        sharedLibraryName = testCase.getConfig().getProperty("test.p11.sharedLibraryName");
        slot = testCase.getConfig().getProperty("test.p11.slot");
        pin = testCase.getConfig().getProperty("test.p11.pin");
        existingKey1 = testCase.getConfig().getProperty("test.p11.existingkey1");
        executableFile = new File(PathUtil.getAppHome(), "res/test/HelloPE.exe");
        msiFile = new File(PathUtil.getAppHome(), "res/test/sample.msi");
        appxFile = new File(PathUtil.getAppHome(), "res/test/HelloAppx.appx");
        ps1File = new File(PathUtil.getAppHome(), "res/test/HelloPowerShell.ps1");
        if (!executableFile.exists()) {
            throw new Exception("Missing sample binary: " + executableFile);
        }
        if (!msiFile.exists()) {
            throw new Exception("Missing sample MSI package: " + msiFile);
        }
        if (!appxFile.exists()) {
            throw new Exception("Missing sample APPX package: " + appxFile);
        }
        if (!ps1File.exists()) {
            throw new Exception("Missing sample PS1 package: " + ps1File);
        }
        SignServerUtil.installBCProvider();
    }
    
    @Before
    public void setUp() throws Exception {
        Assume.assumeFalse("P11NG".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.provider")));
    }
    
    private void setupCryptoTokenProperties(final int tokenId) throws Exception {
        // Setup token
        workerSession.setWorkerProperty(tokenId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(tokenId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(tokenId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(tokenId, "SLOT", slot);
        workerSession.setWorkerProperty(tokenId, "PIN", pin);
        workerSession.setWorkerProperty(tokenId, "DEFAULTKEY", existingKey1); // Test key
    }
    
    private void setAuthenticodeSignerProperties(final int workerId, final FileType fileType) throws Exception {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, fileType == FileType.APPX ? AppxSigner.class.getName() : "org.signserver.module.msauthcode.signer.MSAuthCodeSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, "NAME", WORKER_NAME);
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
    }

    /**
     * Test signing using PKCS#11 token.
     * @throws Exception 
     */
    @Test
    public void testSigningPEUsingP11() throws Exception {
        LOG.info("testSigningPEUsingP11");
        testSigningUsingP11(FileType.PE);
    }
    
    /**
     * Test signing MSI using PKCS#11 token.
     * 
     * @throws Exception 
     */
    @Test
    public void testSigningMSIUsingP11() throws Exception {
        LOG.info("testSigningMSIUsingP11");
        testSigningUsingP11(FileType.MSI);
    }
    
    /**
     * Test signing APPX using PKCS#11 token.
     * 
     * @throws Exception 
     */
    @Test
    public void testSigningAPPXUsingP11() throws Exception {
        LOG.info("testSigningAPPXUsingP11");
        testSigningUsingP11(FileType.APPX);
    }
    
    /**
     * Test signing PS1 using PKCS#11 token.
     * 
     * @throws Exception 
     */
    @Test
    public void testSigningPs1UsingP11() throws Exception {
        LOG.info("testSigningPs1UsingP11");
        testSigningUsingP11(FileType.PS1);
    }

    private void testSigningUsingP11(final FileType fileType) throws Exception {
        File signedBinary = null;        
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out

            setupCryptoTokenProperties(CRYPTO_TOKEN_ID);
            setAuthenticodeSignerProperties(WORKER_ID, fileType);
            testCase.addMSTimeStampSigner(TS_ID, TS_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(CRYPTO_TOKEN_ID);
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            switch (fileType) {
                case MSI:
                    signedBinary = MSAuthCodeSignerTest.signAndAssertOkMSI(msiFile, WORKER_ID, TS_ID, time, false, false, 1);
                    break;
                case PE:
                    signedBinary = MSAuthCodeSignerTest.signAndAssertOk(executableFile, WORKER_ID, TS_ID, time, false, false, 1);
                    break;
                case APPX:
                    signedBinary = MSAuthCodeSignerTest.signAndAssertOkAPPX(appxFile, WORKER_ID, TS_ID, time, false, false, workerSession.getSignerCertificate(new WorkerIdentifier(WORKER_ID)), "SHA-256", 1);
                    break;
                case PS1:
                    signedBinary = MSAuthCodeSignerTest.signAndAssertOkPs1(ps1File, WORKER_ID, TS_ID, time, false, false, 1);
                    break;
                default:
                    throw new Exception("File type unsupported in test: " + fileType);
            }
        } finally {
            if (signedBinary != null) {
                signedBinary.delete();
            }
            testCase.removeWorker(WORKER_ID);
            testCase.removeWorker(TS_ID);
            testCase.removeWorker(CRYPTO_TOKEN_ID);
        }
    }
    
    /**
     * Tests signing MSI when certificate installed in configuration instead of
     * token.
     *
     * @throws Exception
     */
    @Test
    public void testSigningMSIWithCertificateInConfiguration() throws Exception {
        LOG.info("testSigningMSIWithCertificateInConfiguration");
        File signedBinary = null;
        try {
            Date time = new Date((System.currentTimeMillis() / 1000) * 1000); // Current time with milliseconds cleared out

            setupCryptoTokenProperties(CRYPTO_TOKEN_ID);
            setAuthenticodeSignerProperties(WORKER_ID, FileType.MSI);
            testCase.addMSTimeStampSigner(TS_ID, TS_NAME, true);

            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_NAME", "Any program name");
            workerSession.setWorkerProperty(WORKER_ID, "PROGRAM_URL", "http://example.com/anyprogramname.html");
            workerSession.setWorkerProperty(TS_ID, "TIMESOURCE", FixedTimeSource.class.getName());
            workerSession.setWorkerProperty(TS_ID, "FIXEDTIME", String.valueOf(time.getTime()));
            workerSession.reloadConfiguration(CRYPTO_TOKEN_ID);
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            workerSession.generateSignerKey(new WorkerIdentifier(CRYPTO_TOKEN_ID), "RSA", "1024", TEST_KEY_ALIAS, null);
            workerSession.setWorkerProperty(WORKER_ID, "DEFAULTKEY", TEST_KEY_ALIAS);

            workerSession.reloadConfiguration(CRYPTO_TOKEN_ID);
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            // Generate CSR
            final ISignerCertReqInfo req
                    = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_ID, null);
            AbstractCertReqData reqData
                    = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(WORKER_ID), req, false, TEST_KEY_ALIAS);

            // Issue certificate
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
            KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
            X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=Test Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

            // Install certificate and chain
            workerSession.uploadSignerCertificate(WORKER_ID, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER_ID, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER_ID);

            signedBinary = MSAuthCodeSignerTest.signAndAssertOkMSI(msiFile, WORKER_ID, TS_ID, time, false, false, 1);
        } finally {
            workerSession.removeKey(new WorkerIdentifier(CRYPTO_TOKEN_ID), TEST_KEY_ALIAS);
            if (signedBinary != null) {
                signedBinary.delete();
            }
            testCase.removeWorker(WORKER_ID);
            testCase.removeWorker(TS_ID);
            testCase.removeWorker(CRYPTO_TOKEN_ID);
        }
    }

}
