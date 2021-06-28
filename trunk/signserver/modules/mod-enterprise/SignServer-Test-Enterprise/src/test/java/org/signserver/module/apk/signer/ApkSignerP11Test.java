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

import java.io.File;
import java.util.HashMap;
import java.util.HashSet;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.WorkerConfig;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.server.cryptotokens.PKCS11CryptoToken;
import org.signserver.testutils.ModulesTestCase;

/**
 * System tests for JArchiveSigner using PKCS#11.
 *
 * This tests requires a running SignServer. For standalone unit tests
 * preferably use JArchiveSignerUnitTest instead.
 * 
 * See also JArchiveSignerTest for tests that are not PKCS#11 specific.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ApkSignerP11Test {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ApkSignerP11Test.class);

    private static final int WORKER_ID = 8909;
    private static final String WORKER_NAME = "TestApkSignerP11";
    private static final int WORKER_ID_HASH = 8910;
    private static final String WORKER_NAME_HASH = "TestApkHashSignerP11";
    private static final int CRYPTO_TOKEN_ID = 8907;
    private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenP11";
    
    private final String sharedLibraryName;
    private final String slot;
    private final String pin;
    private final String existingKey1;
    
    private final File packageFile;
    
    private final ModulesTestCase testCase = new ModulesTestCase();
    private final WorkerSession workerSession = testCase.getWorkerSession();
    
    public ApkSignerP11Test() throws Exception {
        sharedLibraryName = testCase.getConfig().getProperty("test.p11.sharedLibraryName");
        slot = testCase.getConfig().getProperty("test.p11.slot");
        pin = testCase.getConfig().getProperty("test.p11.pin");
        existingKey1 = testCase.getConfig().getProperty("test.p11.existingkey1");
        packageFile = new File(PathUtil.getAppHome(), "res/test/HelloApk.apk");
        if (!packageFile.exists()) {
            throw new Exception("Missing sample package: " + packageFile);
        }
    }
    
    @Before
    public void setUp() throws Exception {
        Assume.assumeFalse("P11NG".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.provider")));
    }
    
    private void setupCryptoTokenProperties(final int tokenId) throws Exception {
        // Setup token
        workerSession.setWorkerProperty(tokenId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(tokenId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(tokenId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(tokenId, "SLOT", slot);
        workerSession.setWorkerProperty(tokenId, "PIN", pin);
        workerSession.setWorkerProperty(tokenId, "DEFAULTKEY", existingKey1); // Test key
    }
    
    private void setApkSignerProperties(final int workerId) throws Exception {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.apk.signer.ApkSigner");
        workerSession.setWorkerProperty(workerId, "NAME", WORKER_NAME);
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
    }

    private void setApkHashSignerProperties(final int workerId) throws Exception {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS,
                                        "org.signserver.module.apk.signer.ApkHashSigner");
        workerSession.setWorkerProperty(workerId, "NAME", WORKER_NAME_HASH);
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
    }

    /**
     * Test signing using PKCS#11 token.
     * @throws Exception 
     */
    @Test
    public void testSigningUsingP11() throws Exception {
        LOG.info("testSigningUsingP11");
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN_ID);
            setApkSignerProperties(WORKER_ID);
            workerSession.setWorkerProperty(WORKER_ID, "V1_SIGNATURE_NAME", "P11SIG");
            workerSession.reloadConfiguration(CRYPTO_TOKEN_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            final HashSet<String> expectedV1SignatureNames = new HashSet<>();

            expectedV1SignatureNames.add("P11SIG.RSA");
            ApkSignerTest.signAndAssertOk(FileUtils.readFileToByteArray(packageFile),
                                          WORKER_ID, false, true, true, true, false,
                                          1, expectedV1SignatureNames, null);
        } finally {
            testCase.removeWorker(WORKER_ID);
            testCase.removeWorker(CRYPTO_TOKEN_ID);
        }
    }

    /**
     * Test signing using PKCS#11 token. Using client-side mode.
     * @throws Exception 
     */
    @Test
    public void testSigningUsingP11ClientSide() throws Exception {
        LOG.info("testSigningUsingP11");
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN_ID);
            setApkHashSignerProperties(WORKER_ID_HASH);
            workerSession.reloadConfiguration(CRYPTO_TOKEN_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            final HashSet<String> expectedV1SignatureNames = new HashSet<>();

            expectedV1SignatureNames.add("P11SIG.RSA");
            final HashMap<String, String> extraOptions = new HashMap<>();
            extraOptions.put("V1_SIGNATURE_NAME", "P11SIG");

            ApkSignerTest.signAndAssertOk(FileUtils.readFileToByteArray(packageFile),
                                          WORKER_ID_HASH, true, true, true, true, false,
                                          1, expectedV1SignatureNames, extraOptions);
        } finally {
            testCase.removeWorker(WORKER_ID_HASH);
            testCase.removeWorker(CRYPTO_TOKEN_ID);
        }
    }

}
