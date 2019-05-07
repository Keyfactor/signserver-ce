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
package org.signserver.server.cryptotokens;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import static org.junit.Assert.assertNotEquals;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.AbstractCertReqData;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionRemote;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.module.openpgp.signer.OpenPGPUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * Test signing with OpenPGP signer(s) and a PKCS11CryptoToken.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class OpenPGPP11SignTest {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(OpenPGPP11SignTest.class);

    private static final int CRYPTO_TOKEN = 30100;
    private static final int WORKER_OPENPGPSIGNER = 30000;

    private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenOpenPGPP11";

    private final String sharedLibraryName;
    private final String slot;
    private final String pin;
    private final String existingKey1;

    private final File pdfSampleFile;

    private final ModulesTestCase testCase = new ModulesTestCase();
    private final WorkerSession workerSession = testCase.getWorkerSession();

    public OpenPGPP11SignTest() throws FileNotFoundException {
        final File home = PathUtil.getAppHome();
        pdfSampleFile = new File(home, "res/test/pdf/sample.pdf");
        sharedLibraryName = testCase.getConfig().getProperty("test.p11.sharedLibraryName");
        slot = testCase.getConfig().getProperty("test.p11.slot");
        pin = testCase.getConfig().getProperty("test.p11.pin");
        existingKey1 = testCase.getConfig().getProperty("test.p11.existingkey1");
    }

    @Before
    public void setUp() throws Exception {
        //Assume.assumeFalse("P11NG".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.provider")));
        SignServerUtil.installBCProvider();
    }

    private void setupCryptoTokenProperties(final int tokenId, final boolean cache) throws Exception {
        // Setup token
        workerSession.setWorkerProperty(tokenId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(tokenId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(tokenId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(tokenId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(tokenId, "SLOT", slot);
        workerSession.setWorkerProperty(tokenId, "PIN", pin);
        workerSession.setWorkerProperty(tokenId, "DEFAULTKEY", existingKey1); // Test key
        workerSession.setWorkerProperty(tokenId, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }

    private void setOpenPGPSignerOnlyProperties(final int workerId) throws Exception {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.openpgp.signer.OpenPGPSigner");
        workerSession.setWorkerProperty(workerId, "NAME", "OpenPGPSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "DETACHEDSIGNATURE", "true");
    }

    /**
     * Tests adding a User Id to the public key, sign something and verifying it.
     *
     * @throws Exception
     */
    @Test
    public void testAddUserIdSignAndVerify() throws Exception {
        LOG.info("testAddUserIdSignAndVerify");
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, false);
            setOpenPGPSignerOnlyProperties(WORKER_OPENPGPSIGNER);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(WORKER_OPENPGPSIGNER);

            // Generate the public key
            final String userId = "Worker " + WORKER_OPENPGPSIGNER + " worker@example.com";
            final PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA256WithRSA", userId, null);
            AbstractCertReqData csr = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(WORKER_OPENPGPSIGNER), certReqInfo, false);
            assertNotNull(csr);
            String publicKeyArmored = csr.toArmoredForm();
            assertTrue("public key header: " + publicKeyArmored, publicKeyArmored.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
            assertTrue("public key footer: " + publicKeyArmored, publicKeyArmored.contains("-----END PGP PUBLIC KEY BLOCK-----"));

            // Store the updated public key
            workerSession.setWorkerProperty(WORKER_OPENPGPSIGNER, "PGPPUBLICKEY", publicKeyArmored);
            workerSession.reloadConfiguration(WORKER_OPENPGPSIGNER);

            // Check the status has no errors and that the user id is printed
            WorkerStatus status = workerSession.getStatus(new WorkerIdentifier(WORKER_OPENPGPSIGNER));
            assertEquals("fatal errors", "[]", status.getFatalErrors().toString());
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            status.displayStatus(new PrintStream(bout), true);
            String statusOutput = bout.toString(StandardCharsets.UTF_8.toString());
            assertTrue("key contains user id: " + statusOutput, statusOutput.contains(userId));

            // Test signing
            final byte[] originalData = FileUtils.readFileToByteArray(pdfSampleFile);
            GenericSignResponse response = testCase.signGenericDocument(WORKER_OPENPGPSIGNER, originalData);
            final byte[] signedBytes = response.getProcessedData();

            // Verify signature
            PGPSignature sig;
            try (InputStream in = createInputStream(new ByteArrayInputStream(signedBytes), true)) {
                JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(in);
                PGPSignatureList p3 = (PGPSignatureList) objectFactory.nextObject();
                sig = p3.get(0);
            }
            final PGPPublicKey pgpPublicKey = OpenPGPUtils.parsePublicKeys(publicKeyArmored).get(0);
            sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pgpPublicKey);
            sig.update(originalData);
            assertNotEquals("verified", sig.verify());

        } finally {
            testCase.removeWorker(CRYPTO_TOKEN);
            testCase.removeWorker(WORKER_OPENPGPSIGNER);
        }
    }

    private BCPGInputStream createInputStream(InputStream in, boolean armored) throws IOException {
        return new BCPGInputStream(armored ? new ArmoredInputStream(in) : in);
    }

}
