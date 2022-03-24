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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
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
import org.junit.Assume;
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
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.module.openpgp.signer.OpenPGPUtils;
import org.signserver.openpgp.utils.ClearSignedFileProcessorUtils;
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

    private final File sampleBinaryFile;

    private final ModulesTestCase testCase = new ModulesTestCase();
    private final WorkerSession workerSession = testCase.getWorkerSession();

    public OpenPGPP11SignTest() throws FileNotFoundException {
        final File home = PathUtil.getAppHome();
        sampleBinaryFile = new File(home, "res/test/pdf/sample.pdf"); // Let's use any binary file as input
        sharedLibraryName = testCase.getConfig().getProperty("test.p11.sharedLibraryName");
        slot = testCase.getConfig().getProperty("test.p11.slot");
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
        final Map<String, String> properties = new HashMap<>();

        properties.put(WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        properties.put(WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        properties.put(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        properties.put("NAME", CRYPTO_TOKEN_NAME);
        properties.put("SHAREDLIBRARYNAME", sharedLibraryName);
        properties.put("SLOT", slot);
        properties.put("PIN", pin);
        properties.put("DEFAULTKEY", existingKey1); // Test key
        properties.put("CACHE_PRIVATEKEY", String.valueOf(cache));

        workerSession.updateWorkerProperties(tokenId, properties,
                                             Collections.emptyList());
    }

    private void setOpenPGPSignerOnlyProperties(final int workerId, String detachedSignature) throws Exception {
        // Setup worker
        final Map<String, String> properties = new HashMap<>();

        properties.put(WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        properties.put(WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.openpgp.signer.OpenPGPSigner");
        properties.put("NAME", "OpenPGPSignerP11");
        properties.put("AUTHTYPE", "NOAUTH");
        properties.put("CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        properties.put("DEFAULTKEY", existingKey1);
        properties.put("DETACHEDSIGNATURE", detachedSignature);

        workerSession.updateWorkerProperties(workerId, properties,
                                             Collections.emptyList());
    }

    /**
     * Tests adding a User Id to the public key, sign something producing detached signature and verifying it.
     *
     * @throws Exception
     */
    @Test
    public void testAddUserIdDetachedSignAndVerify() throws Exception {
        LOG.info("testAddUserIdDetachedSignAndVerify");
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, false);
            setOpenPGPSignerOnlyProperties(WORKER_OPENPGPSIGNER, "TRUE");
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
            final byte[] originalData = FileUtils.readFileToByteArray(sampleBinaryFile);
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
            assertTrue("verified", sig.verify());

        } finally {
            testCase.removeWorker(CRYPTO_TOKEN);
            testCase.removeWorker(WORKER_OPENPGPSIGNER);
        }
    }
    
    /**
     * Tests adding a User Id to the public key, sign something producing clear text signature and verifying it.
     *
     * @throws Exception
     */
    @Test
    public void testAddUserIdClearTextSignAndVerify() throws Exception {
        LOG.info("testAddUserIdClearTextSignAndVerify");
        final File resultFile = File.createTempFile("resultFile", "txt");
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, false);
            setOpenPGPSignerOnlyProperties(WORKER_OPENPGPSIGNER, "FALSE");
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
            final byte[] originalData = FileUtils.readFileToByteArray(sampleBinaryFile);
            GenericSignResponse response = testCase.signGenericDocument(WORKER_OPENPGPSIGNER, originalData);
            final byte[] signedBytes = response.getProcessedData();

            String signed = new String(signedBytes, StandardCharsets.US_ASCII);
            assertTrue("expecting armored: " + signed, signed.startsWith("-----BEGIN PGP SIGNED MESSAGE-----"));
            
            // Verify signature
            PGPSignature sig;            

            ArmoredInputStream aIn = new ArmoredInputStream(new ByteArrayInputStream(signedBytes));
            ByteArrayOutputStream lineOut;
            int lookAhead;
            try (OutputStream out = new BufferedOutputStream(new FileOutputStream(resultFile))) {
                lineOut = new ByteArrayOutputStream();
                lookAhead = ClearSignedFileProcessorUtils.readInputLine(lineOut, aIn);
                byte[] lineSep = ClearSignedFileProcessorUtils.getLineSeparator();
                if (lookAhead != -1 && aIn.isClearText()) {
                    byte[] line = lineOut.toByteArray();
                    out.write(line, 0, ClearSignedFileProcessorUtils.getLengthWithoutSeparatorOrTrailingWhitespace(line));
                    out.write(lineSep);

                    while (lookAhead != -1 && aIn.isClearText()) {
                        lookAhead = ClearSignedFileProcessorUtils.readInputLine(lineOut, lookAhead, aIn);

                        line = lineOut.toByteArray();
                        out.write(line, 0, ClearSignedFileProcessorUtils.getLengthWithoutSeparatorOrTrailingWhitespace(line));
                        out.write(lineSep);
                    }
                } else {
                    // a single line file
                    if (lookAhead != -1) {
                        byte[] line = lineOut.toByteArray();
                        out.write(line, 0, ClearSignedFileProcessorUtils.getLengthWithoutSeparatorOrTrailingWhitespace(line));
                        out.write(lineSep);
                    }
                }
            }

            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(aIn);
            PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();
            sig = p3.get(0);

            final PGPPublicKey pgpPublicKey = OpenPGPUtils.parsePublicKeys(publicKeyArmored).get(0);
            sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pgpPublicKey);

            try (InputStream sigIn = new BufferedInputStream(new FileInputStream(resultFile))) {
                lookAhead = ClearSignedFileProcessorUtils.readInputLine(lineOut, sigIn);

                ClearSignedFileProcessorUtils.processLine(sig, lineOut.toByteArray());

                if (lookAhead != -1) {
                    do {
                        lookAhead = ClearSignedFileProcessorUtils.readInputLine(lineOut, lookAhead, sigIn);

                        sig.update((byte) '\r');
                        sig.update((byte) '\n');

                        ClearSignedFileProcessorUtils.processLine(sig, lineOut.toByteArray());
                    } while (lookAhead != -1);
                }
            }

            assertTrue("verified", sig.verify());

        } finally {
            testCase.removeWorker(CRYPTO_TOKEN);
            testCase.removeWorker(WORKER_OPENPGPSIGNER);
            FileUtils.deleteQuietly(resultFile);
        }
    }


    private BCPGInputStream createInputStream(InputStream in, boolean armored) throws IOException {
        return new BCPGInputStream(armored ? new ArmoredInputStream(in) : in);
    }

}
