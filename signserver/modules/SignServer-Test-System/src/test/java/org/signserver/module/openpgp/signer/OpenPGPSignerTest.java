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
package org.signserver.module.openpgp.signer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.client.cli.ClientCLI;
import org.signserver.common.AbstractCertReqData;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;

/**
 * System tests for the OpenPGPSigner.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class OpenPGPSignerTest {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(OpenPGPSignerTest.class);

    private static final int WORKER_OPENPGPSIGNER = 40000;
    private static final int WORKER_OPENPGPPLAINSIGNER = 41000;
    private static final String SIGNER00003 = "signer00003";
    private static final String SIGNER00003_KEYID = "F7B50A4D55F6E703";
    private static final String SIGNER00001 = "signer00001";
    private static final String SIGNER00001_KEYID = "4B821662F54A5923";

    private final File sampleBinaryFile;

    private final ModulesTestCase testCase = new ModulesTestCase();
    private final WorkerSession workerSession = testCase.getWorkerSession();
    private static final CLITestHelper CLI = new CLITestHelper(ClientCLI.class);

    public OpenPGPSignerTest() throws FileNotFoundException {
        final File home = PathUtil.getAppHome();
        sampleBinaryFile = new File(home, "res/test/pdf/sample.pdf"); // Let's use any binary file as input
    }

    
    @BeforeClass
    public static void setUpClass() throws Exception {
        SignServerUtil.installBCProvider();
    }
    
    /**
     * Test that generating a certification works both when generating
     * for DEFAULTKEY and for another key, with an existing certificate
     * set in PGPPUBLICKEY, installing the new public certificate and and
     * setting PGPPUBLICKEY to the new certificate and updating DEFAULTKEY.
     * The worker should be active in both cases.
     *
     * @throws Exception
     */
    @Test
    public void testGeneratePublicKeyForNoDefaultKey() throws Exception {
        final int workerId = 42;
        final String workerName = "OpenPGPSigner-gen-non-default";
        try {
            final WorkerIdentifier wi = new WorkerIdentifier(workerId);
            testCase.addSigner("org.signserver.module.openpgp.signer.OpenPGPSigner",
                             workerId, workerName, true);
            testCase.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY",
                                                        "signer00001");
            testCase.getWorkerSession().setWorkerProperty(workerId,
                                                        "DETACHEDSIGNATURE",
                                                        "true");
            testCase.getWorkerSession().reloadConfiguration(workerId);

            PKCS10CertReqInfo certReqInfo =
                    new PKCS10CertReqInfo("SHA256withRSA", "User1", null);
            AbstractCertReqData requestData = (AbstractCertReqData)
                    testCase.getWorkerSession().getCertificateRequest(wi,
                                                                    certReqInfo,
                                                                    false);

            String pgpPublicKey = requestData.toArmoredForm();
            testCase.getWorkerSession().setWorkerProperty(workerId, "PGPPUBLICKEY",
                                                        pgpPublicKey);
            testCase.getWorkerSession().reloadConfiguration(workerId);

            WorkerStatus status = testCase.getWorkerSession().getStatus(wi);
            assertTrue("Worker active: " + status.getFatalErrors().toString(),
                       status.getFatalErrors().isEmpty());

            // generate certification for another key
            certReqInfo = new PKCS10CertReqInfo("SHA256withRSA", "User2", null);
            requestData = (AbstractCertReqData)
                    testCase.getWorkerSession().getCertificateRequest(wi,
                                                                    certReqInfo,
                                                                    false,
                                                                    "signer00003");
            pgpPublicKey = requestData.toArmoredForm();
            testCase.getWorkerSession().setWorkerProperty(workerId, "PGPPUBLICKEY",
                                                        pgpPublicKey);
            testCase.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY",
                                                        "signer00003");
            testCase.getWorkerSession().reloadConfiguration(workerId);

            status = testCase.getWorkerSession().getStatus(wi);
            assertTrue("Worker active: " + status.getFatalErrors().toString(),
                       status.getFatalErrors().isEmpty());
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    /**
     * Tests adding a User Id to the public key, sign something producing 
     * detached signature and verifying it with client-side option.
     *
     * @throws Exception
     */
    @Test
    public void testAddUserIdDetachedSignAndVerify_clientSide() throws Exception {
        addUserIdDetachedSignAndVerify(true, "NONEwithRSA", "SHA256", HashAlgorithmTags.SHA256, SIGNER00003, SIGNER00003_KEYID);
    }

    /**
     * Tests with a different key, client-side.
     *
     * @throws Exception
     */
    @Test
    public void testAddUserIdDetachedSignAndVerify_clientSide_otherKeyId() throws Exception {
        addUserIdDetachedSignAndVerify(true, "NONEwithRSA", "SHA256", HashAlgorithmTags.SHA256, SIGNER00001, SIGNER00001_KEYID);
    }

    /**
     * Tests adding a User Id to the public key, sign something producing 
     * detached signature and verifying it.
     *
     * @throws Exception
     */
    @Test
    public void testAddUserIdDetachedSignAndVerify_serverSide() throws Exception {
        addUserIdDetachedSignAndVerify(false, "SHA256withRSA", null, HashAlgorithmTags.SHA256, SIGNER00003, SIGNER00003_KEYID);
    }
    
    /**
     * Tests with a different key, server-side.
     *
     * @throws Exception
     */
    @Test
    public void testAddUserIdDetachedSignAndVerify_serverSide_otherKeyId() throws Exception {
        addUserIdDetachedSignAndVerify(false, "SHA256withRSA", null, HashAlgorithmTags.SHA256, SIGNER00001, SIGNER00001_KEYID);
    }
    
    private void setupOpenPGPSignerOnlyProperties(final int workerId, final String signatureAlgorithm, final String keyAlias, final boolean detachedSignature) throws Exception {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.openpgp.signer.OpenPGPSigner");
        workerSession.setWorkerProperty(workerId, "NAME", "OpenPGPSigner" + workerId);
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", testCase.getSignerNameDummy1());
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", keyAlias);
        workerSession.setWorkerProperty(workerId, "DETACHEDSIGNATURE", String.valueOf(detachedSignature));
        workerSession.setWorkerProperty(workerId, "SIGNATUREALGORITHM", signatureAlgorithm);
    }

    private void setupOpenPGPPlainSignerOnlyProperties(final int workerId, final String signatureAlgorithm, final String keyAlias) throws Exception {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.openpgp.enterprise.signer.PGPPlainSigner");
        workerSession.setWorkerProperty(workerId, "NAME", "OpenPGPPlainSigner" + workerId);
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", testCase.getSignerNameDummy1());
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", keyAlias);
        workerSession.setWorkerProperty(workerId, "SIGNATUREALGORITHM", signatureAlgorithm);
    }

    /**
     * Tests adding a User Id to the public key, sign something using CLI
     * producing detached signature and verifying it.
     *
     * @param clientSide if client-side option should be used
     * @throws Exception
     */
    private void addUserIdDetachedSignAndVerify(final boolean clientSide, final String signatureAlgorithm, final String clientSideDigestAlgorithm, final int expectedHashAlgorithm, final String keyAlias, final String keyId) throws Exception {
        LOG.info("addUserIdDetachedSignAndVerify-" + (clientSide ? "clientSide" : "serverSide"));
        int workerId = 0;
        try {
            final File outFile = File.createTempFile("outfile-", ".asc");
            testCase.addDummySigner1(true);
            if (clientSide) {
                workerId = WORKER_OPENPGPPLAINSIGNER;
                setupOpenPGPPlainSignerOnlyProperties(WORKER_OPENPGPPLAINSIGNER, signatureAlgorithm, keyAlias);
                if (clientSideDigestAlgorithm == null) {
                    throw new Exception("Must specify digest algorithm for testing client-side");
                }
            } else {
                workerId = WORKER_OPENPGPSIGNER;
                setupOpenPGPSignerOnlyProperties(WORKER_OPENPGPSIGNER, signatureAlgorithm, keyAlias, true);
                if (clientSideDigestAlgorithm != null) {
                    throw new Exception("Must not specify digest algorithm for testing server-side");
                }
            }
            workerSession.reloadConfiguration(testCase.getSignerIdDummy1());
            workerSession.reloadConfiguration(WORKER_OPENPGPSIGNER);

            // Generate the public key
            final String userId = "Worker (" + workerId + ") <worker@example.com>";
            final PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA256WithRSA", userId, null);
            AbstractCertReqData csr = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);
            assertNotNull(csr);
            String publicKeyArmored = csr.toArmoredForm();
            assertTrue("public key header: " + publicKeyArmored, publicKeyArmored.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
            assertTrue("public key footer: " + publicKeyArmored, publicKeyArmored.contains("-----END PGP PUBLIC KEY BLOCK-----"));

            // Store the updated public key
            workerSession.setWorkerProperty(workerId, "PGPPUBLICKEY", publicKeyArmored);
            workerSession.reloadConfiguration(workerId);

            // Check the status has no errors and that the user id is printed
            WorkerStatus status = workerSession.getStatus(new WorkerIdentifier(workerId));
            assertEquals("fatal errors", "[]", status.getFatalErrors().toString());
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            status.displayStatus(new PrintStream(bout), true);
            String statusOutput = bout.toString(StandardCharsets.UTF_8.toString());
            assertTrue("key contains user id: " + statusOutput, statusOutput.contains(userId));

            // Test signing
            final byte[] originalData = FileUtils.readFileToByteArray(sampleBinaryFile);
            if (clientSide) {
                assertEquals("Status code", ClientCLI.RETURN_SUCCESS,
                         CLI.execute("signdocument", "-workerid",
                                     String.valueOf(workerId),
                                     "-infile", sampleBinaryFile.getAbsolutePath(),
                                     "-outfile", outFile.getAbsolutePath(),
                                     "-clientside",
                                     "-filetype", "PGP",
                                     "-digestalgorithm", clientSideDigestAlgorithm,
                                     "-extraoption", "KEY_ID=" + keyId));
            } else {
                assertEquals("Status code", ClientCLI.RETURN_SUCCESS,
                         CLI.execute("signdocument", "-workerid",
                                     String.valueOf(workerId),
                                     "-infile", sampleBinaryFile.getAbsolutePath(),
                                     "-outfile", outFile.getAbsolutePath()));
            }
            final byte[] signedBytes = FileUtils.readFileToByteArray(outFile);


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
            
            assertEquals("hash algorithm", expectedHashAlgorithm, sig.getHashAlgorithm());
            assertEquals("key id", new BigInteger(keyId, 16).longValue(), sig.getKeyID());
            
        } finally {
            testCase.removeWorker(testCase.getSignerIdDummy1());
            if (workerId != 0) {
                testCase.removeWorker(workerId);
            }
        }
    }
    // TODO: See OpenPGPP11SignTest.java for a clear-text version of above method

    private BCPGInputStream createInputStream(InputStream in, boolean armored) throws IOException {
        return new BCPGInputStream(armored ? new ArmoredInputStream(in) : in);
    }

}
