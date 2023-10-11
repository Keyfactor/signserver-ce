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
package org.signserver.module.debiandpkgsig.signer;

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
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Locale;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import static org.junit.Assert.assertTrue;

import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.util.encoders.Hex;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.client.cli.ClientCLI;
import org.signserver.common.AbstractCertReqData;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.util.PropertiesConstants;
import org.signserver.module.openpgp.signer.OpenPGPUtils;
import org.signserver.openpgp.utils.ClearSignedFileProcessorUtils;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;

/**
 * System tests DebianDpkgSig signing both using server side and client side
 * hashing.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class DebianDpkgSigSignTest {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(DebianDpkgSigSignTest.class);
    private static final String HELLO_DEB = "res/test/HelloDeb.deb";

    
    private static final int WORKER_DEBIANDPKGSIGSIGNER = 40000;

    private static final ModulesTestCase helper = new ModulesTestCase();
    private static final CLITestHelper CLI = new CLITestHelper(ClientCLI.class);
    
    private static final String WORKER_DEBIANDPKGSIGSIGNER_CLASS_NAME = "org.signserver.module.debiandpkgsig.signer.DebianDpkgSigSigner";

    private static final String RSA_KEY_ALGORITHM = String.valueOf(PublicKeyAlgorithmTags.RSA_SIGN);
    private static final String ECDSA_KEY_ALGORITHM = String.valueOf(PublicKeyAlgorithmTags.ECDSA);
    private static final String DSA_KEY_ALGORITHM = String.valueOf(PublicKeyAlgorithmTags.DSA);
    
    private static String MYKEY_KEYID;
    private static String MYKEY_KEY_FINGERPRINT;
    private static final String TS40003_KEYID = "019B2B04267FE968";
    private static final String TS40003_KEY_FINGERPRINT = "5D165C36B0B019BBF2D40E44019B2B04267FE968";
    private static final String SIGNER00002_KEYID = "E3091F74636A925E";
    private static final String SIGNER00002_KEY_FINGERPRINT = "4C1EAD9A968EC39AB9A2F7F5E3091F74636A925E";
    private static final String SIGNER00001_KEYID = "4B821662F54A5923";    
    private static final String SIGNER00001_KEY_FINGERPRINT = "23C0B776EEE6A30D6530ACD44B821662F54A5923";

    @BeforeClass
    public static void setUp() throws Exception {
        SignServerUtil.installBCProvider();

        final String signatureAlgorithm = "SHA256withRSA";

        // Create CA
        final KeyPair caKeyPair = CryptoUtils.generateRSA(1024);
        final String caDN = "CN=Test CA";
        long currentTime = System.currentTimeMillis();
        final X509Certificate caCertificate
                = new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                .setSelfSignKeyPair(caKeyPair)
                .setNotBefore(new Date(currentTime - 120000))
                .setSignatureAlgorithm(signatureAlgorithm)
                .setIssuer(caDN)
                .setSubject(caDN)
                .build());

        // Create signer key-pair (DSA) and issue certificate
        final KeyPair signerKeyPairDSA = CryptoUtils.generateDSA(1024);
        final Certificate[] certChainDSA =
                new Certificate[] {
                        // Code Signer
                        new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                                .setIssuerPrivateKey(caKeyPair.getPrivate())
                                .setSubjectPublicKey(signerKeyPairDSA.getPublic())
                                .setNotBefore(new Date(currentTime - 60000))
                                .setSignatureAlgorithm(signatureAlgorithm)
                                .setIssuer(caDN)
                                .setSubject("CN=Code Signer DSA 2")
                                .build()),

                        // CA
                        caCertificate
                };

        final JcaPGPKeyConverter conv = new JcaPGPKeyConverter();
        PGPPublicKey pgpPublicKey = conv.getPGPPublicKey(OpenPGPUtils.getKeyAlgorithm((X509Certificate) certChainDSA[0]), certChainDSA[0].getPublicKey(), ((X509Certificate) certChainDSA[0]).getNotBefore());
        MYKEY_KEYID = Long.toHexString(pgpPublicKey.getKeyID());
        MYKEY_KEY_FINGERPRINT = Hex.toHexString(pgpPublicKey.getFingerprint()).toUpperCase(Locale.ENGLISH);

        KeyStore ks = KeyStore.getInstance("pkcs12");
        char[] password = "foo123".toCharArray();
        ks.load(null, password);
        ks.setKeyEntry("mykeyDSA", signerKeyPairDSA.getPrivate(), "foo123".toCharArray(), certChainDSA);

        // Store away the keystore.
        try (FileOutputStream fos = new FileOutputStream("tmp/DebianDpkgSigSignTest.p12")) {
            ks.store(fos, password);
        }
    }

    @AfterClass
    public static void tearDown() throws FileNotFoundException {
        final File keystore = new File(helper.getSignServerHome(), "tmp/DebianDpkgSigSignTest.p12");
        keystore.delete();
    }

    @Test
    public void testSigning_RSA_SHA256_ServerSide() throws Exception {
        LOG.info("testSigning_RSA_SHA256_ServerSide");
        signAndVerify("rsa2048", "SHA-256", HashAlgorithmTags.SHA256, RSA_KEY_ALGORITHM, HELLO_DEB, ClientCLI.RETURN_SUCCESS);
    }

    @Test
    public void testSigning_RSA_SHA1_ServerSide() throws Exception {
        LOG.info("testSigning_RSA_SHA1_ServerSide");
        signAndVerify("rsa2048", "SHA-1", HashAlgorithmTags.SHA1, RSA_KEY_ALGORITHM, HELLO_DEB, ClientCLI.RETURN_SUCCESS);
    }
    
    @Test
    public void testSigning_RSA_SHA384_ServerSide() throws Exception {
        LOG.info("testSigning_RSA_SHA384_ServerSide");
        signAndVerify("rsa2048", "SHA-384", HashAlgorithmTags.SHA384, RSA_KEY_ALGORITHM, HELLO_DEB, ClientCLI.RETURN_SUCCESS);
    }

    @Test
    public void testSigning_RSA_SHA512_ServerSide() throws Exception {
        LOG.info("testSigning_RSA_SHA512_ServerSide");
        signAndVerify("rsa2048", "SHA-512", HashAlgorithmTags.SHA512, RSA_KEY_ALGORITHM, HELLO_DEB, ClientCLI.RETURN_SUCCESS);
    }
    
    @Test
    public void testSigning_ECDSA_SHA256_ServerSide() throws Exception {
        LOG.info("testSigning_ECDSA_SHA256_ServerSide");
        signAndVerify("nistp256", "SHA-256", HashAlgorithmTags.SHA256, ECDSA_KEY_ALGORITHM, HELLO_DEB, ClientCLI.RETURN_SUCCESS);
    }
    
    @Test
    public void testSigning_ECDSA_SHA384_ServerSide() throws Exception {
        LOG.info("testSigning_ECDSA_SHA384_ServerSide");
        signAndVerify("nistp256", "SHA-384", HashAlgorithmTags.SHA384, ECDSA_KEY_ALGORITHM, HELLO_DEB, ClientCLI.RETURN_SUCCESS);
    }

    @Test
    public void testSigning_ECDSA_SHA512_ServerSide() throws Exception {
        LOG.info("testSigning_ECDSA_SHA512_ServerSide");
        signAndVerify("nistp256", "SHA-512", HashAlgorithmTags.SHA512, ECDSA_KEY_ALGORITHM, HELLO_DEB, ClientCLI.RETURN_SUCCESS);
    }

    @Test
    public void testSigning_RSA4096_SHA256_ServerSide() throws Exception {
        LOG.info("testSigning_RSA4096_SHA256_ServerSide");
        signAndVerify("rsa4096", "SHA-256", HashAlgorithmTags.SHA256, RSA_KEY_ALGORITHM, HELLO_DEB, ClientCLI.RETURN_SUCCESS);
    }

    @Test
    public void testSigning_RSA4096_SHA1_ServerSide() throws Exception {
        LOG.info("testSigning_RSA4096_SHA1_ServerSide");
        signAndVerify("rsa4096", "SHA-1", HashAlgorithmTags.SHA1, RSA_KEY_ALGORITHM, HELLO_DEB, ClientCLI.RETURN_SUCCESS);
    }

    // Not supported by BC/ArmoredOutputStream
    //@Test
    //public void testSigning_RSA4096_SHA224() throws Exception {
    //    signAndVerify("rsa4096", "SHA-224", HELLO_DEB);
    //}
    
    
    @Test
    public void testSigning_RSA4096_SHA384_ServerSide() throws Exception {
        LOG.info("testSigning_RSA4096_SHA384_ServerSide");
        signAndVerify("rsa4096", "SHA-384", HashAlgorithmTags.SHA384, RSA_KEY_ALGORITHM, HELLO_DEB, ClientCLI.RETURN_SUCCESS);
    }

    @Test
    public void testSigning_RSA4096_SHA512_ServerSide() throws Exception {
        LOG.info("testSigning_RSA4096_SHA512_ServerSide");
        signAndVerify("rsa4096", "SHA-512", HashAlgorithmTags.SHA512, RSA_KEY_ALGORITHM, HELLO_DEB, ClientCLI.RETURN_SUCCESS);
    }

    @Test
    public void testSigning_DSA1024_SHA256_ServerSide() throws Exception {
        LOG.info("testSigning_DSA1024_SHA256_ServerSide");
        signAndVerify("dsa1024", "SHA-256", HashAlgorithmTags.SHA256, DSA_KEY_ALGORITHM, HELLO_DEB, ClientCLI.RETURN_SUCCESS);
    }

    @Test
    public void testSigning_DSA1024_SHA1_ServerSide() throws Exception {
        LOG.info("testSigning_DSA1024_SHA1_ServerSide");
        signAndVerify("dsa1024", "SHA-1", HashAlgorithmTags.SHA1, DSA_KEY_ALGORITHM, HELLO_DEB, ClientCLI.RETURN_SUCCESS);
    }

    // Not supported by BC/ArmoredOutputStream
    //@Test
    //public void testSigning_DSA1024_SHA224() throws Exception {
    //    signAndVerify("dsa1024", "SHA-224", HELLO_DEB);
    //}
    
    /**
     * Sets up a signer using a key with the chosen algorithm, 
     * then adds a user ID to the public key, 
     * then signs deb file using CLI,  
     * then verifies the signature, 
     * checks that it succeeds and 
     * has the expected algorithms.
     *
     * @param chosenKeyAlgorithm
     * @param digestAlgorithm
     * @param expectedHashAlgorithm
     * @param keyAlgorithm
     * @param inputFile
     * @throws Exception
     */
    private void signAndVerify(final String chosenKeyAlgorithm, final String digestAlgorithm, final int expectedHashAlgorithm, String keyAlgorithm, String inputFile, final int expectedOutcome) throws Exception {
        final int workerId = WORKER_DEBIANDPKGSIGSIGNER;
        final String workerName = workerId + chosenKeyAlgorithm + "-" + digestAlgorithm;
        final String signerClassName = WORKER_DEBIANDPKGSIGSIGNER_CLASS_NAME;
        final File inFile = new File(helper.getSignServerHome(), inputFile);
        final File outFile = File.createTempFile("HelloDeb", "-signed.deb");
        String keyId;
        String keyFingerPrint;
                
        final String userId = "User 1 (Code Signing) <user1@example.com>";
        
        try {

            helper.addSigner(signerClassName, workerId, workerName, true);
            switch (chosenKeyAlgorithm) {
                case "rsa2048": {
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", "signer00001");
                    keyId = SIGNER00001_KEYID;
                    keyFingerPrint = SIGNER00001_KEY_FINGERPRINT;
                    break;
                }
                case "rsa4096": {
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", "ts40003");
                    keyId = TS40003_KEYID;
                    keyFingerPrint = TS40003_KEY_FINGERPRINT;
                    break;
                }
                case "nistp256": {
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", "signer00002");
                    keyId = SIGNER00002_KEYID;
                    keyFingerPrint = SIGNER00002_KEY_FINGERPRINT;
                    break;
                }
                case "dsa1024": {
                    final File keystore = new File(helper.getSignServerHome(), "tmp/DebianDpkgSigSignTest.p12");
                    helper.getWorkerSession().setWorkerProperty(workerId, PropertiesConstants.CRYPTOTOKEN_IMPLEMENTATION_CLASS, "org.signserver.server.cryptotokens.JKSCryptoToken");
                    helper.getWorkerSession().setWorkerProperty(workerId, "KEYSTOREPATH", keystore.getAbsolutePath());
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", "mykeydsa");
                    keyId = MYKEY_KEYID;
                    keyFingerPrint = MYKEY_KEY_FINGERPRINT;
                    break;
                }
                case "INVALIDFINGERPRINT": {
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", "signer00001");
                    keyId = SIGNER00001_KEYID;
                    keyFingerPrint = "INVALIDFINGERPRINT";
                    break;
                }
                case "INCORRECTFINGERPRINT": {
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", "signer00001");
                    keyId = SIGNER00001_KEYID;
                    keyFingerPrint = "23C0B776EEE6A30D6530ACD44B821662F54A5920";  // last digit modified from 3 to 0
                    break;
                }
                case "INCORRECTFINGERPRINTKEYID": {
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", "signer00001");
                    keyId = "4B821662F54A5920"; // last digit modified from 3 to 0
                    keyFingerPrint = "23C0B776EEE6A30D6530ACD44B821662F54A5920";  // last digit modified from 3 to 0
                    break;
                }
                default: {
                    throw new UnsupportedOperationException("Test does not support key algorithm: " + keyAlgorithm);
                }
            }

            // DIGEST_ALGORITHM will be only used by signer (for producing clear text control file signature) in case of server side dpkg-sig signature 
            helper.getWorkerSession().setWorkerProperty(workerId, "DIGEST_ALGORITHM", digestAlgorithm);
            helper.getWorkerSession().reloadConfiguration(workerId);

            // Add User ID and get public key
            final AbstractCertReqData requestData = (AbstractCertReqData) helper.getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), new PKCS10CertReqInfo(digestAlgorithm + "withRSA", userId, null), false);
            assertNotNull(requestData);
            String publicKeyArmored = requestData.toArmoredForm();
            assertTrue("public key header: " + publicKeyArmored, publicKeyArmored.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
            assertTrue("public key footer: " + publicKeyArmored, publicKeyArmored.contains("-----END PGP PUBLIC KEY BLOCK-----"));                                              

            // Sign
            assertEquals("Status code", expectedOutcome,
                    CLI.execute("signdocument", "-workername",
                            workerName,
                            "-infile", inFile.getAbsolutePath(),
                            "-outfile", outFile.getAbsolutePath()));

            // Verify signature if signing was successful
            if (expectedOutcome == 0) {
                PGPSignature sig = verifySignature(outFile, publicKeyArmored);
                assertEquals("hash algorithm", expectedHashAlgorithm, sig.getHashAlgorithm());
                assertEquals("key algorithm", Integer.parseInt(keyAlgorithm), sig.getKeyAlgorithm());
                assertEquals("key id", new BigInteger(keyId, 16).longValue(), sig.getKeyID());
            }

        } finally {
            helper.removeWorker(workerId);
            FileUtils.deleteQuietly(outFile);
        }
    }    
    
    private PGPSignature verifySignature(final File outFile, final String publicKeyArmored) throws IOException, PGPException, SignatureException {
        File resultFile = null;
        PGPSignature sig;
        try {
            final byte[] signedBytes = FileUtils.readFileToByteArray(outFile);
            resultFile = File.createTempFile("resultFile", "txt");

            String signed = new String(signedBytes, StandardCharsets.US_ASCII);
            assertTrue("expecting armored: " + signed, signed.startsWith("!<arch>"));

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

            return sig;
        } finally {
            FileUtils.deleteQuietly(resultFile);
        }
    }

    
}
