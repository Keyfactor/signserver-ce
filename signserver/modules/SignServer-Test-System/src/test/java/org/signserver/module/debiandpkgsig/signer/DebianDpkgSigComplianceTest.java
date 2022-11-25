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

import org.signserver.module.openpgp.signer.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import static junit.framework.TestCase.assertTrue;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPPublicKey;
import static org.junit.Assert.assertEquals;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.client.cli.ClientCLI;
import org.signserver.common.AbstractCertReqData;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.util.PropertiesConstants;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ComplianceTestUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * Compliance test running dpkg-sig to verify signatures created by the
 * DebianDpkgSigSigner.
 *
 * These tests can be disabled by setting the test.dpkgsig.enabled test
 * configuration parameter to false for test environments where the dpkg-sig
 * CLI tool is not available.
 *
 * @author Markus Kilås
 * @author Marcus Lundblad
 * @version $Id$
 */
public class DebianDpkgSigComplianceTest {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(DebianDpkgSigComplianceTest.class);
    private static final String DPKGSIG_ENABLED = "test.dpkgsig.enabled";
    private static final String HELLO_DEB = "res/test/HelloDeb.deb";
    
    private static final int WORKER_DEBIANDPKGSIGSIGNER = 40000;
    private static final int WORKER_OPENPGPPLAINSIGNER = 41000;
    
    private static final String WORKER_DEBIANDPKGSIGSIGNER_CLASS_NAME = "org.signserver.module.debiandpkgsig.signer.DebianDpkgSigSigner";
    private static final String WORKER_OPENPGPPLAINSIGNER_CLASS_NAME = "org.signserver.module.openpgp.enterprise.signer.OpenPGPPlainSigner";

    private static final String MYKEY_KEYID = "1FBDD942533B1793";
    private static final String MYKEY_KEY_FINGERPRINT = "1398A0B6CA0807EEB39CC2A11FBDD942533B1793";
    private static final String TS40003_KEYID = "019B2B04267FE968";
    private static final String TS40003_KEY_FINGERPRINT = "5D165C36B0B019BBF2D40E44019B2B04267FE968";
    private static final String SIGNER00002_KEYID = "E3091F74636A925E";
    private static final String SIGNER00002_KEY_FINGERPRINT = "4C1EAD9A968EC39AB9A2F7F5E3091F74636A925E";
    private static final String SIGNER00001_KEYID = "4B821662F54A5923";    
    private static final String SIGNER00001_KEY_FINGERPRINT = "23C0B776EEE6A30D6530ACD44B821662F54A5923";
    
    private static final String RSA_KEY_ALGORITHM = String.valueOf(PublicKeyAlgorithmTags.RSA_SIGN);
    private static final String ECDSA_KEY_ALGORITHM = String.valueOf(PublicKeyAlgorithmTags.ECDSA);
    private static final String DSA_KEY_ALGORITHM = String.valueOf(PublicKeyAlgorithmTags.DSA);

    private final ModulesTestCase helper = new ModulesTestCase();
    private static final CLITestHelper CLI = new CLITestHelper(ClientCLI.class);

    private static boolean enabled;
    private static boolean ecdsaSupported;

    @BeforeClass
    public static void setUpClass() throws IOException {
        enabled = Boolean.valueOf(new ModulesTestCase().getConfig().getProperty(DPKGSIG_ENABLED));
        if (enabled) {
            final ComplianceTestUtils.ProcResult res =
                ComplianceTestUtils.execute("gpg2", "--version");
            final String output = ComplianceTestUtils.toString(res.getOutput());
            LOG.info("GPG version output: " + output);
            ecdsaSupported = output.contains("ECDSA");
        }
    }

    @Before
    public void setUpTest() {
        Assume.assumeTrue("dpkg-sig enabled", enabled);
    }

    /**
     * Test that the command "gpg2 --version" prints a reasonable message.
     * And log the version string, so that it's visible in the stdout from the
     * test.
     *
     * @throws Exception
     */
    @Test
    public void testGpgVersion() throws Exception {
        final ComplianceTestUtils.ProcResult res =
                ComplianceTestUtils.execute("gpg2", "--version");
        final String output = ComplianceTestUtils.toString(res.getOutput());

        assertTrue("Contains GPG message", output.startsWith("gpg (GnuPG)"));
        LOG.info("GPG version output: " + output);
    }

    @Test
    public void testSigning_RSA_SHA256_ServerSide() throws Exception {
        signAndVerify("rsa2048", "SHA-256", RSA_KEY_ALGORITHM, HELLO_DEB, false);
    }
    
    @Test
    public void testSigning_RSA_SHA256_ClientSide() throws Exception {
        signAndVerify("rsa2048", "SHA-256", RSA_KEY_ALGORITHM, HELLO_DEB, true);
    }

    @Test
    public void testSigning_RSA_SHA1_ServerSide() throws Exception {
        signAndVerify("rsa2048", "SHA-1", RSA_KEY_ALGORITHM, HELLO_DEB, false);
    }
    
    @Test
    public void testSigning_RSA_SHA1_ClientSide() throws Exception {
        signAndVerify("rsa2048", "SHA-1", RSA_KEY_ALGORITHM, HELLO_DEB, true);
    }

    // Not supported by BC/ArmoredOutputStream
    //@Test
    //public void testSigning_RSA_SHA224() throws Exception {
    //    signAndVerify("rsa2048", "SHA-224", HELLO_DEB);
    //}

    @Test
    public void testSigning_RSA_SHA384_ServerSide() throws Exception {
        signAndVerify("rsa2048", "SHA-384", RSA_KEY_ALGORITHM, HELLO_DEB, false);
    }
    
    @Test
    public void testSigning_RSA_SHA384_ClientSide() throws Exception {
        signAndVerify("rsa2048", "SHA-384", RSA_KEY_ALGORITHM, HELLO_DEB, true);
    }

    @Test
    public void testSigning_RSA_SHA512_ServerSide() throws Exception {
        signAndVerify("rsa2048", "SHA-512", RSA_KEY_ALGORITHM, HELLO_DEB, false);
    }
    
    @Test
    public void testSigning_RSA_SHA512_ClientSide() throws Exception {
        signAndVerify("rsa2048", "SHA-512", RSA_KEY_ALGORITHM, HELLO_DEB, true);
    }

    @Test
    public void testSigning_ECDSA_SHA256_ServerSide() throws Exception {
        Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
        signAndVerify("nistp256", "SHA-256", ECDSA_KEY_ALGORITHM, HELLO_DEB, false);
    }
    
    @Test
    public void testSigning_ECDSA_SHA256_ClientSide() throws Exception {
        Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
        signAndVerify("nistp256", "SHA-256", ECDSA_KEY_ALGORITHM, HELLO_DEB, true);
    }

    // Note: GPG won't accept SHA-1 with a 256-bit curve
    //@Test
    //public void testSigning_ECDSA_SHA1() throws Exception {
    //    Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
    //    signAndVerify("nistp256", "SHA-1");
    //}

    // Note: GPG won't accept SHA-224 with a 256-bit curve
    //@Test
    //public void testSigning_ECDSA_SHA224() throws Exception {
    //    Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
    //    signAndVerify("nistp256", "SHA-224");
    //}

    @Test
    public void testSigning_ECDSA_SHA384_ServerSide() throws Exception {
        Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
        signAndVerify("nistp256", "SHA-384", ECDSA_KEY_ALGORITHM, HELLO_DEB, false);
    }
    
    @Test
    public void testSigning_ECDSA_SHA384_ClientSide() throws Exception {
        Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
        signAndVerify("nistp256", "SHA-384", ECDSA_KEY_ALGORITHM, HELLO_DEB, true);
    }

    @Test
    public void testSigning_ECDSA_SHA512_ServerSide() throws Exception {
        Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
        signAndVerify("nistp256", "SHA-512", ECDSA_KEY_ALGORITHM, HELLO_DEB, false);
    }
    
    @Test
    public void testSigning_ECDSA_SHA512_ClientSide() throws Exception {
        Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
        signAndVerify("nistp256", "SHA-512", ECDSA_KEY_ALGORITHM, HELLO_DEB, true);
    }

    @Test
    public void testSigning_RSA4096_SHA256_ServerSide() throws Exception {
        signAndVerify("rsa4096", "SHA-256", RSA_KEY_ALGORITHM, HELLO_DEB, false);
    }
    
    @Test
    public void testSigning_RSA4096_SHA256_ClientSide() throws Exception {
        signAndVerify("rsa4096", "SHA-256", RSA_KEY_ALGORITHM, HELLO_DEB, true);
    }

    @Test
    public void testSigning_RSA4096_SHA1_ServerSide() throws Exception {
        signAndVerify("rsa4096", "SHA-1", RSA_KEY_ALGORITHM, HELLO_DEB, false);
    }
    
    @Test
    public void testSigning_RSA4096_SHA1_ClientSide() throws Exception {
        signAndVerify("rsa4096", "SHA-1", RSA_KEY_ALGORITHM, HELLO_DEB, true);
    }

    // Not supported by BC/ArmoredOutputStream
    //@Test
    //public void testSigning_RSA4096_SHA224() throws Exception {
    //    signAndVerify("rsa4096", "SHA-224", HELLO_DEB);
    //}

    @Test
    public void testSigning_RSA4096_SHA384_ServerSide() throws Exception {
        signAndVerify("rsa4096", "SHA-384", RSA_KEY_ALGORITHM, HELLO_DEB, false);
    }
    
    @Test
    public void testSigning_RSA4096_SHA384_ClientSide() throws Exception {
        signAndVerify("rsa4096", "SHA-384", RSA_KEY_ALGORITHM, HELLO_DEB, true);
    }

    @Test
    public void testSigning_RSA4096_SHA512_ServerSide() throws Exception {
        signAndVerify("rsa4096", "SHA-512", RSA_KEY_ALGORITHM, HELLO_DEB, false);
    }
    
    @Test
    public void testSigning_RSA4096_SHA512_ClientSide() throws Exception {
        signAndVerify("rsa4096", "SHA-512", RSA_KEY_ALGORITHM, HELLO_DEB, true);
    }

    @Test
    public void testSigning_DSA1024_SHA256_ServerSide() throws Exception {
        signAndVerify("dsa1024", "SHA-256", DSA_KEY_ALGORITHM, HELLO_DEB, false);
    }
    
    // for DSA signatures in client-side mode, other algorithms than SHA1 may not be supported due to the underlying implementation.
//    @Test
//    public void testSigning_DSA1024_SHA256_ClientSide() throws Exception {
//        signAndVerify("dsa1024", "SHA-256", RSA_KEY_ALGORITHM, HELLO_DEB, true);
//    }

    @Test
    public void testSigning_DSA1024_SHA1_ServerSide() throws Exception {
        signAndVerify("dsa1024", "SHA-1", DSA_KEY_ALGORITHM, HELLO_DEB, false);
    }
    
    @Test
    public void testSigning_DSA1024_SHA1_ClientSide() throws Exception {
        signAndVerify("dsa1024", "SHA-1", DSA_KEY_ALGORITHM, HELLO_DEB, true);
    }

    // Not supported by BC/ArmoredOutputStream
    //@Test
    //public void testSigning_DSA1024_SHA224() throws Exception {
    //    signAndVerify("dsa1024", "SHA-224", HELLO_DEB);
    //}

    // Note: Not supported with SUN/JKS:
    //@Test
    //public void testSigning_DSA1024_SHA384() throws Exception {
    //    signAndVerify("dsa1024", "SHA-384");
    //}

    // Note: Not supported with SUN/JKS:
    //@Test
    //public void testSigning_DSA1024_SHA512() throws Exception {
    //    signAndVerify("dsa1024", "SHA-512");
    //}    

    // Note: Not supported by BC:
    //@Test
    //public void testSigning_RSA_SHA224_clearText() throws Exception {
    //    signAndVerify("rsa2048", "SHA-224", false, false);
    //}    

    // Note: Not supported by BC:
    //@Test
    //public void testSigning_RSA4096_SHA224_clearText() throws Exception {
    //    signAndVerify("rsa4096", "SHA-224", false, false);
    //}    

    // Note: Not supported by BC:
    //@Test
    //public void testSigning_DSA1024_SHA224_clearText() throws Exception {
    //    signAndVerify("dsa1024", "SHA-224", false, false);
    //}

    /**
     * Sets up a signer using a key with the chosen algorithm,
     * then adds a user ID to the public key,
     * then imports the public key in a new local key ring and trusts it,
     * then performs a signing,
     * then verifies the signature using GPG2 and checks that it succeeds
     * and has the expected algorithms.
     *
     * @param expectedKeyAlgorithm in gpg format
     * @param digestAlgorithm to use
     * @param revokeAfter if true, issue and import a revocation certificate afterwards
     * @throws Exception
     */
    private void signAndVerify(final String expectedKeyAlgorithm, final String digestAlgorithm, String keyAlgorithm, String inputFile, boolean clientSide) throws Exception {
        final int workerId = clientSide ? WORKER_OPENPGPPLAINSIGNER : WORKER_DEBIANDPKGSIGSIGNER;
        final String workerName = workerId + expectedKeyAlgorithm + "-" + digestAlgorithm;
        final String signerClassName = clientSide ? WORKER_OPENPGPPLAINSIGNER_CLASS_NAME : WORKER_DEBIANDPKGSIGSIGNER_CLASS_NAME;
        final File inFile = new File(helper.getSignServerHome(), inputFile);
        final File outFile = File.createTempFile("HelloDeb", "-signed.deb");
        final File gpgHome = Files.createTempDirectory("debiandpkgsigsigner-gnupghome").toFile();
        final String[] envp = new String[]{"GNUPGHOME=" + gpgHome.getAbsolutePath()};
        final File publicKeyFile = File.createTempFile("pubkey", ".gpg");
        final String userId = "User 1 (Code Signing) <user1@example.com>";
        String keyId;
        String keyFingerPrint;

        try {

            helper.addSigner(signerClassName, workerId, workerName, true);
            switch (expectedKeyAlgorithm) {
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
                    final File keystore = new File(helper.getSignServerHome(), "res/test/dss10/dss10_tssigner6dsa.jks");
                    helper.getWorkerSession().setWorkerProperty(workerId, PropertiesConstants.CRYPTOTOKEN_IMPLEMENTATION_CLASS, "org.signserver.server.cryptotokens.JKSCryptoToken");
                    helper.getWorkerSession().setWorkerProperty(workerId, "KEYSTOREPATH", keystore.getAbsolutePath());
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", "mykey");
                    keyId = MYKEY_KEYID;
                    keyFingerPrint = MYKEY_KEY_FINGERPRINT;
                    break;
                }
                default: {
                    throw new UnsupportedOperationException("Test does not support key algorithm: " + expectedKeyAlgorithm);
                }
            }

            // DIGEST_ALGORITHM will be only used by signer (for producing clear text control file signature) in case of server side dpkg-sig signature 
            helper.getWorkerSession().setWorkerProperty(workerId, "DIGEST_ALGORITHM", digestAlgorithm);
            helper.getWorkerSession().reloadConfiguration(workerId);

            // Add User ID and get public key
            final AbstractCertReqData requestData = (AbstractCertReqData) helper.getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), new PKCS10CertReqInfo(digestAlgorithm + "withRSA", userId, null), false);
            final byte[] publicKeyBytes = requestData.toBinaryForm();
            FileUtils.writeByteArrayToFile(publicKeyFile, publicKeyBytes);
            final PGPPublicKey pgpPublicKey = OpenPGPUtils.parsePublicKeys(requestData.toArmoredForm()).get(0);

            // Import public key
            ComplianceTestUtils.ProcResult res = ComplianceTestUtils.executeWithEnv(envp, "gpg2",
                    "--import", publicKeyFile.getAbsolutePath());
            assertEquals("gpg2 --import: " + res.getErrorMessage(), 0, res.getExitValue());

            // Trust public key
            // Equaivalent of Bash: echo -e "trust\n5\ny\nsave\n" | gpg --command-fd 0 --edit-key F7B50A4D55F6E703
            res = ComplianceTestUtils.executeWritingWithEnv("trust\n5\ny\nsave\n".getBytes(), envp, "gpg2",
                    "--command-fd", "0", "--no-tty", "--edit-key", OpenPGPUtils.formatKeyID(pgpPublicKey.getKeyID()));
            assertEquals("gpg2 --edit-key: " + res.getErrorMessage(), 0, res.getExitValue());

            // Sign
            if (clientSide) {
                assertEquals("Status code", ClientCLI.RETURN_SUCCESS,
                        CLI.execute("signdocument", "-workername",
                                workerName,
                                "-infile", inFile.getAbsolutePath(),
                                "-outfile", outFile.getAbsolutePath(),
                                "-clientside",
                                "-filetype", "DPKG_SIG",
                                "-digestalgorithm", digestAlgorithm,
                                "-extraoption", "KEY_ID=" + keyId,
                                "-extraoption", "KEY_ALGORITHM=" + keyAlgorithm,
                                "-extraoption", "KEY_FINGERPRINT=" + keyFingerPrint));
            } else {
                assertEquals("Status code", ClientCLI.RETURN_SUCCESS,
                        CLI.execute("signdocument", "-workername",
                                workerName,
                                "-infile", inFile.getAbsolutePath(),
                                "-outfile", outFile.getAbsolutePath()));
            }

            // Verify
            res = ComplianceTestUtils.executeWithEnv(envp, "dpkg-sig",
                        "--verify", outFile.getAbsolutePath());

            final String output = res.getErrorMessage();

            assertTrue("Expecting Good signature: " + res.getOutput().toString(), res.getOutput().get(1).contains("GOODSIG"));
            assertEquals("return code", 0, res.getExitValue());

        } finally {
            helper.removeWorker(workerId);
            FileUtils.deleteQuietly(outFile);
            FileUtils.deleteQuietly(gpgHome);
            FileUtils.deleteQuietly(publicKeyFile);
        }
    }

}
