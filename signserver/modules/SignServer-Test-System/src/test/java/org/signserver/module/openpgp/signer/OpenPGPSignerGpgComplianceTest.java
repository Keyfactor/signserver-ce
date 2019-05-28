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

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import static junit.framework.TestCase.assertTrue;
import static junit.framework.TestCase.fail;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPPublicKey;
import static org.junit.Assert.assertEquals;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.admin.cli.AdminCLI;
import org.signserver.client.cli.ClientCLI;
import org.signserver.common.AbstractCertReqData;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.util.PropertiesConstants;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ComplianceTestUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * Compliance test running GPG to verify signatures created by the
 * OpenPGPSigner.
 *
 * These tests can be disabled by setting the test.gpg.enabled test
 * configuration parameter to false for test environments where the gpg2
 * CLI tool is not available.
 *
 * @author Markus Kilås
 * @author Marcus Lundblad
 * @version $Id: TimeStampSignerOpenSslComplianceTest.java 9042 2018-01-18 10:16:57Z malu9369 $
 */
public class OpenPGPSignerGpgComplianceTest {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(OpenPGPSignerGpgComplianceTest.class);
    private static final String GPG_ENABLED = "test.gpg.enabled";

    private final ModulesTestCase helper = new ModulesTestCase();
    private static final CLITestHelper CLI = new CLITestHelper(ClientCLI.class);
    private static final CLITestHelper AdminCLI = new CLITestHelper(AdminCLI.class);
    
    private static final String RSA2048_ALIAS = "signer00001";
    private static final String RSA2048_KEYID = "4B821662F54A5923";
    private static final String RSA4096_ALIAS = "ts40003";
    private static final String RSA4096_KEYID = "019B2B04267FE968";
    private static final String NISTP256_ALIAS = "signer00002";
    private static final String NISTP256_KEYID = "E3091F74636A925E";
    private static final String DSA2048_ALIAS = "signer00004";
    private static final String DSA2048_KEYID = "EFF9ED546884D030";

    private static boolean enabled;
    private static boolean ecdsaSupported;

    @BeforeClass
    public static void setUpClass() throws IOException {
        enabled = Boolean.valueOf(new ModulesTestCase().getConfig().getProperty(GPG_ENABLED));
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
        Assume.assumeTrue("GPG enabled", enabled);
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
    public void testSigning_RSA_SHA256() throws Exception {
        signAndVerify("rsa2048", "SHA-256", false, true, false, null);
    }

    @Test
    public void testSigning_RSA_SHA256_clientSide() throws Exception {
        signAndVerify("rsa2048", "SHA-256", false, true, true, RSA2048_KEYID);
    }

    @Test
    public void testSigning_RSA_SHA512_clientSide() throws Exception {
        signAndVerify("rsa2048", "SHA-512", false, true, true, RSA2048_KEYID);
    }
    
    @Test
    public void testSigning_DSA_SHA256_clientSide() throws Exception {
        signAndVerify("dsa2048", "SHA-256", false, true, true, DSA2048_KEYID,
                      PublicKeyAlgorithmTags.DSA);
    }
 
    @Test
    public void testSigning_ECDSA_SHA256_clientSide() throws Exception {
        signAndVerify("nistp256", "SHA-256", false, true, true, NISTP256_KEYID,
                      PublicKeyAlgorithmTags.ECDSA);
    }
    
    @Test
    public void testSigning_RSA_SHA1() throws Exception {
        signAndVerify("rsa2048", "SHA-1", false, true, false, null);
    }

    @Test
    public void testSigning_RSA_SHA224() throws Exception {
        signAndVerify("rsa2048", "SHA-224", false, true, false, null);
    }

    @Test
    public void testSigning_RSA_SHA384() throws Exception {
        signAndVerify("rsa2048", "SHA-384", false, true, false, null);
    }

    @Test
    public void testSigning_RSA_SHA512() throws Exception {
        signAndVerify("rsa2048", "SHA-512", false, true, false, null);
    }

    @Test
    public void testSigning_ECDSA_SHA256() throws Exception {
        Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
        signAndVerify("nistp256", "SHA-256", false, true, false, null);
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
    public void testSigning_ECDSA_SHA384() throws Exception {
        Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
        signAndVerify("nistp256", "SHA-384", false, true, false, null);
    }

    @Test
    public void testSigning_ECDSA_SHA512() throws Exception {
        Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
        signAndVerify("nistp256", "SHA-512", false, true, false, null);
    }

    @Test
    public void testSigning_RSA4096_SHA256() throws Exception {
        signAndVerify("rsa4096", "SHA-256", false, true, false, null);
    }

    @Test
    public void testSigning_RSA4096_SHA256_clientSide() throws Exception {
        signAndVerify("rsa4096", "SHA-256", false, true, true, RSA4096_KEYID);
    }

    @Test
    public void testSigning_RSA4096_SHA1() throws Exception {
        signAndVerify("rsa4096", "SHA-1", false, true, false, null);
    }

    @Test
    public void testSigning_RSA4096_SHA224() throws Exception {
        signAndVerify("rsa4096", "SHA-224", false, true, false, null);
    }

    @Test
    public void testSigning_RSA4096_SHA384() throws Exception {
        signAndVerify("rsa4096", "SHA-384", false, true, false, null);
    }

    @Test
    public void testSigning_RSA4096_SHA512() throws Exception {
        signAndVerify("rsa4096", "SHA-512", false, true, false, null);
    }

    @Test
    public void testSigning_DSA1024_SHA256() throws Exception {
        signAndVerify("dsa1024", "SHA-256", false, true, false, null);
    }

    @Test
    public void testSigning_DSA1024_SHA1() throws Exception {
        signAndVerify("dsa1024", "SHA-1", false, true, false, null);
    }

    @Test
    public void testSigning_DSA1024_SHA224() throws Exception {
        signAndVerify("dsa1024", "SHA-224", false, true, false, null);
    }

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

    @Test
    public void testSigning_RSA_SHA256_clearText() throws Exception {
        signAndVerify("rsa2048", "SHA-256", false, false, false, null);
    }

    @Test
    public void testSigning_RSA_SHA1_clearText() throws Exception {
        signAndVerify("rsa2048", "SHA-1", false, false, false, null);
    }

    // Note: Not supported by BC:
    //@Test
    //public void testSigning_RSA_SHA224_clearText() throws Exception {
    //    signAndVerify("rsa2048", "SHA-224", false, false);
    //}

    @Test
    public void testSigning_RSA_SHA384_clearText() throws Exception {
        signAndVerify("rsa2048", "SHA-384", false, false, false, null);
    }

    @Test
    public void testSigning_RSA_SHA512_clearText() throws Exception {
        signAndVerify("rsa2048", "SHA-512", false, false, false, null);
    }

    @Test
    public void testSigning_ECDSA_SHA256_clearText() throws Exception {
        Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
        signAndVerify("nistp256", "SHA-256", false, false, false, null);
    }

    @Test
    public void testSigning_ECDSA_SHA384_clearText() throws Exception {
        Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
        signAndVerify("nistp256", "SHA-384", false, false, false, null);
    }

    @Test
    public void testSigning_ECDSA_SHA512_clearText() throws Exception {
        Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
        signAndVerify("nistp256", "SHA-512", false, false, false, null);
    }

    @Test
    public void testSigning_RSA4096_SHA256_clearText() throws Exception {
        signAndVerify("rsa4096", "SHA-256", false, false, false, null);
    }

    @Test
    public void testSigning_RSA4096_SHA1_clearText() throws Exception {
        signAndVerify("rsa4096", "SHA-1", false, false, false, null);
    }

    // Note: Not supported by BC:
    //@Test
    //public void testSigning_RSA4096_SHA224_clearText() throws Exception {
    //    signAndVerify("rsa4096", "SHA-224", false, false);
    //}

    @Test
    public void testSigning_RSA4096_SHA384_clearText() throws Exception {
        signAndVerify("rsa4096", "SHA-384", false, false, false, null);
    }

    @Test
    public void testSigning_RSA4096_SHA512_clearText() throws Exception {
        signAndVerify("rsa4096", "SHA-512", false, false, false, null);
    }

    @Test
    public void testSigning_DSA1024_SHA256_clearText() throws Exception {
        signAndVerify("dsa1024", "SHA-256", false, false, false, null);
    }

    @Test
    public void testSigning_DSA1024_SHA1_clearText() throws Exception {
        signAndVerify("dsa1024", "SHA-1", false, false, false, null);
    }

    // Note: Not supported by BC:
    //@Test
    //public void testSigning_DSA1024_SHA224_clearText() throws Exception {
    //    signAndVerify("dsa1024", "SHA-224", false, false);
    //}

    /**
     * Test signing and later revoking with RSA and SHA256
     * @throws Exception 
     */
    @Test
    public void testSigning_RSA_SHA256withRevocation() throws Exception {
        signAndVerify("rsa2048", "SHA-256", true, true, false, null);
    }
 
    /**
     * Test signing and later revoking with RSA and SHA1
     * @throws Exception 
     */
    @Test
    public void testSigning_RSA_SHA1withRevocation() throws Exception {
        signAndVerify("rsa2048", "SHA-1", true, true, false, null);
    }
    
    /**
     * Test signing and later revoking with ECDSA and SHA256
     * @throws Exception 
     */
    @Test
    public void testSigning_ECDSA_SHA256withRevocation() throws Exception {
        Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
        signAndVerify("nistp256", "SHA-256", true, true, false, null);
    }
    
    /**
     * Test signing and later revoking with DSA and SHA256
     * @throws Exception 
     */
    @Test
    public void testSigning_DSA1024_SHA256withRevocation() throws Exception {
        signAndVerify("dsa1024", "SHA-256", true, true, false, null);
    }

    private void signAndVerify(final String expectedKeyAlgorithm,
                               final String digestAlgorithm,
                               final boolean revokeAfter,
                               final boolean detachedSignature,
                               final boolean clientSide,
                               final String clientSideKeyId) throws Exception {
        signAndVerify(expectedKeyAlgorithm, digestAlgorithm, revokeAfter,
                      detachedSignature, clientSide, clientSideKeyId,
                      PublicKeyAlgorithmTags.RSA_SIGN);
    }
    
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
    private void signAndVerify(final String expectedKeyAlgorithm,
                               final String digestAlgorithm,
                               final boolean revokeAfter,
                               final boolean detachedSignature,
                               final boolean clientSide,
                               final String clientSideKeyId,
                               final int clientSideKeyAlgorithm) throws Exception {
        final int workerId = 42;
        final String workerName = "OpenPGPSigner-" + expectedKeyAlgorithm + "-" + digestAlgorithm + (clientSide ? "clientSide" : "serverSide");
        final File inFile = new File(helper.getSignServerHome(), detachedSignature ? "res/test/HelloJar.jar" : "res/test/stub.c");  // Let's use any binary file as input for detached and any text file for clear-text
        final File outFile = File.createTempFile("HelloJar.jar", ".asc");
        final File gpgHome = Files.createTempDirectory("debiandpkgsigsigner-gnupghome").toFile();
        final String[] envp = new String[] { "GNUPGHOME=" + gpgHome.getAbsolutePath() };
        final File ringFile = File.createTempFile("pubring", ".gpg");
        final File trustFile = File.createTempFile("trustdb", ".gpg");
        final File publicKeyFile = File.createTempFile("pubkey", ".gpg");
        final File csrFile = File.createTempFile("csr", ".rev");
        final File revocationFile = File.createTempFile("revocation", ".rev");
        File clearTextFile = null;
        final String userId = "User 1 (Code Signing) <user1@example.com>";
        final String expectedDigestAlgorithm = digestAlgorithm.replace("-", "");

        try {
            final String implementation;
            if (clientSide) {
                implementation = "org.signserver.module.openpgp.enterprise.signer.OpenPGPPlainSigner";
            } else {
                implementation = "org.signserver.module.openpgp.signer.OpenPGPSigner";
            }

            helper.addSigner(implementation, workerId, workerName, true);
            if (!clientSide) {
                helper.getWorkerSession().setWorkerProperty(workerId, "DETACHEDSIGNATURE", String.valueOf(detachedSignature));
            }
            switch (expectedKeyAlgorithm) {
                case "rsa2048": {
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", RSA2048_ALIAS);
                    if (clientSide) {
                        helper.getWorkerSession().setWorkerProperty(workerId, "SIGNATUREALGORITHM", "NONEwithRSA");
                    }
                    break;
                }
                case "rsa4096": {
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", RSA4096_ALIAS);
                    if (clientSide) {
                        helper.getWorkerSession().setWorkerProperty(workerId, "SIGNATUREALGORITHM", "NONEwithRSA");
                    }
                    break;
                }
                case "nistp256": {
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", NISTP256_ALIAS);
                    if (clientSide) {
                        helper.getWorkerSession().setWorkerProperty(workerId, "SIGNATUREALGORITHM", "NONEwithECDSA");
                    }
                    break;
                }
                case "dsa1024": {
                    final File keystore = new File(helper.getSignServerHome(), "res/test/dss10/dss10_tssigner6dsa.jks");
                    helper.getWorkerSession().setWorkerProperty(workerId, PropertiesConstants.CRYPTOTOKEN_IMPLEMENTATION_CLASS, "org.signserver.server.cryptotokens.JKSCryptoToken");
                    helper.getWorkerSession().setWorkerProperty(workerId, "KEYSTOREPATH", keystore.getAbsolutePath());
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", "mykey");
                    if (clientSide) {
                        helper.getWorkerSession().setWorkerProperty(workerId, "SIGNATUREALGORITHM", "NONEwithDSA");
                    }
                    break;
                }
                case "dsa2048": {
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", DSA2048_ALIAS);
                    if (clientSide) {
                        helper.getWorkerSession().setWorkerProperty(workerId, "SIGNATUREALGORITHM", "NONEwithDSA");
                    }
                    break;
                }
                default: {
                    throw new UnsupportedOperationException("Test does not support key algorithm: " + expectedKeyAlgorithm);
                }
            }

            if (!clientSide) {
                helper.getWorkerSession().setWorkerProperty(workerId, "DIGEST_ALGORITHM", digestAlgorithm);
            }
            helper.getWorkerSession().reloadConfiguration(workerId);

            // Add User ID and get public key
            final AbstractCertReqData requestData = (AbstractCertReqData) helper.getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), new PKCS10CertReqInfo(digestAlgorithm + "withRSA", userId, null), false);
            final byte[] publicKeyBytes = requestData.toBinaryForm();
            FileUtils.writeByteArrayToFile(publicKeyFile, publicKeyBytes);
            final PGPPublicKey pgpPublicKey = OpenPGPUtils.parsePublicKeys(requestData.toArmoredForm()).get(0);

            // Import public key
            trustFile.delete(); // Seems to be a bug in older versions of gpg not liking that the file is empty but non-existing is fine: https://dev.gnupg.org/T2417
            ComplianceTestUtils.ProcResult res = ComplianceTestUtils.executeWithEnv(envp, "gpg2", "--trustdb-name", trustFile.getAbsolutePath(), "--no-default-keyring", "--keyring", ringFile.getAbsolutePath(),
                    "--import", publicKeyFile.getAbsolutePath());
            assertEquals("gpg2 --import: " + res.getErrorMessage(), 0, res.getExitValue());

            // Trust public key
            // Equaivalent of Bash: echo -e "trust\n5\ny\nsave\n" | gpg --command-fd 0 --edit-key F7B50A4D55F6E703
            res = ComplianceTestUtils.executeWritingWithEnv("trust\n5\ny\nsave\n".getBytes(), envp, "gpg2", "--trustdb-name", trustFile.getAbsolutePath(), "--no-default-keyring", "--keyring", ringFile.getAbsolutePath(),
                    "--command-fd", "0", "--no-tty", "--edit-key", OpenPGPUtils.formatKeyID(pgpPublicKey.getKeyID()));
            assertEquals("gpg2 --edit-key: " + res.getErrorMessage(), 0, res.getExitValue());

            // Sign
            if (clientSide) {
                //fail("TODO: Below code should be modified to also supply the key Id and any other needed flags");
                assertEquals("Status code", ClientCLI.RETURN_SUCCESS,
                         CLI.execute("signdocument", "-workername",
                                     workerName,
                                     "-infile", inFile.getAbsolutePath(),
                                     "-outfile", outFile.getAbsolutePath(),
                                     "-clientside",
                                     "-filetype", "PGP",
                                     "-digestalgorithm", digestAlgorithm,
                                     "-extraoption", "KEY_ID=" + clientSideKeyId,
                                     "-extraoption", "KEY_ALGORITHM=" +
                                     Integer.toString(clientSideKeyAlgorithm)));
            } else {
                assertEquals("Status code", ClientCLI.RETURN_SUCCESS,
                         CLI.execute("signdocument", "-workername",
                                     workerName,
                                     "-infile", inFile.getAbsolutePath(),
                                     "-outfile", outFile.getAbsolutePath()));
            }

            // Verify
            if (detachedSignature) {
                // Verify detached signature + input file
                res = ComplianceTestUtils.executeWithEnv(envp, "gpg2", "--trustdb-name", trustFile.getAbsolutePath(), "--no-default-keyring", "--keyring", ringFile.getAbsolutePath(),
                        "--verbose", "--verify", outFile.getAbsolutePath(), inFile.getAbsolutePath());
            } else {
                // Verify clear-text signature
                clearTextFile = File.createTempFile("cleartext", ".txt");
                clearTextFile.delete();
                res = ComplianceTestUtils.executeWithEnv(envp, "gpg2", "--trustdb-name", trustFile.getAbsolutePath(), "--no-default-keyring", "--keyring", ringFile.getAbsolutePath(),
                        "--verbose", "--output", clearTextFile.getAbsolutePath(), "--verify", outFile.getAbsolutePath());
            }

            final String output = res.getErrorMessage();

            assertTrue("Expecting Good signature: " + output, output.contains("gpg: Good signature from \"User 1 (Code Signing) <user1@example.com>\""));
            assertEquals("return code", 0, res.getExitValue());

            assertTrue("Expecting digest algorithm " + expectedDigestAlgorithm + ": " + output, output.contains("digest algorithm " + expectedDigestAlgorithm));
            
            // Check key algorithm but only if it exists as this is not available in older gpg versions
            if (output.contains("key algorithm ")) {
                assertTrue("Expecting key algorithm " + expectedKeyAlgorithm + ": " + output, output.contains("key algorithm " + expectedKeyAlgorithm));
            }
            
            // Verify the output for clear-text signatures
            if (clearTextFile != null) {
                
                // --output was not working together with --verify before GnuPG 2.1.16: https://dev.gnupg.org/T1814
                // so we need to call output explicitly in that case
                if (!clearTextFile.exists()) {
                    LOG.info("File " + clearTextFile.getAbsolutePath() + " did not exist so assuming gpg < 2.1.16");
                    
                    res = ComplianceTestUtils.executeWritingWithEnv(FileUtils.readFileToByteArray(outFile), envp, "gpg2", "--trustdb-name", trustFile.getAbsolutePath(), "--no-default-keyring", "--keyring", ringFile.getAbsolutePath(),
                            "--command-fd", "0", "--no-tty",
                            "--verbose", "--output", clearTextFile.getAbsolutePath());
                    LOG.info("Output output: " + res.getErrorMessage());
                    assertEquals("return code", 0, res.getExitValue());
                }

                // Now read the output
                List<String> expectedLines = FileUtils.readLines(inFile, StandardCharsets.UTF_8);
                List<String> actualLines = FileUtils.readLines(clearTextFile, StandardCharsets.UTF_8);
                assertEquals(expectedLines, actualLines);
            }

            if (revokeAfter) {
                // set to generate revocation certificate on generate CSR
                helper.getWorkerSession().setWorkerProperty(workerId,
                                                            "GENERATE_REVOCATION_CERTIFICATE",
                                                            "true");
                helper.getWorkerSession().reloadConfiguration(workerId);
                
                // Issue a CSR
                assertEquals("Status code", ClientCLI.RETURN_SUCCESS,
                             AdminCLI.execute("generatecertreq",
                                              Integer.toString(workerId),
                                              "Revocation",
                                              getRevocationSigningAlgorithm(expectedKeyAlgorithm,
                                                                            digestAlgorithm),
                                              csrFile.getAbsolutePath()));

                // read CSR file
                String csrString =
                        FileUtils.readFileToString(csrFile, StandardCharsets.UTF_8);
                
                // check that the file contains the short-circuited PGP header
                assertTrue("Contains colon-prefixed PGP header: " + csrString,
                           csrString.contains(":-----BEGIN PGP PUBLIC KEY BLOCK-----"));
                
                // remove short-circuit colon
                csrString = csrString.replaceFirst("\n:", "\n");
                FileUtils.writeStringToFile(revocationFile, csrString,
                                            StandardCharsets.UTF_8);
                
                // import revocation certificate
                res = ComplianceTestUtils.executeWithEnv(envp, "gpg2", "--trustdb-name", trustFile.getAbsolutePath(), "--no-default-keyring", "--keyring", ringFile.getAbsolutePath(),
                    "--import", revocationFile.getAbsolutePath());
                assertEquals("gpg2 --import: " + res.getErrorMessage(), 0, res.getExitValue());

                final String importRevocationOutput = res.getErrorMessage();
                assertTrue("Expecting revocation: " + importRevocationOutput,
                           importRevocationOutput.contains("revocation certificate imported"));
                
                // Verify
                res = ComplianceTestUtils.executeWithEnv(envp, "gpg2", "--trustdb-name", trustFile.getAbsolutePath(), "--no-default-keyring", "--keyring", ringFile.getAbsolutePath(),
                        "--verbose", "--verify", outFile.getAbsolutePath(), inFile.getAbsolutePath());

                final String verifyAfterRevokeOutput = res.getErrorMessage();

                assertTrue("Expecting revocation warning: " + verifyAfterRevokeOutput,
                           verifyAfterRevokeOutput.contains("gpg: WARNING: This key has been revoked by its owner!"));

            }

        } finally {
            helper.removeWorker(workerId);
            FileUtils.deleteQuietly(outFile);
            FileUtils.deleteQuietly(gpgHome);
            FileUtils.deleteQuietly(ringFile);
            FileUtils.deleteQuietly(trustFile);
            FileUtils.deleteQuietly(publicKeyFile);
            FileUtils.deleteQuietly(clearTextFile);
        }
    }

    private String getRevocationSigningAlgorithm(final String keyAlgorithm,
                                                 final String digestAlgorithm)
        throws IllegalArgumentException {
        final String digestPart;
        final String keyalgoPart;

        switch (keyAlgorithm) {
            case "rsa2048":
            case "rsa4096":
                keyalgoPart = "RSA";
                break;
            case "nistp256":
                keyalgoPart = "ECDSA";
                break;
            case "dsa1024":
                keyalgoPart = "DSA";
                break;
            default:
                throw new IllegalArgumentException("Unsupported key algorithm: " + keyAlgorithm);
        }
        
        switch (digestAlgorithm) {
            case "SHA-1":
                digestPart = "SHA1";
                break;
            case "SHA-224":
                digestPart = "SHA224";
                break;
            case "SHA-256":
                digestPart = "SHA256";
                break;
            case "SHA-384":
                digestPart = "SHA384";
                break;
            case "SHA-512":
                digestPart = "SHA512";
                break;
            default:
                throw new IllegalArgumentException("Unsupported digest algorithm: " + digestAlgorithm);
        }
        
        return digestPart + "with" + keyalgoPart;
    }

}
