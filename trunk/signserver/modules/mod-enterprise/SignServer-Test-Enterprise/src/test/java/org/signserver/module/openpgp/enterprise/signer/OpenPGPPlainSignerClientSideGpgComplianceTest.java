/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.openpgp.enterprise.signer;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
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
import org.signserver.admin.cli.AdminCLI;
import org.signserver.client.cli.ClientCLI;
import org.signserver.common.AbstractCertReqData;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.util.PropertiesConstants;
import org.signserver.module.openpgp.signer.OpenPGPUtils;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ComplianceTestUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * Compliance test running GPG to verify signatures created by the
 * OpenPGPPlainSigner.
 *
 * These tests can be disabled by setting the test.gpg.enabled test
 * configuration parameter to false for test environments where the gpg2
 * CLI tool is not available.
 *
 * @author Markus Kilås
 * @author Marcus Lundblad
 * @version $Id$
 */
public class OpenPGPPlainSignerClientSideGpgComplianceTest {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(OpenPGPPlainSignerClientSideGpgComplianceTest.class);
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
        LOG.info("testGpgVersion");
        final ComplianceTestUtils.ProcResult res =
                ComplianceTestUtils.execute("gpg2", "--version");
        final String output = ComplianceTestUtils.toString(res.getOutput());

        assertTrue("Contains GPG message", output.startsWith("gpg (GnuPG)"));
        LOG.info("GPG version output: " + output);
    }    

    @Test
    public void testDetachedSigning_RSA_SHA256_clientSide() throws Exception {
        LOG.info("testDetachedSigning_RSA_SHA256_clientSide");
        signAndVerify("rsa2048", "SHA-256", true, RSA2048_KEYID);
    }
    
    @Test
    public void testClearTextSigning_RSA_SHA256_clientSide() throws Exception {
        LOG.info("testClearTextSigning_RSA_SHA256_clientSide");
        signAndVerify("rsa2048", "SHA-256", false, RSA2048_KEYID);
    }

    @Test
    public void testDetachedSigning_RSA_SHA512_clientSide() throws Exception {
        LOG.info("testDetachedSigning_RSA_SHA512_clientSide");
        signAndVerify("rsa2048", "SHA-512", true, RSA2048_KEYID);
    }
    
    @Test
    public void testClearTextSigning_RSA_SHA512_clientSide() throws Exception {
        LOG.info("testClearTextSigning_RSA_SHA512_clientSide");
        signAndVerify("rsa2048", "SHA-512", false, RSA2048_KEYID);
    }
    
    @Test
    public void testDetachedSigning_DSA_SHA256_clientSide() throws Exception {
        LOG.info("testDetachedSigning_DSA_SHA256_clientSide");
        signAndVerify("dsa2048", "SHA-256", true, DSA2048_KEYID,
                      PublicKeyAlgorithmTags.DSA);
    }
    
    @Test
    public void testClearTextSigning_DSA_SHA256_clientSide() throws Exception {
        LOG.info("testClearTextSigning_DSA_SHA256_clientSide");
        signAndVerify("dsa2048", "SHA-256", false, DSA2048_KEYID,
                      PublicKeyAlgorithmTags.DSA);
    }
 
    @Test
    public void testDetachedSigning_ECDSA_SHA256_clientSide() throws Exception {
        LOG.info("testDetachedSigning_ECDSA_SHA256_clientSide");
        Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
        signAndVerify("nistp256", "SHA-256", true, NISTP256_KEYID,
                      PublicKeyAlgorithmTags.ECDSA);
    }
    
    @Test
    public void testClearTextSigning_ECDSA_SHA256_clientSide() throws Exception {
        LOG.info("testClearTextSigning_ECDSA_SHA256_clientSide");
        Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
        signAndVerify("nistp256", "SHA-256", false, NISTP256_KEYID,
                      PublicKeyAlgorithmTags.ECDSA);
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
    public void testDetachedSigning_RSA4096_SHA256_clientSide() throws Exception {
        LOG.info("testDetachedSigning_RSA4096_SHA256_clientSide");
        signAndVerify("rsa4096", "SHA-256", true, RSA4096_KEYID);
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
   
    private void signAndVerify(final String expectedKeyAlgorithm,
                               final String digestAlgorithm,                               
                               final boolean detachedSignature,                               
                               final String clientSideKeyId) throws Exception {
        signAndVerify(expectedKeyAlgorithm, digestAlgorithm,
                      detachedSignature, clientSideKeyId,
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
                               final boolean detachedSignature,
                               final String clientSideKeyId,
                               final int clientSideKeyAlgorithm) throws Exception {
        final int workerId = 42;
        final String workerName = "OpenPGPSigner-" + expectedKeyAlgorithm + "-" + digestAlgorithm;
        final File inFile = new File(helper.getSignServerHome(), detachedSignature ? "res/test/HelloJar.jar" : "res/test/stub.c");  // Let's use any binary file as input for detached and any text file for clear-text
        final File outFile = File.createTempFile("HelloJar.jar", ".asc");
        final File gpgHome = Files.createTempDirectory("debiandpkgsigsigner-gnupghome").toFile();
        final String[] envp = new String[] { "GNUPGHOME=" + gpgHome.getAbsolutePath() };
        final File ringFile = File.createTempFile("pubring", ".gpg");
        final File trustFile = File.createTempFile("trustdb", ".gpg");
        final File publicKeyFile = File.createTempFile("pubkey", ".gpg");        
        File clearTextFile = null;
        final String userId = "User 1 (Code Signing) <user1@example.com>";
        final String expectedDigestAlgorithm = digestAlgorithm.replace("-", "");

        try {
            final String implementation = "org.signserver.module.openpgp.enterprise.signer.OpenPGPPlainSigner";                     
            helper.addSigner(implementation, workerId, workerName, true);            
            
            switch (expectedKeyAlgorithm) {
                case "rsa2048": {
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", RSA2048_ALIAS);
                    helper.getWorkerSession().setWorkerProperty(workerId, "SIGNATUREALGORITHM", "NONEwithRSA");                    
                    break;
                }
                case "rsa4096": {
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", RSA4096_ALIAS);
                    helper.getWorkerSession().setWorkerProperty(workerId, "SIGNATUREALGORITHM", "NONEwithRSA");                   
                    break;
                }
                case "nistp256": {
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", NISTP256_ALIAS);
                    helper.getWorkerSession().setWorkerProperty(workerId, "SIGNATUREALGORITHM", "NONEwithECDSA");
                    break;
                }
                case "dsa1024": {
                    final File keystore = new File(helper.getSignServerHome(), "res/test/dss10/dss10_tssigner6dsa.jks");
                    helper.getWorkerSession().setWorkerProperty(workerId, PropertiesConstants.CRYPTOTOKEN_IMPLEMENTATION_CLASS, "org.signserver.server.cryptotokens.JKSCryptoToken");
                    helper.getWorkerSession().setWorkerProperty(workerId, "KEYSTOREPATH", keystore.getAbsolutePath());
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", "mykey");
                    helper.getWorkerSession().setWorkerProperty(workerId, "SIGNATUREALGORITHM", "NONEwithDSA");
                    break;
                }
                case "dsa2048": {
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", DSA2048_ALIAS);
                    helper.getWorkerSession().setWorkerProperty(workerId, "SIGNATUREALGORITHM", "NONEwithDSA");
                    break;
                }
                default: {
                    throw new UnsupportedOperationException("Test does not support key algorithm: " + expectedKeyAlgorithm);
                }
            }
            
            helper.getWorkerSession().reloadConfiguration(workerId);

            // Add User ID and get public key
            final AbstractCertReqData requestData = (AbstractCertReqData) helper.getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), new PKCS10CertReqInfo(digestAlgorithm + "withRSA", userId, null), false);
            final byte[] publicKeyBytes = requestData.toBinaryForm();
            FileUtils.writeByteArrayToFile(publicKeyFile, publicKeyBytes);
            final PGPPublicKey pgpPublicKey = OpenPGPUtils.parsePublicKeys(requestData.toArmoredForm()).get(0);

            // Import public key
            trustFile.delete(); // Seems to be a bug in older versions of gpg not liking that the file is empty but non-existing is fine: https://dev.gnupg.org/T2417
            // For GPG 2.0 it seems public key algorithm 3 is not supported (?) so we had to add --allow-non-selfsigned-uid
            ComplianceTestUtils.ProcResult res = ComplianceTestUtils.executeWithEnv(envp, "gpg2", "-v", "--allow-non-selfsigned-uid", "--trustdb-name", trustFile.getAbsolutePath(), "--no-default-keyring", "--keyring", ringFile.getAbsolutePath(),
                    "--import", publicKeyFile.getAbsolutePath());
            assertEquals("gpg2 --import: " + res.getErrorMessage(), 0, res.getExitValue());

            // Trust public key
            // Equivalent of Bash: echo -e "trust\n5\ny\nsave\n" | gpg --command-fd 0 --edit-key F7B50A4D55F6E703
            res = ComplianceTestUtils.executeWritingWithEnv("trust\n5\ny\nsave\n".getBytes(), envp, "gpg2", "--trustdb-name", trustFile.getAbsolutePath(), "--no-default-keyring", "--keyring", ringFile.getAbsolutePath(),
                    "--command-fd", "0", "--no-tty", "--edit-key", OpenPGPUtils.formatKeyID(pgpPublicKey.getKeyID()));
            assertEquals("gpg2 --edit-key: " + res.getErrorMessage(), 0, res.getExitValue());

            // Sign
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
                                     Integer.toString(clientSideKeyAlgorithm),
                                     "-extraoption", "DETACHED_SIGNATURE=" +
                                     Boolean.toString(detachedSignature)));
            
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
    
}
