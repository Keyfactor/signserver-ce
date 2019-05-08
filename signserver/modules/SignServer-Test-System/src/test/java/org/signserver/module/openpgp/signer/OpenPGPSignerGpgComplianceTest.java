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
import static junit.framework.TestCase.assertTrue;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
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
        signAndVerify("rsa2048", "SHA-256", false);
    }

    @Test
    public void testSigning_RSA_SHA1() throws Exception {
        signAndVerify("rsa2048", "SHA-1", false);
    }

    @Test
    public void testSigning_RSA_SHA224() throws Exception {
        signAndVerify("rsa2048", "SHA-224", false);
    }

    @Test
    public void testSigning_RSA_SHA384() throws Exception {
        signAndVerify("rsa2048", "SHA-384", false);
    }

    @Test
    public void testSigning_RSA_SHA512() throws Exception {
        signAndVerify("rsa2048", "SHA-512", false);
    }

    @Test
    public void testSigning_ECDSA_SHA256() throws Exception {
        Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
        signAndVerify("nistp256", "SHA-256", false);
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
        signAndVerify("nistp256", "SHA-384", false);
    }

    @Test
    public void testSigning_ECDSA_SHA512() throws Exception {
        Assume.assumeTrue("ECDSA supported by GPG version", ecdsaSupported);
        signAndVerify("nistp256", "SHA-512", false);
    }

    @Test
    public void testSigning_RSA4096_SHA256() throws Exception {
        signAndVerify("rsa4096", "SHA-256", false);
    }

    @Test
    public void testSigning_RSA4096_SHA1() throws Exception {
        signAndVerify("rsa4096", "SHA-1", false);
    }

    @Test
    public void testSigning_RSA4096_SHA224() throws Exception {
        signAndVerify("rsa4096", "SHA-224", false);
    }

    @Test
    public void testSigning_RSA4096_SHA384() throws Exception {
        signAndVerify("rsa4096", "SHA-384", false);
    }

    @Test
    public void testSigning_RSA4096_SHA512() throws Exception {
        signAndVerify("rsa4096", "SHA-512", false);
    }

    @Test
    public void testSigning_DSA1024_SHA256() throws Exception {
        signAndVerify("dsa1024", "SHA-256", false);
    }

    @Test
    public void testSigning_DSA1024_SHA1() throws Exception {
        signAndVerify("dsa1024", "SHA-1", false);
    }

    @Test
    public void testSigning_DSA1024_SHA224() throws Exception {
        signAndVerify("dsa1024", "SHA-224", false);
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
    
    /**
     * Test signing and later revoking with RSA and SHA256
     * @throws Exception 
     */
    @Test
    public void testSigning_RSA_SHA256withRevocation() throws Exception {
        signAndVerify("rsa2048", "SHA-256", true);
    }
 
    /**
     * Test signing and later revoking with RSA and SHA1
     * @throws Exception 
     */
    @Test
    public void testSigning_RSA_SHA1withRevocation() throws Exception {
        signAndVerify("rsa2048", "SHA-1", true);
    }
    
    /**
     * Test signing and later revoking with ECDSA and SHA256
     * @throws Exception 
     */
    @Test
    public void testSigning_ECDSA_SHA256withRevocation() throws Exception {
        signAndVerify("nistp256", "SHA-256", true);
    }
    
    /**
     * Test signing and later revoking with DSA and SHA256
     * @throws Exception 
     */
    @Test
    public void testSigning_DSA1024_SHA256withRevocation() throws Exception {
        signAndVerify("dsa1024", "SHA-256", true);
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
                               final boolean revokeAfter) throws Exception {
        final int workerId = 42;
        final String workerName = "OpenPGPSigner-" + expectedKeyAlgorithm + "-" + digestAlgorithm ;
        final File inFile = new File(helper.getSignServerHome(), "res/test/HelloJar.jar");
        final File outFile = File.createTempFile("HelloJar.jar", ".asc");
        final File ringFile = File.createTempFile("pubring", ".gpg");
        final File trustFile = File.createTempFile("trustdb", ".gpg");
        final File publicKeyFile = File.createTempFile("pubkey", ".gpg");
        final String userId = "User 1 (Code Signing) <user1@example.com>";
        final String expectedDigestAlgorithm = digestAlgorithm.replace("-", "");

        try {

            helper.addSigner("org.signserver.module.openpgp.signer.OpenPGPSigner", workerId, workerName, true);
            helper.getWorkerSession().setWorkerProperty(workerId, "DETACHEDSIGNATURE", "true");
            switch (expectedKeyAlgorithm) {
                case "rsa2048": {
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", "signer00001");
                    break;
                }
                case "rsa4096": {
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", "ts40003");
                    break;
                }
                case "nistp256": {
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", "signer00002");
                    break;
                }
                case "dsa1024": {
                    final File keystore = new File(helper.getSignServerHome(), "res/test/dss10/dss10_tssigner6dsa.jks");
                    helper.getWorkerSession().setWorkerProperty(workerId, PropertiesConstants.CRYPTOTOKEN_IMPLEMENTATION_CLASS, "org.signserver.server.cryptotokens.JKSCryptoToken");
                    helper.getWorkerSession().setWorkerProperty(workerId, "KEYSTOREPATH", keystore.getAbsolutePath());
                    helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY", "mykey");
                    break;
                }
                default: {
                    throw new UnsupportedOperationException("Test does not support key algorithm: " + expectedKeyAlgorithm);
                }
            }

            helper.getWorkerSession().setWorkerProperty(workerId, "DIGEST_ALGORITHM", digestAlgorithm);
            helper.getWorkerSession().reloadConfiguration(workerId);

            // Add User ID and get public key
            final AbstractCertReqData requestData = (AbstractCertReqData) helper.getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), new PKCS10CertReqInfo(digestAlgorithm + "withRSA", userId, null), false);
            final byte[] publicKeyBytes = requestData.toBinaryForm();
            FileUtils.writeByteArrayToFile(publicKeyFile, publicKeyBytes);
            final PGPPublicKey pgpPublicKey = OpenPGPUtils.parsePublicKeys(requestData.toArmoredForm()).get(0);

            // Import public key
            trustFile.delete(); // Seems to be a bug in older versions of gpg not liking that the file is empty but non-existing is fine: https://dev.gnupg.org/T2417
            ComplianceTestUtils.ProcResult res = ComplianceTestUtils.execute("gpg2", "--trustdb-name", trustFile.getAbsolutePath(), "--no-default-keyring", "--keyring", ringFile.getAbsolutePath(),
                    "--import", publicKeyFile.getAbsolutePath());
            assertEquals("gpg2 --import: " + res.getErrorMessage(), 0, res.getExitValue());

            // Trust public key
            // Equaivalent of Bash: echo -e "trust\n5\ny\nsave\n" | gpg --command-fd 0 --edit-key F7B50A4D55F6E703
            res = ComplianceTestUtils.executeWriting("trust\n5\ny\nsave\n".getBytes(), "gpg2", "--trustdb-name", trustFile.getAbsolutePath(), "--no-default-keyring", "--keyring", ringFile.getAbsolutePath(),
                    "--command-fd", "0", "--no-tty", "--edit-key", OpenPGPUtils.formatKeyID(pgpPublicKey.getKeyID()));
            assertEquals("gpg2 --edit-key: " + res.getErrorMessage(), 0, res.getExitValue());

            // Sign
            assertEquals("Status code", ClientCLI.RETURN_SUCCESS,
                         CLI.execute("signdocument", "-workername",
                                     workerName,
                                     "-infile", inFile.getAbsolutePath(),
                                     "-outfile", outFile.getAbsolutePath()));

            // Verify
            res = ComplianceTestUtils.execute("gpg2", "--trustdb-name", trustFile.getAbsolutePath(), "--no-default-keyring", "--keyring", ringFile.getAbsolutePath(),
                    "--verbose", "--verify", outFile.getAbsolutePath(), inFile.getAbsolutePath());

            final String output = res.getErrorMessage();

            assertTrue("Expecting Good signature: " + output, output.contains("gpg: Good signature from \"User 1 (Code Signing) <user1@example.com>\""));
            assertEquals("return code", 0, res.getExitValue());

            assertTrue("Expecting digest algorithm " + expectedDigestAlgorithm + ": " + output, output.contains("digest algorithm " + expectedDigestAlgorithm));
            
            // Check key algorithm but only if it exists as this is not available in older gpg versions
            if (output.contains("key algorithm ")) {
                assertTrue("Expecting key algorithm " + expectedKeyAlgorithm + ": " + output, output.contains("key algorithm " + expectedKeyAlgorithm));
            }
            
            if (revokeAfter) {
                final File csrFile = File.createTempFile("csr", ".rev");
                final File revocationFile = File.createTempFile("revocation", ".rev");
                
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
                
                // remove short-cicuit colon
                csrString = csrString.replaceFirst("\n:", "\n");
                FileUtils.writeStringToFile(revocationFile, csrString,
                                            StandardCharsets.UTF_8);
                
                // import revocation certificate
                res = ComplianceTestUtils.execute("gpg2", "--trustdb-name", trustFile.getAbsolutePath(), "--no-default-keyring", "--keyring", ringFile.getAbsolutePath(),
                    "--import", revocationFile.getAbsolutePath());
                assertEquals("gpg2 --import: " + res.getErrorMessage(), 0, res.getExitValue());

                final String importRevocationOutput = res.getErrorMessage();
                assertTrue("Expecting revocation: " + importRevocationOutput,
                           importRevocationOutput.contains("revocation certificate imported"));
                
                // Verify
                res = ComplianceTestUtils.execute("gpg2", "--trustdb-name", trustFile.getAbsolutePath(), "--no-default-keyring", "--keyring", ringFile.getAbsolutePath(),
                        "--verbose", "--verify", outFile.getAbsolutePath(), inFile.getAbsolutePath());

                final String verifyAfterRevokeOutput = res.getErrorMessage();

                assertTrue("Expecting revocation warning: " + verifyAfterRevokeOutput,
                           verifyAfterRevokeOutput.contains("gpg: WARNING: This key has been revoked by its owner!"));

            }

        } finally {
            helper.removeWorker(workerId);
            FileUtils.deleteQuietly(outFile);
            FileUtils.deleteQuietly(ringFile);
            FileUtils.deleteQuietly(trustFile);
            FileUtils.deleteQuietly(publicKeyFile);
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
