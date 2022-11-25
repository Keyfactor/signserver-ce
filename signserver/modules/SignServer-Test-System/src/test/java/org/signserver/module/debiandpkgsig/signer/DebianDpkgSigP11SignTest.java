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
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.encoders.Hex;
import static org.junit.Assert.assertTrue;
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
import org.signserver.debiandpkgsig.ar.ParsedArFile;
import org.signserver.module.openpgp.signer.OpenPGPUtils;
import org.signserver.openpgp.utils.ClearSignedFileProcessorUtils;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.server.cryptotokens.PKCS11CryptoToken;

/**
 * Test signing with DebianDpkgSig signer(s) and a PKCS11CryptoToken.
 *
 * @author Vinay Singh
 * @version $Id: DebianDpkgSigP11SignTest.java 10853 2019-05-16 12:18:23Z vinays
 * $
 */
public class DebianDpkgSigP11SignTest {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(DebianDpkgSigP11SignTest.class);

    private static final int CRYPTO_TOKEN = 30100;
    private static final int WORKER_DEBIAN_DPKG_SIG_SIGNER = 30200;

    private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenDebianDpkgSigP11";

    private final String sharedLibraryName;
    private final String slot;
    private final String pin;
    private final String existingKey1;

    private final File HELLO_DEB;

    private final ModulesTestCase testCase = new ModulesTestCase();
    private final WorkerSession workerSession = testCase.getWorkerSession();

    public DebianDpkgSigP11SignTest() throws FileNotFoundException {
        final File home = PathUtil.getAppHome();
        HELLO_DEB = new File(home, "res/test/HelloDeb.deb");
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

    private void setDebianDpkgSigSignerOnlyProperties(final int workerId) throws Exception {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.debiandpkgsig.signer.DebianDpkgSigSigner");
        workerSession.setWorkerProperty(workerId, "NAME", "DebianDpkgSigSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
    }

    /**
     * Tests adding a User Id to the public key, sign sample deb file verifying
     * the manifest signature.
     *
     * @throws Exception
     */
    @Test
    public void testSignAndVerifyHelloDeb() throws Exception {
        LOG.info("testAddUserIdClearTextSignAndVerify");
        final File resultFile = File.createTempFile("resultFile", "txt");
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, false);
            setDebianDpkgSigSignerOnlyProperties(WORKER_DEBIAN_DPKG_SIG_SIGNER);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(WORKER_DEBIAN_DPKG_SIG_SIGNER);

            // Generate the public key
            final String userId = "Worker " + WORKER_DEBIAN_DPKG_SIG_SIGNER + " worker@example.com";
            final PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA256WithRSA", userId, null);
            AbstractCertReqData csr = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(WORKER_DEBIAN_DPKG_SIG_SIGNER), certReqInfo, false);
            assertNotNull(csr);
            String publicKeyArmored = csr.toArmoredForm();
            assertTrue("public key header: " + publicKeyArmored, publicKeyArmored.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
            assertTrue("public key footer: " + publicKeyArmored, publicKeyArmored.contains("-----END PGP PUBLIC KEY BLOCK-----"));

            // Store the updated public key
            workerSession.setWorkerProperty(WORKER_DEBIAN_DPKG_SIG_SIGNER, "PGPPUBLICKEY", publicKeyArmored);
            workerSession.reloadConfiguration(WORKER_DEBIAN_DPKG_SIG_SIGNER);

            // Check the status has no errors and that the user id is printed
            WorkerStatus status = workerSession.getStatus(new WorkerIdentifier(WORKER_DEBIAN_DPKG_SIG_SIGNER));
            assertEquals("fatal errors", "[]", status.getFatalErrors().toString());
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            status.displayStatus(new PrintStream(bout), true);
            String statusOutput = bout.toString(StandardCharsets.UTF_8.toString());
            assertTrue("key contains user id: " + statusOutput, statusOutput.contains(userId));

            // Test signing
            final byte[] originalData = FileUtils.readFileToByteArray(HELLO_DEB);
            GenericSignResponse response = testCase.signGenericDocument(WORKER_DEBIAN_DPKG_SIG_SIGNER, originalData);
            final byte[] signedBytes = response.getProcessedData();

            String signed = new String(signedBytes, StandardCharsets.US_ASCII);
            LOG.info("signed content response\n" + signed);
            assertTrue("expecting armored: " + signed, signed.startsWith("!<arch>"));

            final PGPPublicKey pgpPublicKey = OpenPGPUtils.parsePublicKeys(publicKeyArmored).get(0);
            String fingerprint = Hex.toHexString(pgpPublicKey.getFingerprint()).toUpperCase(Locale.ENGLISH);
            LOG.info("fingerprint: " + fingerprint);

            final ParsedArFile parsedFile;
            try (final InputStream fis = new ByteArrayInputStream(signedBytes)) {
                parsedFile = ParsedArFile.parseCopyAndHash(fis,
                        new ByteArrayOutputStream(),
                        new AlgorithmIdentifier(CMSAlgorithm.MD5),
                        new AlgorithmIdentifier(CMSAlgorithm.SHA1));
            }

            // Extract manifest from response
            String manifest = signed.substring(signed.indexOf("Version:"), signed.indexOf("-----BEGIN PGP SIGNATURE-----") - 2);
            LOG.info("manifest " + manifest);
            final String[] lines = StringUtils.split(manifest, "\n");

            assertEquals("Number of lines", 8, lines.length);
            assertEquals("Version", "Version: 4", lines[0]);
            assertEquals("Signer fingerprint", "Signer: " + fingerprint,
                    lines[1]);

            // check date
            final DateFormat format = new SimpleDateFormat("E MMM d HH:mm:ss yyyy", Locale.ENGLISH);
            Date dateInManifest = format.parse(lines[2].substring(lines[2].indexOf("Date: ") + 6));
            LOG.info("now " + dateInManifest.toString());
            final Date now = new Date();
            long diffInMillies = Math.abs(now.getTime() - dateInManifest.getTime());
            long diffInMinutes = TimeUnit.MINUTES.convert(diffInMillies, TimeUnit.MILLISECONDS);
            assertTrue("Time difference in seconds should be less than 5 minutes " + diffInMinutes, diffInMinutes < 5);

            assertEquals("Role", "Role: builder", lines[3]);
            assertEquals("Files header", "Files: ", lines[4]);

            // Check manifest entries
            final List<ParsedArFile.Entry> entries = parsedFile.getEntries();
            checkEntryLine(entries.get(0), lines[5]);
            checkEntryLine(entries.get(1), lines[6]);
            checkEntryLine(entries.get(2), lines[7]);

            // Verify signature
            verifySignature(pgpPublicKey, new ByteArrayInputStream(signedBytes), resultFile);            

        } finally {
            testCase.removeWorker(CRYPTO_TOKEN);
            testCase.removeWorker(WORKER_DEBIAN_DPKG_SIG_SIGNER);
            FileUtils.deleteQuietly(resultFile);
        }
    }

    /**
     * Check that a parsed line following the "Files: " header in a manifest
     * matches the expected AR entry.
     *
     * @param entry AR file entry
     * @param line Corresponding line from the manifest
     * @throws Exception in case of assertion error
     */
    private void checkEntryLine(final ParsedArFile.Entry entry, final String line)
            throws Exception {
        final AlgorithmIdentifier md5
                = new AlgorithmIdentifier(CMSAlgorithm.MD5);
        final AlgorithmIdentifier sha1
                = new AlgorithmIdentifier(CMSAlgorithm.SHA1);
        final String expectedMD5
                = Hex.toHexString(entry.getDigest().get(md5)).toLowerCase(Locale.ENGLISH);
        final String expectedSHA1
                = Hex.toHexString(entry.getDigest().get(sha1)).toLowerCase(Locale.ENGLISH);
        final String[] parts = line.split(" ");

        assertEquals("Number of fields, including leading space", 5, parts.length);
        assertTrue("Leading space", parts[0].isEmpty());
        assertEquals("Expected MD5", expectedMD5, parts[1]);
        assertEquals("Expected SHA1", expectedSHA1, parts[2]);
        assertEquals("Size", Integer.toString(entry.getHeader().getFileSize()), parts[3]);
        assertEquals("File name", entry.getHeader().getFileIdentifier(), parts[4]);
    }
    
    private void verifySignature(PGPPublicKey pgpPublicKey, InputStream in, final File resultFile) throws Exception {
        PGPSignature sig;

        ArmoredInputStream aIn = new ArmoredInputStream(in);
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
    }

}
