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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.util.PathUtil;
import org.signserver.debiandpkgsig.ar.ParsedArFile;
import org.signserver.debiandpkgsig.utils.DebianDpkgSigUtils;
import org.signserver.server.SignServerContext;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.test.utils.mock.MockedServicesImpl;
import org.signserver.testutils.ModulesTestCase;

/**
 * Unit tests for the Debian package signer.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class DebianDpkgSigSignerUnitTest {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(DebianDpkgSigSignerUnitTest.class);
    
    private static File sampleFile;
    private static final String DUMMY_FINGERPRINT = "1234567890ABCDEF";
    private static final String EXPECTED_DATE_STRING = "Wed May 15 08:51:48 2019";

    private static MockedCryptoToken tokenRSA;
    private static MockedCryptoToken tokenDSA;
    private static MockedCryptoToken tokenECDSA;

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // RSA
        final KeyPair signerKeyPairRSA = CryptoUtils.generateRSA(1024);
        final Certificate[] certChainRSA =
                new Certificate[] {new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSelfSignKeyPair(signerKeyPairRSA).
                        setNotBefore(new Date()).
                        setSignatureAlgorithm("SHA256withRSA")
                        .build())};
        final Certificate signerCertificateRSA = certChainRSA[0];
        tokenRSA = new MockedCryptoToken(signerKeyPairRSA.getPrivate(), signerKeyPairRSA.getPublic(), signerCertificateRSA, Arrays.asList(certChainRSA), "BC");

        // DSA
        final KeyPair signerKeyPairDSA = CryptoUtils.generateDSA(1024);
        final Certificate[] certChainDSA =
                new Certificate[] {new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSelfSignKeyPair(signerKeyPairDSA).
                        setNotBefore(new Date()).
                        setSignatureAlgorithm("SHA256withDSA")
                        .build())};
        final Certificate signerCertificateDSA = certChainDSA[0];
        tokenDSA = new MockedCryptoToken(signerKeyPairDSA.getPrivate(), signerKeyPairDSA.getPublic(), signerCertificateDSA, Arrays.asList(certChainDSA), "BC");
        
        // ECDSA
        final KeyPair signerKeyPairECDSA = CryptoUtils.generateEcCurve("prime256v1");
        final Certificate[] certChainECDSA =
                new Certificate[] {new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSelfSignKeyPair(signerKeyPairECDSA).
                        setNotBefore(new Date()).
                        setSignatureAlgorithm("SHA256withECDSA")
                        .build())};
        final Certificate signerCertificateECDSA = certChainECDSA[0];
        tokenECDSA = new MockedCryptoToken(signerKeyPairECDSA.getPrivate(), signerKeyPairECDSA.getPublic(), signerCertificateECDSA, Arrays.asList(certChainECDSA), "BC");

        // Sample package to test with
        sampleFile = new File(PathUtil.getAppHome(), "res/test/HelloDeb.deb");
        if (!sampleFile.exists()) {
            throw new Exception("Missing sample package: " + sampleFile);
        }
    }

    private DebianDpkgSigSigner createMockSigner(final MockedCryptoToken token) {
        return new MockedDebianDpkgSigSigner(token);
    }

    private SignatureResponse sign(final byte[] data,
                                   final DebianDpkgSigSigner signer)
            throws Exception {
        final RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(data);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);) {
            SignatureRequest request = new SignatureRequest(100, requestData, responseData);
            SignatureResponse response = (SignatureResponse) signer.processData(request, requestContext);

            return response;
        }
    }
    
    /**
     * Test that providing an incorrect value for DIGEST_ALGORITHM
     * gives a fatal error.
     * Also ensure that attempting to sign gives a SignServerException.
     * 
     * @throws Exception
     */
    @Test(expected = SignServerException.class)
    public void testInit_incorrectDigestAlgorithmValue() throws Exception {
        LOG.info("testInit_incorrectDigestAlgorithmValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("DIGEST_ALGORITHM", "_incorrect-value--");
        final DebianDpkgSigSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("DIGEST_ALGORITHM"));

        sign(FileUtils.readFileToByteArray(sampleFile), instance);
    }
    
    /**
     * Test that providing an incorrect value for GENERATE_REVOCATION_CERTIFICATE
     * gives a fatal error.
     * @throws Exception
     */
    @Test(expected = SignServerException.class)
    public void testInit_incorrectGenerateRevocationCertificateValue()
            throws Exception {
        LOG.info("testInit_incorrectGenerateRevocationCertificateValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("GENERATE_REVOCATION_CERTIFICATE", "_incorrect-value--");
        final DebianDpkgSigSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("GENERATE_REVOCATION_CERTIFICATE"));

        sign(FileUtils.readFileToByteArray(sampleFile), instance);
    }

    /**
     * Test that providing an incorrect value for PGPPUBLICKEY gives a fatal
     * error.
     * @throws Exception
     */
    @Test(expected = SignServerException.class)
    public void testInit_incorrectPgpPublicKeyValue() throws Exception {
        LOG.info("testInit_incorrectPgpPublicKeyValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("PGPPUBLICKEY", "_incorrect-value--");
        final DebianDpkgSigSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("PGPPUBLICKEY"));

        sign(FileUtils.readFileToByteArray(sampleFile), instance);
    }

    /**
     * Test that providing an incorrect value for SELFSIGNED_VALIDITY gives a 
     * fatal error.
     * @throws Exception
     */
    @Test(expected = SignServerException.class)
    public void testInit_incorrectSelfsignedValidityValue() throws Exception {
        LOG.info("testInit_incorrectSelfsignedValidityValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("SELFSIGNED_VALIDITY", "_incorrect-value--");
        final DebianDpkgSigSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("SELFSIGNED_VALIDITY"));

        sign(FileUtils.readFileToByteArray(sampleFile), instance);
    }
    
    /**
     * Test signing using an RSA key.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignRSA() throws Exception {
        LOG.info("testSignRSA");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("DIGEST_ALGORITHM", "SHA-256");

        final DebianDpkgSigSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        sign(FileUtils.readFileToByteArray(sampleFile), instance);
    }
    
    /**
     * Test signing using a DSA key.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignDSA() throws Exception {
        LOG.info("testSignDSA");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("DIGEST_ALGORITHM", "SHA-256");

        final DebianDpkgSigSigner instance = createMockSigner(tokenDSA);
        instance.init(1, config, new SignServerContext(), null);

        sign(FileUtils.readFileToByteArray(sampleFile), instance);
    }
    
    /**
     * Test signing using an ECDSA key.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignECDSA() throws Exception {
        LOG.info("testSignECDSA");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("DIGEST_ALGORITHM", "SHA-256");

        final DebianDpkgSigSigner instance = createMockSigner(tokenECDSA);
        instance.init(1, config, new SignServerContext(), null);

        sign(FileUtils.readFileToByteArray(sampleFile), instance);
    }

    /**
     * Test creating a manifest from a sample input package.
     * 
     * Expected manifest format (including newline characters for clarity):
     * <code>
     * Version: 4\n
     * Signer: 123456789ABCDE\n
     * Date: Wed May 15 08:51:48 2019\n
     * Role: builder\n
     * Files: \n
     *  3cf918272ffa5de195752d73f3da3e5e 7959c969e092f2a5a8604e2287807ac5b1b384ad 4 debian-binary\n
     *  94ff0dae369a24df829ff58c2606f8e6 5532b60c23ec7acee08a36d0803dc3d96bf0f1a0 336 control.tar.xz\n
     *  35ddaef8a5af0ae5bf7743f519b834c5 81eb7974a37b6b810eccf1cfe4df3994587cd7bb 256 data.tar.xz\n
     * </code>
     *
     * @throws Exception 
     */
    @Test
    public void testCreateManifest() throws Exception {
        LOG.info("testCreateManifest");
        try (final FileInputStream fis = new FileInputStream(sampleFile)) {
            final ParsedArFile parsedFile =
                    ParsedArFile.parseCopyAndHash(fis,
                                                  new ByteArrayOutputStream(),
                                                  new AlgorithmIdentifier(CMSAlgorithm.MD5),
                                                  new AlgorithmIdentifier(CMSAlgorithm.SHA1));
            final Calendar cal = Calendar.getInstance();

            cal.set(2019, 4, 15, 8, 51, 48);

            final Date date = cal.getTime();
            final String manifest =
                    DebianDpkgSigUtils.createManifest(Hex.decode(DUMMY_FINGERPRINT),
                                                       date, parsedFile);
            final String[] lines = StringUtils.split(manifest, "\n");

            LOG.info("Manifest:w\n" + manifest);
            
            assertEquals("Number of lines", 8, lines.length);
            assertEquals("Version", "Version: 4", lines[0]);
            assertEquals("Signer fingerprint", "Signer: " + DUMMY_FINGERPRINT,
                         lines[1]);
            assertEquals("Date", "Date: " + EXPECTED_DATE_STRING, lines[2]);
            assertEquals("Role", "Role: builder", lines[3]);
            assertEquals("Files header", "Files: ", lines[4]);

            final List<ParsedArFile.Entry> entries = parsedFile.getEntries();

            checkEntryLine(entries.get(0), lines[5]);
            checkEntryLine(entries.get(1), lines[6]);
            checkEntryLine(entries.get(2), lines[7]);
        }
    }
    
    /**
     * Test that creating manifest fails when not given required MD5 digest.
     * 
     * @throws Exception 
     */
    @Test(expected = IllegalArgumentException.class)
    public void testCreateManifestNoMD5() throws Exception {
        LOG.info("testCreateManifestNoMD5");
        try (final FileInputStream fis = new FileInputStream(sampleFile)) {
            final ParsedArFile parsedFile =
                    ParsedArFile.parseCopyAndHash(fis,
                                                  new ByteArrayOutputStream(),
                                                  new AlgorithmIdentifier(CMSAlgorithm.SHA1));
            final String manifest =
                    DebianDpkgSigUtils.createManifest(Hex.decode(DUMMY_FINGERPRINT),
                                                       new Date(), parsedFile);
        }
    }

    /**
     * Test that creating manifest fails when not given required SHA1 digest.
     * 
     * @throws Exception 
     */
    @Test(expected = IllegalArgumentException.class)
    public void testCreateManifestNoSHA1() throws Exception {
        LOG.info("testCreateManifestNoSHA1");
        try (final FileInputStream fis = new FileInputStream(sampleFile)) {
            final ParsedArFile parsedFile =
                    ParsedArFile.parseCopyAndHash(fis,
                                                  new ByteArrayOutputStream(),
                                                  new AlgorithmIdentifier(CMSAlgorithm.MD5));
            final String manifest =
                    DebianDpkgSigUtils.createManifest(Hex.decode(DUMMY_FINGERPRINT),
                                                       new Date(), parsedFile);
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
        final AlgorithmIdentifier md5 =
                new AlgorithmIdentifier(CMSAlgorithm.MD5);
        final AlgorithmIdentifier sha1 =
                new AlgorithmIdentifier(CMSAlgorithm.SHA1);
        final String expectedMD5 =
                Hex.toHexString(entry.getDigest().get(md5)).toLowerCase(Locale.ENGLISH);
        final String expectedSHA1 =
                Hex.toHexString(entry.getDigest().get(sha1)).toLowerCase(Locale.ENGLISH);
        final String[] parts = line.split(" ");

        assertEquals("Number of fields, including leading space", 5, parts.length);
        assertTrue("Leading space", parts[0].isEmpty());
        assertEquals("Expected MD5", expectedMD5, parts[1]);
        assertEquals("Expected SHA1", expectedSHA1, parts[2]);
        assertEquals("Size", Integer.toString(entry.getHeader().getFileSize()), parts[3]);
        assertEquals("File name", entry.getHeader().getFileIdentifier(), parts[4]);
    }
}
