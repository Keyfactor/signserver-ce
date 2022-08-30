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
package org.signserver.module.jarchive.signer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.CodeSigner;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;
import static junit.framework.TestCase.assertNotNull;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.NullOutputStream;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.selector.jcajce.JcaX509CertificateHolderSelector;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
import org.signserver.module.jarchive.signer.JArchiveSigner.SignatureNameType;
import org.signserver.server.SignServerContext;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.testutils.ModulesTestCase;

/**
 * Unit tests for the JArchiveSigner class.
 *
 * For system tests see JArchiveSignerTest instead.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class JArchiveSignerUnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(JArchiveSignerUnitTest.class);

    //JDK8: private static final ASN1ObjectIdentifier ID_SHA1WITHDSA = new ASN1ObjectIdentifier("1.2.840.10040.4.3");
    //JDK8: private static final ASN1ObjectIdentifier ID_SHA256WITHDSA = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.2");
    private static final String JAVA_SHA_512 = "SHA-512";
    private static final String JAVA_SHA_256 = "SHA-256";
    private static final String JAVA_SHA1 = "SHA1";
    private static final String KEYALIAS_REAL = "Key alias 1";
    private static final String KEYALIAS_CONVERTED = "KEY_ALIA";

    private static MockedCryptoToken tokenRSA;
    private static MockedCryptoToken tokenRSA2;
    private static MockedCryptoToken tokenRSAwithIntermediate;
    //JDK8: private static MockedCryptoToken tokenDSA;
    //JDK8: private static MockedCryptoToken tokenECDSA;
    private static File executableFile;

    /** File HelloJar-signed.jar containing CERT0.SF and CERT0.RSA using SHA-256 digest. */
    private static File executableFileWithSignature;

    /** File HelloJar-signed-ts.jar containing CERT.SF and CERT.RSA, using SHA-256 digest and with a time-stamp. */
    private static File executableFileWithSignatureTS;

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        final String signatureAlgorithm = "SHA256withRSA";
        final String signatureAlgorithm2 = "SHA512withRSA";

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

        // Create signer key-pair (RSA) and issue certificate
        final KeyPair signerKeyPairRSA = CryptoUtils.generateRSA(1024);
        final Certificate[] certChainRSA =
                new Certificate[] {
                    // Code Signer
                    new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                        .setIssuerPrivateKey(caKeyPair.getPrivate())
                        .setSubjectPublicKey(signerKeyPairRSA.getPublic())
                        .setNotBefore(new Date(currentTime - 60000))
                        .setSignatureAlgorithm(signatureAlgorithm)
                        .setIssuer(caDN)
                        .setSubject("CN=Code Signer RSA 1")
                        .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairRSA.getPublic())))
                        .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                        .build()),

                    // CA
                    caCertificate
                };
        tokenRSA = new MockedCryptoToken(signerKeyPairRSA.getPrivate(), signerKeyPairRSA.getPublic(), certChainRSA[0], Arrays.asList(certChainRSA), "BC");

        tokenRSAwithIntermediate = generateTokenWithIntermediateCert();

        // Create signer key-pair (RSA) and issue certificate but using an other key size (2048) and an other signature algorithm (SHA512withRSA)
        final KeyPair signerKeyPairRSA2 = CryptoUtils.generateRSA(2048);
        final Certificate[] certChainRSA2 =
                new Certificate[] {
                    // Code Signer
                    new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                        .setIssuerPrivateKey(caKeyPair.getPrivate())
                        .setSubjectPublicKey(signerKeyPairRSA2.getPublic())
                        .setNotBefore(new Date(currentTime - 60000))
                        .setSignatureAlgorithm(signatureAlgorithm2)
                        .setIssuer(caDN)
                        .setSubject("CN=Code Signer RSA 2")
                        .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairRSA2.getPublic())))
                        .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                        .build()),

                    // CA
                    caCertificate
                };
        tokenRSA2 = new MockedCryptoToken(signerKeyPairRSA2.getPrivate(), signerKeyPairRSA2.getPublic(), certChainRSA2[0], Arrays.asList(certChainRSA2), "BC");

        // Create signer key-pair (DSA) and issue certificate
        /* JDK8: final KeyPair signerKeyPairDSA = CryptoUtils.generateDSA(1024);
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
                        .addExtension(new CertExt(X509Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairDSA.getPublic())))
                        .addExtension(new CertExt(X509Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                        .build()),

                    // CA
                    caCertificate
                };
        tokenDSA = new MockedCryptoToken(signerKeyPairDSA.getPrivate(), signerKeyPairDSA.getPublic(), certChainDSA[0], Arrays.asList(certChainDSA), "BC");
        */

        // Create signer key-pair (ECDSA) and issue certificate
        /* JDK8: final KeyPair signerKeyPairECDSA = CryptoUtils.generateEcCurve("prime256v1");
        final Certificate[] certChainECDSA =
                new Certificate[] {
                    // Code Signer
                    new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                        .setIssuerPrivateKey(caKeyPair.getPrivate())
                        .setSubjectPublicKey(signerKeyPairECDSA.getPublic())
                        .setNotBefore(new Date(currentTime - 60000))
                        .setSignatureAlgorithm(signatureAlgorithm)
                        .setIssuer(caDN)
                        .setSubject("CN=Code Signer ECDSA 3")
                        .addExtension(new CertExt(X509Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairECDSA.getPublic())))
                        .addExtension(new CertExt(X509Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                        .build()),

                    // CA
                    caCertificate
                };
        tokenECDSA = new MockedCryptoToken(signerKeyPairECDSA.getPrivate(), signerKeyPairECDSA.getPublic(), certChainECDSA[0], Arrays.asList(certChainECDSA), "BC");
        */

        // Sample binaries to test with
        executableFile = new File(PathUtil.getAppHome(), "res/test/HelloJar.jar");
        if (!executableFile.exists()) {
            throw new Exception("Missing sample binary: " + executableFile);
        }
        executableFileWithSignature = new File(PathUtil.getAppHome(), "res/test/HelloJar-signed.jar");
        if (!executableFileWithSignature.exists()) {
            throw new Exception("Missing sample binary: " + executableFileWithSignature);
        }
        executableFileWithSignatureTS = new File(PathUtil.getAppHome(), "res/test/HelloJar-signed-ts.jar");
        if (!executableFileWithSignatureTS.exists()) {
            throw new Exception("Missing sample binary: " + executableFileWithSignatureTS);
        }
    }

    private static MockedCryptoToken generateTokenWithIntermediateCert() throws Exception {
        final JcaX509CertificateConverter conv = new JcaX509CertificateConverter();
        final KeyPair rootcaKeyPair = CryptoUtils.generateRSA(1024);
        final X509CertificateHolder rootcaCert = new CertBuilder()
                .setSelfSignKeyPair(rootcaKeyPair)
                .setSubject("CN=Root, O=JAR Test, C=SE")
                .addExtension(new CertExt(Extension.keyUsage, false, new X509KeyUsage(X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign)))
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(true)))
                .build();
        final KeyPair subcaKeyPair = CryptoUtils.generateRSA(1024);
        final X509CertificateHolder subcaCert = new CertBuilder()
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .setSubjectPublicKey(subcaKeyPair.getPublic())
                .setSubject("CN=Sub, O=JAR Test, C=SE")
                .addExtension(new CertExt(Extension.keyUsage, false, new X509KeyUsage(X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign)))
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(true)))
                .build();

        final KeyPair signerKeyPair = CryptoUtils.generateRSA(1024);
        final X509CertificateHolder signerCert = new CertBuilder()
            .setIssuerPrivateKey(subcaKeyPair.getPrivate())
            .setIssuer(subcaCert.getSubject())
            .setSubjectPublicKey(signerKeyPair.getPublic())
            .setSubject("CN=Signer 1, O=JAR Test, C=SE")
            .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
            .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
            .build();

        final List<Certificate> chain = Arrays.asList(conv.getCertificate(signerCert),
                                                                   conv.getCertificate(subcaCert),
                                                                   conv.getCertificate(rootcaCert));

        return new MockedCryptoToken(
                signerKeyPair.getPrivate(),
                signerKeyPair.getPublic(),
                conv.getCertificate(signerCert),
                chain,
                "BC");
    }

    /**
     * Tests that setting both TSA_URL and TSA_WORKER gives a fatal error.
     */
    @Test
    public void testInit_noTSAURLandWorker() {
        LOG.info("testInit_noTSAURLandWorker");
        WorkerConfig config = createConfig();
        config.setProperty("TSA_URL", "https://example.com/tsa");
        config.setProperty("TSA_WORKER", "TimeStampSigner4");
        JArchiveSigner instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("TSA_URL") && actualErrors.contains("TSA_WORKER"));
    }

    /**
     * Tests that if TSA_USERNAME is given then TSA_PASSWORD must also be
     * specified, but empty password is fine.
     */
    @Test
    public void testInit_TSA_PASSWORD() {
        LOG.info("testInit_TSA_PASSWORD");
        WorkerConfig config = createConfig();
        config.setProperty("TSA_URL", "https://example.com/tsa");
        config.setProperty("TSA_USERNAME", "user1");
        JArchiveSigner instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("TSA_PASSWORD"));

        config.setProperty("TSA_PASSWORD", "");
        instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("expecting no fatalErrors: " + actualErrors, instance.getFatalErrors(null).isEmpty());
    }

    /**
     * Tests that setting TSA_DIGESTALGORITHM to "SHA1" doesn't give
     * any error.
     */
    @Test
    public void testInit_tsaDigestAlgorithmSHA1() {
        LOG.info("testInit_TSA_PASSWORD");
        WorkerConfig config = createConfig();
        config.setProperty("TSA_DIGESTALGORITHM", "SHA1");
        JArchiveSigner instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertFalse("fatalErrors: " + actualErrors,
                    actualErrors.contains("Illegal timestamping digest algorithm"));
    }

    /**
     * Tests that setting TSA_DIGESTALGORITHM to "SHA-256" doesn't give
     * any error.
     */
    @Test
    public void testInit_tsaDigestAlgorithmSHA256() {
        LOG.info("testInit_TSA_PASSWORD");
        WorkerConfig config = createConfig();
        config.setProperty("TSA_DIGESTALGORITHM", "SHA-256");
        JArchiveSigner instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertFalse("fatalErrors: " + actualErrors,
                    actualErrors.contains("Illegal timestamping digest algorithm"));
    }

    /**
     * Tests that setting TSA_DIGESTALGORITHM to "SHA-384" doesn't give
     * any error.
     */
    @Test
    public void testInit_tsaDigestAlgorithmSHA384() {
        LOG.info("testInit_TSA_PASSWORD");
        WorkerConfig config = createConfig();
        config.setProperty("TSA_DIGESTALGORITHM", "SHA-384");
        JArchiveSigner instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertFalse("fatalErrors: " + actualErrors,
                    actualErrors.contains("Illegal timestamping digest algorithm"));
    }

    /**
     * Tests that setting TSA_DIGESTALGORITHM to an illegal value gives
     * the correct error.
     */
    @Test
    public void testInit_illegalTsaDigestAlgorithm() {
        LOG.info("testInit_TSA_PASSWORD");
        WorkerConfig config = createConfig();
        config.setProperty("TSA_DIGESTALGORITHM", "_non_existant_");
        JArchiveSigner instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors,
                   actualErrors.contains("Illegal timestamping digest algorithm"));
    }

//    /**
//     * Tests that setting an unknown digest algorithm name gives an error.
//     * @throws Exception
//     */
//    @Test
//    public void testInit_incorrectDigestAlg() throws Exception {
//        LOG.info("testInit_incorrectDigestAlg");
//        WorkerConfig config = createConfig();
//        config.setProperty("DIGESTALGORITHM", "_incorrect_value_");
//        JArchiveSigner instance = new MockedJArchiveSigner(tokenRSA);
//        instance.init(1, config, new SignServerContext(), null);
//
//        String actualErrors = instance.getFatalErrors(null).toString();
//        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("DIGESTALGORITHM"));
//    }

    /**
     * Test signing using an RSA key-pair.
     * @throws Exception in case of failure.
     */
    @Test
    public void testNormalSigning_RSA() throws Exception {
        LOG.info("testNormalSigning_RSA");
        signAndAssertSignedAndTimestamped(tokenRSA, new ConfigBuilder()
                .create(), null, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
    }

    /**
     * Test signing when explicitly specified the SHA1WithRSA algorithm.
     * @throws Exception in case of failure.
     */
    @Test
    public void testNormalSigning_SHA1WithRSA() throws Exception {
        LOG.info("testNormalSigning_SHA1WithRSA");
        signAndAssertSignedAndTimestamped(tokenRSA, new ConfigBuilder()
                .withSignatureAlgorithm("SHA1WithRSA")
                .create(), null, JAVA_SHA_256, CMSAlgorithm.SHA1, PKCSObjectIdentifiers.rsaEncryption);
    }

    /**
     * Test signing when parameters specified as empty values.
     * @throws Exception in case of failure.
     */
    @Test
    public void testNormalSigningWithEmptyParams() throws Exception {
        LOG.info("testNormalSigningWithEmptyParams");
        signAndAssertSignedAndTimestamped(tokenRSA, new ConfigBuilder()
                .withSignatureAlgorithm("  ").withDigestAlgorithm("  ")
                .create(), null, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
    }

    /**
     * Test signing when explicitly specified the SHA1WithRSA algorithm and
     * using a certificate with SHA256withRSA.
     * @throws Exception in case of failure.
     */
    @Test
    public void testNormalSigning_SHA1WithRSA_withSHA512Cert() throws Exception {
        LOG.info("testNormalSigning_SHA1WithRSA_withSHA512Cert");
        signAndAssertSignedAndTimestamped(tokenRSA2, new ConfigBuilder()
                .withSignatureAlgorithm("SHA1WithRSA")
                .create(), null, JAVA_SHA_256, CMSAlgorithm.SHA1, PKCSObjectIdentifiers.rsaEncryption);
    }

//    TODO: Not supported by Java?
//    /**
//     * Test signing when specified the SHA256WithRSAandMGF1 algorithm.
//     * @throws Exception
//     */
//    @Test
//    public void testNormalSigning_SHA256WithRSAandMGF1() throws Exception {
//        LOG.info("testNormalSigning_SHA256WithRSAandMGF1");
//        SignatureResponse resp = sign(tokenRSA, new ConfigBuilder()
//                .withSignatureAlgorithm("SHA256WithRSAandMGF1")
//                .create(), null);
//        assertSignedAndTimestamped(tokenRSA, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.id_RSASSA_PSS, resp);
//    }

    /**
     * Test signing when specified the SHA256WithRSA algorithm.
     * @throws Exception in case of failure.
     */
    @Test
    public void testNormalSigning_SHA256WithRSA() throws Exception {
        LOG.info("testNormalSigning_SHA256WithRSA");
        signAndAssertSignedAndTimestamped(tokenRSA, new ConfigBuilder()
                .withSignatureAlgorithm("SHA256WithRSA")
                .create(), null, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
    }

    /**
     * Test signing when specified the SHA384WithRSA algorithm.
     * @throws Exception in case of failure.
     */
    @Test
    public void testNormalSigning_SHA384WithRSA() throws Exception {
        LOG.info("testNormalSigning_SHA384WithRSA");
        signAndAssertSignedAndTimestamped(tokenRSA, new ConfigBuilder()
                .withSignatureAlgorithm("SHA384WithRSA")
                .create(), null, JAVA_SHA_256, CMSAlgorithm.SHA384, PKCSObjectIdentifiers.sha384WithRSAEncryption);
    }

    /**
     * Test signing when specified the SHA384WithRSA algorithm.
     * @throws Exception in case of failure.
     */
    @Test
    public void testNormalSigning_SHA512WithRSA() throws Exception {
        LOG.info("testNormalSigning_SHA512WithRSA");
        signAndAssertSignedAndTimestamped(tokenRSA, new ConfigBuilder()
                .withSignatureAlgorithm("SHA512WithRSA")
                .create(), null, JAVA_SHA_256, CMSAlgorithm.SHA512, PKCSObjectIdentifiers.sha512WithRSAEncryption);
    }

//    TODO: Not supported on Java < 8
//
//    /**
//     * Test signing using a DSA key-pair.
//     * @throws Exception
//     */
//    @Test
//    public void testNormalSigning_DSA() throws Exception {
//        LOG.info("testNormalSigning_DSA");
//        SignatureResponse resp = sign(tokenDSA, new ConfigBuilder()
//                .create(), null);
//        assertSignedAndTimestamped(tokenDSA, "SHA1", CMSAlgorithm.SHA1, ID_SHA1WITHDSA, resp);
//    }

    /**
     * Test signing when explicitly specified the SHA-1 digest algorithm.
     * @throws Exception in case of failure.
     */
    @Test
    public void testNormalSigning_digestSHA1() throws Exception {
        LOG.info("testNormalSigning_digestSHA1");
        signAndAssertSignedAndTimestamped(tokenRSA, new ConfigBuilder()
                .withDigestAlgorithm(JAVA_SHA1)
                .withSignatureAlgorithm("SHA256WithRSA")
                .create(), null, JAVA_SHA1, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
    }

    /**
     * Test signing when specified the SHA-256 digest algorithm.
     * @throws Exception in case of failure.
     */
    @Test
    public void testNormalSigning_digestSHA256() throws Exception {
        LOG.info("testNormalSigning_digestSHA256");
        signAndAssertSignedAndTimestamped(tokenRSA, new ConfigBuilder()
                .withDigestAlgorithm(JAVA_SHA_256)
                .create(), null, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption);
    }

    /**
     * Test signing when specified the SHA-512 digest algorithm but SHA1WithRSA.
     * @throws Exception in case of failure.
     */
    @Test
    public void testNormalSigning_digestSHA512() throws Exception {
        LOG.info("testNormalSigning_digestSHA256");
        signAndAssertSignedAndTimestamped(tokenRSA, new ConfigBuilder()
                .withDigestAlgorithm(JAVA_SHA_512)
                .withSignatureAlgorithm("SHA1WithRSA")
                .create(), null, JAVA_SHA_512, CMSAlgorithm.SHA1, PKCSObjectIdentifiers.rsaEncryption);
    }

//    TODO: Not supported on Java < 8
//    /**
//     * Test signing when specified the SHA256WithDSA algorithm.
//     * @throws Exception
//     */
//    @Test
//    public void testNormalSigning_SHA256WithDSA() throws Exception {
//        LOG.info("testNormalSigning_SHA256WithDSA");
//        SignatureResponse resp = sign(tokenDSA, new ConfigBuilder()
//                .withSignatureAlgorithm("SHA256WithDSA")
//                .create(), null);
//        assertSignedAndTimestamped(tokenDSA, "SHA1", CMSAlgorithm.SHA256, ID_SHA256WITHDSA, resp);
//    }
//
//    /**
//     * Test signing when explicitly specified the SHA1WithDSA algorithm.
//     * @throws Exception
//     */
//    @Test
//    public void testNormalSigning_SHA1WithDSA() throws Exception {
//        LOG.info("testNormalSigning_SHA1WithDSA");
//        SignatureResponse resp = sign(tokenDSA, new ConfigBuilder()
//                .withSignatureAlgorithm("SHA1WithDSA")
//                .create(), null);
//        assertSignedAndTimestamped(tokenDSA, "SHA1", CMSAlgorithm.SHA1, ID_SHA1WITHDSA, resp);
//    }
//
//    /**
//     * Test signing with a ECDSA key-pair.
//     * @throws Exception
//     */
//    @Test
//    public void testNormalSigning_ECDSA() throws Exception {
//        LOG.info("testNormalSigning_ECDSA");
//        SignatureResponse resp = sign(tokenECDSA, new ConfigBuilder()
//                .create(), null);
//        assertSignedAndTimestamped(tokenECDSA, "SHA1", CMSAlgorithm.SHA1, X9ObjectIdentifiers.ecdsa_with_SHA1, resp);
//    }
//
//    /**
//     * Test signing when explicitly specified the SHA1WithECDSA algorithm.
//     * @throws Exception
//     */
//    @Test
//    public void testNormalSigning_SHA1WithECDSA() throws Exception {
//        LOG.info("testNormalSigning_SHA1WithECDSA");
//        SignatureResponse resp = sign(tokenECDSA, new ConfigBuilder()
//                .withSignatureAlgorithm("SHA1WithECDSA")
//                .create(), null);
//        assertSignedAndTimestamped(tokenECDSA, "SHA1", CMSAlgorithm.SHA1, X9ObjectIdentifiers.ecdsa_with_SHA1, resp);
//    }
//
//    /**
//     * Test signing when specified the SHA256WithECDSA algorithm.
//     * @throws Exception
//     */
//    @Test
//    public void testNormalSigning_SHA256WithECDSA() throws Exception {
//        LOG.info("testNormalSigning_SHA256WithECDSA");
//        File file = null;
//        SignatureResponse resp = sign(tokenECDSA, new ConfigBuilder()
//                .withSignatureAlgorithm("SHA256WithECDSA")
//                .create(), null);
//        assertSignedAndTimestamped(tokenECDSA, "SHA1", CMSAlgorithm.SHA256, X9ObjectIdentifiers.ecdsa_with_SHA256, resp);
//    }

    /**
     * Tests that submitting an empty document gives an error.
     * @throws Exception in case of failure.
     */
    @Test
    public void testIncorrectDocument_empty() throws Exception {
        LOG.info("testIncorrectDocument_empty");
        try {
            signData(new byte[0], tokenRSA, new ConfigBuilder()
                    .create(), null);
            fail("Expected IllegalRequestException");
        } catch (IllegalRequestException expected) { // NOPMD
            // OK
        }
    }

    /**
     * Tests that submitting a document with garbage gives an error.
     * @throws Exception in case of failure.
     */
    @Test
    public void testIncorrectDocument_garbage() throws Exception {
        LOG.info("testIncorrectDocument_garbage");
        try {
            signData("anything-not-correct-123-".getBytes(StandardCharsets.US_ASCII), tokenRSA, new ConfigBuilder()
                    .create(), null);
            fail("Expected IllegalRequestException");
        } catch (IllegalRequestException expected) { // NOPMD
            // OK
        }
    }

    /**
     * Test signing a document with the ZIP file-marker followed by
     * garbage gives an error.
     * @throws Exception in case of failure.
     */
    @Test
    public void testIncorrectDocument_garbageMZ() throws Exception {
        LOG.info("testIncorrectDocument_garbageMZ");
        try {
            signData("PK+not-correct-123-".getBytes(StandardCharsets.US_ASCII), tokenRSA, new ConfigBuilder()
                    .create(), null);
            fail("Expected IllegalRequestException");
        } catch (IllegalRequestException expected) { // NOPMD
            // OK
        }
    }

//    @Test
//    public void testSigningAlreadySigned() throws Exception {
//        LOG.info("testSigningAlreadySigned");
//
//        // Fist check that test file already has a signature
//        PEFile peOriginal = new PEFile(executableFileWithSignature);
//        try {
//            if (peOriginal.getSignatures().size() != 1) {
//                throw new Exception("Test expect the test file already have one signature but was " + peOriginal.getSignatures().size());
//            }
//        } finally {
//            peOriginal.close();
//        }
//
//        final byte[] data = FileUtils.readFileToByteArray(executableFileWithSignature);
//
//        File file = null;
//        PEFile pe = null;
//        try {
//            SignatureResponse resp = signData(data, tokenRSA, createConfig(null, null, "SignServer-JUnit-Test-åäö", "http://www.signserver.org/junit/test.html", null, null), null, null);
//            file = createFile(responseData.toReadableData().getAsByteArray());
//            pe = new PEFile(file);
//            assertSignedAndTimestamped(tokenRSA, "SHA1", CMSAlgorithm.SHA1, PKCSObjectIdentifiers.rsaEncryption, resp, pe);
//        } finally {
//            if (pe != null) {
//                pe.close();
//            }
//            if (file != null) {
//                file.delete();
//            }
//        }
//    }

//    /**
//     * Tests that already signed files are rejected with an error.
//     * @throws Exception
//     */
//    @Test
//    public void testSigningAlreadySigned() throws Exception {
//        LOG.info("testSigningAlreadySigned");
//
//        // Fist check that test file already has a signature
//        PEFile peOriginal = new PEFile(executableFileWithSignature);
//        try {
//            if (peOriginal.getSignatures().size() != 1) {
//                throw new Exception("Test expect the test file already have one signature but was " + peOriginal.getSignatures().size());
//            }
//        } finally {
//            peOriginal.close();
//        }
//
//        final byte[] data = FileUtils.readFileToByteArray(executableFileWithSignature);
//
//        File file = null;
//        PEFile pe = null;
//        try {
//            signData(data, tokenRSA, new ConfigBuilder()
//                    .withProgramName("SignServer-JUnit-Test-åäö")
//                    .withProgramURL("http://www.signserver.org/junit/test.html")
//                    .create(), null, null, null);
//            fail("Expected IllegalRequestException");
//        } catch(IllegalRequestException expected) { // NOPMD
//            // OK
//        } finally {
//            if (pe != null) {
//                pe.close();
//            }
//            if (file != null) {
//                file.delete();
//            }
//        }
//    }


    private void assertRequestDigestMatches(File file, String digestAlgorithm, RequestContext context) throws NoSuchAlgorithmException, IOException {
        final LogMap logMap = LogMap.getInstance(context);
        final Object digestAlgLoggable = logMap.get("REQUEST_DIGEST_ALGORITHM");
        assertEquals("digestAlg", digestAlgorithm, String.valueOf(digestAlgLoggable));

        final byte[] data = FileUtils.readFileToByteArray(file);

        final MessageDigest md = MessageDigest.getInstance(digestAlgorithm);
        final String expected = Hex.toHexString(md.digest(data));
        final Object loggable = logMap.get("REQUEST_DIGEST");
        final String actual = String.valueOf(loggable);
        assertEquals("digest", expected, actual);
    }

    private void assertResponseDigestMatches(byte[] data, String digestAlgorithm, RequestContext context) throws NoSuchAlgorithmException {
        final LogMap logMap = LogMap.getInstance(context);
        final Object digestAlgLoggable = logMap.get("RESPONSE_DIGEST_ALGORITHM");
        assertEquals("digestAlg", digestAlgorithm, String.valueOf(digestAlgLoggable));

        final MessageDigest md = MessageDigest.getInstance(digestAlgorithm);
        final String expected = Hex.toHexString(md.digest(data));
        final Object digestLoggable = logMap.get("RESPONSE_DIGEST");
        final String actual = String.valueOf(digestLoggable);
        assertEquals("digest", expected, actual);
    }

    /**
     * Tests logging of the request digest and request digest algorithm using
     * the default algorithm.
     * @throws Exception in case of failure.
     */
    @Test
    public void testLogRequestDigestDefault() throws Exception {
        LOG.info("testLogRequestDigestDefault");
        final RequestContext context = new RequestContext();
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {
            signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withDigestAlgorithm(JAVA_SHA1)
                    .withSignatureAlgorithm("SHA256WithRSA")
                    .create(), context);
            assertRequestDigestMatches(executableFile, "SHA256", context);
        }
    }

    /**
     * Tests logging of the request digest and request digest algorithm using
     * SHA1.
     * @throws Exception in case of failure.
     */
    @Test
    public void testLogRequestDigestSHA1() throws Exception {
        LOG.info("testLogRequestDigestSHA1");
        final RequestContext context = new RequestContext();
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {
            signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withLogRequestDigest("SHA1")
                    .create(), context);
            assertRequestDigestMatches(executableFile, "SHA1", context);
        }
    }

    /**
     * Tests logging of the response digest and response digest algorithm using
     * the default algorithm.
     * @throws Exception in case of failure.
     */
    @Test
    public void testLogResponseDigestDefault() throws Exception {
        LOG.info("testLogResponseDigestDefault");
        final RequestContext context = new RequestContext();
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {
            signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                        .create(), context);
            assertResponseDigestMatches(responseData.toReadableData().getAsByteArray(), "SHA256", context);
        }
    }

    /**
     * Tests logging of the response digest and response digest algorithm using
     * SHA1.
     * @throws Exception in case of failure.
     */
    @Test
    public void testLogResponseDigestSHA1() throws Exception {
        LOG.info("testLogResponseDigestSHA1");
        final RequestContext context = new RequestContext();
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {
            signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                        .withLogResponseDigest("SHA1")
                        .create(), context);
            assertResponseDigestMatches(responseData.toReadableData().getAsByteArray(), "SHA1", context);
        }
    }

    /**
     * Tests no request digest is logged if it is disabled.
     * @throws Exception in case of failure.
     */
    @Test
    public void testLogNoRequestDigest() throws Exception {
        LOG.info("testLogNoRequestDigest");
        final RequestContext context = new RequestContext();
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {
            signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                        .withDoLogRequestDigest(false)
                        .create(), context);
            assertNull("logRequest", LogMap.getInstance(context).get(IWorkerLogger.LOG_REQUEST_DIGEST));
            assertNull("logRequestAlg", LogMap.getInstance(context).get(IWorkerLogger.LOG_REQUEST_DIGEST_ALGORITHM));
        }
    }

    /**
     * Tests no response digest is logged if it is disabled.
     * @throws Exception in case of failure.
     */
    @Test
    public void testLogNoResponseDigest() throws Exception {
        LOG.info("testLogNoResponseDigest");
        final RequestContext context = new RequestContext();
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {
            signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                        .withDoLogResponseDigest(false)
                        .create(), context);
            assertNull("logResponse", LogMap.getInstance(context).get(IWorkerLogger.LOG_RESPONSE_DIGEST));
            assertNull("logResponseAlg", LogMap.getInstance(context).get(IWorkerLogger.LOG_RESPONSE_DIGEST_ALGORITHM));
        }
    }

    /**
     * Test signing of a normal ZIP file (one without META-INF/MANIFEST.MF).
     * @throws Exception in case of failure.
     */
    @Test
    public void testSignZIP() throws Exception {
        LOG.info("testSignZIP");

        // Create a ZIP file
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        ZipOutputStream out = new ZipOutputStream(bout);
        ZipEntry entry = new ZipEntry("file1.txt");
        out.putNextEntry(entry);
        out.write("Content of file 1.".getBytes(StandardCharsets.US_ASCII));
        out.closeEntry();
        out.finish();

        final byte[] data = bout.toByteArray();

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(data);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false)
            ) {

            SignatureResponse resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withDigestAlgorithm(JAVA_SHA_256)
                    .withSignatureAlgorithm("SHA256WithRSA")
                    .create(),
                    null);

            assertSignedAndTimestamped(requestData, responseData, tokenRSA, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, resp);
        }
    }

    /**
     * Tests that setting an incorrect value for ZIPALIGN gives an error.
     */
    @Test
    public void testInit_incorrectZipAlign() {
        LOG.info("testInit_incorrectZipAlign");
        WorkerConfig config = createConfig();
        config.setProperty("ZIPALIGN", "_incorrect_value_");
        JArchiveSigner instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("ZIPALIGN"));
    }

    /**
     * Create a ZIP file with entries which are unaligned.
     * @return the ZIP data
     * @throws Exception in case of failure.
     */
    private byte[] createUnalignedZip() throws Exception {
        // Create a ZIP file
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        ZipOutputStream out = new ZipOutputStream(bout);

        // name: 9, data: 1
        {
            ZipEntry entry1 = new ZipEntry("file1.txt");
            byte[] entry1Bytes = Hex.decode("ff");
            entry1.setMethod(ZipEntry.STORED);
            entry1.setCompressedSize(entry1Bytes.length);
            entry1.setSize(entry1Bytes.length);
            CRC32 crc = new CRC32();
            crc.update(entry1Bytes);
            entry1.setCrc(crc.getValue());
            out.putNextEntry(entry1);
            out.write(entry1Bytes);
            out.closeEntry();
        }

        // name: 10, data: 2
        {
            ZipEntry entry2 = new ZipEntry("file22.txt");
            byte[] entry2Bytes = Hex.decode("f1f2");
            entry2.setMethod(ZipEntry.STORED);
            entry2.setCompressedSize(entry2Bytes.length);
            entry2.setSize(entry2Bytes.length);
            CRC32 crc = new CRC32();
            crc.update(entry2Bytes);
            entry2.setCrc(crc.getValue());
            out.putNextEntry(entry2);
            out.write(entry2Bytes);
            out.closeEntry();
        }

        // name: 11, data: 3
        {
            ZipEntry entry3 = new ZipEntry("file333.txt");
            byte[] entry3Bytes = Hex.decode("f1f2f3");
            entry3.setMethod(ZipEntry.STORED);
            entry3.setCompressedSize(entry3Bytes.length);
            entry3.setSize(entry3Bytes.length);
            CRC32 crc = new CRC32();
            crc.update(entry3Bytes);
            entry3.setCrc(crc.getValue());
            out.putNextEntry(entry3);
            out.write(entry3Bytes);
            out.closeEntry();
        }

        // name: 12, data: 4
        {
            ZipEntry entry4 = new ZipEntry("file4444.txt");
            byte[] entry4Bytes = Hex.decode("f1f2f3f4");
            entry4.setMethod(ZipEntry.STORED);
            entry4.setCompressedSize(entry4Bytes.length);
            entry4.setSize(entry4Bytes.length);
            CRC32 crc = new CRC32();
            crc.update(entry4Bytes);
            entry4.setCrc(crc.getValue());
            out.putNextEntry(entry4);
            out.write(entry4Bytes);
            out.closeEntry();
        }

        out.finish();
        return bout.toByteArray();
    }

    /**
     * Test signing of a JAR/ZIP file and check that it is 'zipaligned'.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSignZIPAligned() throws Exception {
        LOG.info("testSignZIPAligned");

        // Get some ZIP data with entries which are unaligned
        final byte[] zipFile = createUnalignedZip();

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(zipFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false)
            ) {

            // Note: zipAlign specified
            SignatureResponse resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withDigestAlgorithm(JAVA_SHA_256)
                    .withSignatureAlgorithm("SHA256WithRSA")
                    .withZipAlign(true)
                    .create(),
                    null);
            assertSignedAndTimestamped(requestData, responseData, tokenRSA, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, resp);
            byte[] data = responseData.toReadableData().getAsByteArray();

            assertAllZipAligned(true, data);
        }
    }

    /**
     * Test signing of a JAR/ZIP file and check that it is not 'zipaligned'
     * by default.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSignZIPAligned_default() throws Exception {
        LOG.info("testSignZIPAligned_default");

        // Get some ZIP data with entries which are unaligned
        final byte[] zipFile = createUnalignedZip();

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(zipFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false)
            ) {
            // Note: No zipAlign specified
            SignatureResponse resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withDigestAlgorithm(JAVA_SHA_256)
                    .withSignatureAlgorithm("SHA256WithRSA")
                    .create(),
                    null);
            assertSignedAndTimestamped(requestData, responseData, tokenRSA, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, resp);
            byte[] data = responseData.toReadableData().getAsByteArray();

            assertAllZipAligned(false, data);
        }
    }

    /**
     * Test signing of a JAR/ZIP file and specify zipAlign=false and check that
     * it is not 'zipaligned'.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSignZIPAligned_false() throws Exception {
        LOG.info("testSignZIPAligned_false");

        // Get some ZIP data with entries which are unaligned
        final byte[] zipFile = createUnalignedZip();

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(zipFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false)
            ) {
            // Note: zipAlign=false specified
            SignatureResponse resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withDigestAlgorithm(JAVA_SHA_256)
                    .withSignatureAlgorithm("SHA256WithRSA")
                    .withZipAlign(false)
                    .create(),
                    null);
            assertSignedAndTimestamped(requestData, responseData, tokenRSA, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, resp);
            byte[] data = responseData.toReadableData().getAsByteArray();

            assertAllZipAligned(false, data);
        }
    }

    private void assertAllZipAligned(final boolean expectAllAligned, byte[] data) throws Exception {
        // Parse the resulting JAR file
        File signedFile = File.createTempFile("test-zip", ".signed");
        FileUtils.writeByteArrayToFile(signedFile, data);
        JarFile jar = new JarFile(signedFile, true);

        // Loop over each entry and keep track of the offset at which the data
        // begins
        Enumeration<JarEntry> entries = jar.entries();
        int offset = 0;
        final StringBuilder sb = new StringBuilder();
        boolean allStoredAligned = true;
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();

            // Get the lengths of the variable length header fields
            final int nameLen = entry.getName().getBytes(StandardCharsets.UTF_8).length;
            final int extraLen = entry.getExtra() == null ? 0 : entry.getExtra().length;

            // The length of the header
            final long totalHeader = JarFile.LOCHDR + nameLen + extraLen;

            // The length of the data (after the header / before the next entry)
            final long dataLen = entry.getCompressedSize();

            // Is the data starting at an offset which is a multiple of 4?
            final boolean multiple = (offset + totalHeader) % 4 == 0;

            // Output the entry for troubleshooting
            final String entryInfo = "Entry at " + offset +  ": Header(" + JarFile.LOCHDR + ",\"" + entry.getName() + "\" (" + nameLen + ")," + extraLen + "=" + totalHeader + ") Data at " + (offset + totalHeader) + " (" + (multiple ? "aligned" : "unaligned")  + ") : " + dataLen + " " + (entry.getMethod() != JarEntry.STORED ? "skipped" : "");
            LOG.info(entryInfo);
            sb.append(entryInfo);

            // Register if any stored entry was not aligned
            if (entry.getMethod() == JarEntry.STORED && !multiple) {
                allStoredAligned = false;
            }

            // Increase the offset with this entry
            offset += totalHeader + dataLen;
        }

        if (expectAllAligned) {
            assertTrue("All STORED entries should be on multiple:\n" + sb,
                    allStoredAligned);
        } else {
            assertFalse("Some STORED entries should be unaligned:\n" + sb,
                    allStoredAligned);
        }
    }

    /**
     * Test signing an already signed file again with the same digest algorithm
     * and an other signer name.
     * Note: The file is assumed to have an existing signature with an other
     * name than CERT.SF/RSA and to have SHA-256-Digest entries in MANIFEST.MF.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSignAgain_CERT0_SHA256() throws Exception {
        LOG.info("testSignAgain_CERT0_SHA256");

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFileWithSignature);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {

            // Extract the certificate(s) from previous signature(s)
            // And extract all signature entries
            Collection<WrappedJarEntry> sigEntries = new LinkedList<>();
            Collection<Certificate> signerCerts = new LinkedList<>();
            gatherPreviousSignatures(requestData, sigEntries, signerCerts);
            if (sigEntries.size() < 1) {
                throw new Exception("Test expects " + executableFileWithSignature + " to have at least one existing signature");
            }
            boolean found = false;
            for (WrappedJarEntry entry : sigEntries) {
                if (entry.getName().equalsIgnoreCase("META-INF/CERT0.SF")) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw new Exception("Test expects " + executableFileWithSignatureTS + " to have CERT0.SF");
            }

            // Note: keepSignatures
            SignatureResponse resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withSignatureNameType(SignatureNameType.VALUE).withSignatureNameValue("CERT2")
                    .withDigestAlgorithm(JAVA_SHA_256)
                    .withKeepSignatures(true)
                    .create(), null);
            // FileUtils.writeByteArrayToFile(new File("/tmp/out-resigned.zip"), responseData.toReadableData().getAsByteArray());

            assertSignedAndTimestamped(requestData, responseData, tokenRSA, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, resp, signerCerts, sigEntries);
        }
    }

    /**
     * Test signing an already signed file again replacing the existing
     * signatures.
     * Note: The file is assumed to have an existing signature.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSignAgain_replaceSigs() throws Exception {
        LOG.info("testSignAgain_replaceSigs");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFileWithSignature);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {

            // Extract the certificate(s) from previous signature(s)
            // And extract all signature entries
            Collection<WrappedJarEntry> sigEntries = new LinkedList<>();
            Collection<Certificate> signerCerts = new LinkedList<>();
            gatherPreviousSignatures(requestData, sigEntries, signerCerts);
            if (sigEntries.size() < 1) {
                throw new Exception("Test expects " + executableFileWithSignature + " to have at least one existing signature");
            }

            // Expect old sigs to get removed
            sigEntries = Collections.emptyList();
            signerCerts = Collections.emptyList();

            // Note: keepSignatures=false
            SignatureResponse resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withDigestAlgorithm(JAVA_SHA1)
                    .withKeepSignatures(false)
                    .create(), null);
            //FileUtils.writeByteArrayToFile(new File("/tmp/out-resigned.zip"), responseData.toReadableData().getAsByteArray());

            assertSignedAndTimestamped(requestData, responseData, tokenRSA, JAVA_SHA1, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, resp, signerCerts, sigEntries);
        }
    }

    /**
     * Test signing an already signed file again with a different digest
     * algorithm and an other signer name.
     * Note 1: The file is assumed to have an existing signature with an other
     * name than CERT.SF/RSA and to not have SHA-1-Digest entries in MANIFEST.MF.
     * Note 2: As with jarsigner (1.8.0_65) the resulting JAR will not verify
     * correctly so this test only checks that we are bug-compatible with
     * jarsigner and allows the production of such jar.
     * In a future version we might want to instead return a failure for this
     * case.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSignAgain_CERT0_SHA1() throws Exception {
        LOG.info("testSignAgain_CERT0_SHA1");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFileWithSignature);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {

            // Extract the certificate(s) from previous signature(s)
            // And extract all signature entries
            Collection<WrappedJarEntry> sigEntries = new LinkedList<>();
            Collection<Certificate> signerCerts = new LinkedList<>();
            gatherPreviousSignatures(requestData, sigEntries, signerCerts);
            if (sigEntries.size() < 1) {
                throw new Exception("Test expects " + executableFileWithSignature + " to have at least one existing signature");
            }
            boolean found = false;
            for (WrappedJarEntry entry : sigEntries) {
                if (entry.getName().equalsIgnoreCase("META-INF/CERT0.SF")) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw new Exception("Test expects " + executableFileWithSignature + " to have CERT0.SF");
            }

            // Note: keepSignatures
            signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withSignatureNameType(SignatureNameType.VALUE).withSignatureNameValue("CERT2")
                    .withDigestAlgorithm(JAVA_SHA1)
                    .withKeepSignatures(true)
                    .create(), null);
            //FileUtils.writeByteArrayToFile(new File("/tmp/out-resigned.zip"), responseData.toReadableData().getAsByteArray());
        }
    }

    /**
     * Test signing of a normal ZIP file (one without META-INF/MANIFEST.MF),
     * using the KEEPSIGNATURES=true option.
     * Purpose with test is to see that KEEPSIGNATURES does not freak out on
     * missing MANIFEST.MF.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSignAgainZIP_withoutManifest() throws Exception {
        LOG.info("testSignAgainZIP_withoutManifest");

        // Create a ZIP file
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        ZipOutputStream out = new ZipOutputStream(bout);
        ZipEntry entry = new ZipEntry("file1.txt");
        out.putNextEntry(entry);
        out.write("Content of file 1.".getBytes(StandardCharsets.US_ASCII));
        out.closeEntry();
        out.finish();

        final byte[] data = bout.toByteArray();

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(data);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false)
            ) {

            SignatureResponse resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withDigestAlgorithm(JAVA_SHA_256)
                    .withSignatureAlgorithm("SHA256WithRSA")
                    .withKeepSignatures(true)
                    .create(),
                    null);

            assertSignedAndTimestamped(requestData, responseData, tokenRSA, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, resp);
        }
    }

    /**
     * Test signing an already signed file again with the same digest algorithm
     * and the same signer name.
     * Note: The file is assumed to have an existing signature with a
     * CERT.SF/RSA and to have SHA-256-Digest entries in MANIFEST.MF.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSignAgain_sameAlias() throws Exception {
        LOG.info("testSignAgain_sameAlias");

        signAgain_SameAlias(executableFileWithSignatureTS);
    }

    /**
     * Test signing an already signed file again with the same digest algorithm
     * and the same signer name, but where existing signatures are STORED
     * instead of DEFLATED.
     * Note: The file is assumed to have an existing signature with a
     * CERT.SF/RSA and to have SHA-256-Digest entries in MANIFEST.MF.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSignAgain_sameAlias_stored() throws Exception {
        LOG.info("testSignAgain_sameAlias_stored");

        File file = null;
        try {
            file = createTempFileWithStoredEntriesFromJar(executableFileWithSignatureTS);

            signAgain_SameAlias(file);
        } finally {
            FileUtils.deleteQuietly(file);
        }
    }

    private File createTempFileWithStoredEntriesFromJar(File input) throws Exception {
        File file = File.createTempFile("HelloJar-signed-ts-stored", ".jar");
        try (ZipFile zf = new ZipFile(input); ZipOutputStream zout = new ZipOutputStream(new FileOutputStream(file))) {
            Enumeration<? extends ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                ZipEntry newEntry = new ZipEntry(entry.getName());
                newEntry.setMethod(ZipEntry.STORED);
                newEntry.setSize(entry.getSize());

                byte[] content = IOUtils.toByteArray(zf.getInputStream(entry));
                assertEquals(entry.getSize(), content.length);

                CRC32 crc = new CRC32();
                crc.update(content);
                newEntry.setCrc(crc.getValue());

                zout.putNextEntry(newEntry);
                zout.write(content);
            }
        }
        return file;
    }

    private void signAgain_SameAlias(File file) throws Exception {
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(file);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {

            // Extract the certificate(s) from previous signature(s)
            // And extract all signature entries
            Collection<WrappedJarEntry> sigEntries = new LinkedList<>();
            Collection<Certificate> signerCerts = new LinkedList<>();
            gatherPreviousSignatures(requestData, sigEntries, signerCerts);
            if (sigEntries.size() < 1) {
                throw new Exception("Test expects " + file + " to have at least one existing signature");
            }
            boolean found = false;
            for (WrappedJarEntry entry : sigEntries) {
                if (entry.getName().equalsIgnoreCase("META-INF/CERT.SF")) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw new Exception("Test expects " + file + " to have CERT.SF");
            }

            // Note: keepSignatures
            try {
                signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withSignatureNameType(SignatureNameType.VALUE).withSignatureNameValue("CERT")
                    .withReplaceSignature(false)
                    .withDigestAlgorithm(JAVA_SHA_256)
                    .withKeepSignatures(true)
                    .create(), null);
                fail("Should have thrown IllegalRequestException as the file already contains a signature with the same name and replaceSignature=false");
            } catch (IllegalRequestException ex) {
                assertTrue("exception: " + ex.getMessage(), ex.getMessage().contains("same name"));
            }
        }
    }

    /**
     * Test signing an already signed file again with the same digest algorithm
     * and the same signer name, replacing the signature file.
     * Note: The file is assumed to have an existing signature with a
     * CERT.SF/RSA and to have SHA-256-Digest entries in MANIFEST.MF.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSignAgain_sameAlias_replace() throws Exception {
        LOG.info("testSignAgain_sameAlias_replace");
        signAgain_sameAlias_replace(executableFileWithSignatureTS);
    }

    /**
     * Test signing an already signed file again with the same digest algorithm
     * and the same signer name, replacing the signature file but with an
     * input JAR having STORED entries instead of DEFLATED.
     * Note: The file is assumed to have an existing signature with a
     * CERT.SF/RSA and to have SHA-256-Digest entries in MANIFEST.MF.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSignAgain_sameAlias_replace_stored() throws Exception {
        LOG.info("testSignAgain_sameAlias_replace_stored");
        File file = null;
        try {
            file = createTempFileWithStoredEntriesFromJar(executableFileWithSignatureTS);

            signAgain_sameAlias_replace(executableFileWithSignatureTS);
        } finally {
            FileUtils.deleteQuietly(file);
        }
    }

    private void signAgain_sameAlias_replace(File file) throws Exception {
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(file);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {

            // Extract the certificate(s) from previous signature(s)
            // And extract all signature entries
            Collection<WrappedJarEntry> sigEntries = new LinkedList<>();
            Collection<Certificate> signerCerts = new LinkedList<>();
            gatherPreviousSignatures(requestData, sigEntries, signerCerts);
            if (sigEntries.size() < 1) {
                throw new Exception("Test expects " + file + " to have at least one existing signature");
            }
            boolean found = false;
            for (WrappedJarEntry entry : sigEntries) {
                if (entry.getName().equalsIgnoreCase("META-INF/CERT.SF")) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw new Exception("Test expects " + file + " to have CERT.SF");
            }

            // We expect the previous signature to be removed
            signerCerts.clear();
            sigEntries.clear();

            // Note: replaceSignature=true,
            // keepSignatures=true (not important)
            SignatureResponse resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withSignatureNameType(SignatureNameType.VALUE).withSignatureNameValue("CERT")
                    .withReplaceSignature(true)
                    .withDigestAlgorithm(JAVA_SHA_256)
                    .withKeepSignatures(true)
                    .create(), null);
            // FileUtils.writeByteArrayToFile(new File("/tmp/out-resigned.zip"), responseData.toReadableData().getAsByteArray());
            assertSignedAndTimestamped(requestData, responseData, tokenRSA, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, resp, signerCerts, sigEntries);

            // Note: replaceSignature=true,
            // keepSignatures=false (not important)
            resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withReplaceSignature(true)
                    .withDigestAlgorithm(JAVA_SHA_256)
                    .withKeepSignatures(false)
                    .create(), null);
            // FileUtils.writeByteArrayToFile(new File("/tmp/out-resigned.zip"), responseData.toReadableData().getAsByteArray());
            assertSignedAndTimestamped(requestData, responseData, tokenRSA, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, resp, signerCerts, sigEntries);
        }
    }

    /**
     * Tests that setting an incorrect value for KEEPSIGNATURES gives an error.
     */
    @Test
    public void testInit_incorrectKeepSignatures() {
        LOG.info("testInit_incorrectKeepSignatures");
        WorkerConfig config = createConfig();
        config.setProperty("KEEPSIGNATURES", "_incorrect_value_");
        JArchiveSigner instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("KEEPSIGNATURES"));
    }

    /**
     * Tests that setting an incorrect value for REPLACESIGNATURE gives an error.
     */
    @Test
    public void testInit_incorrectReplaceSignature() {
        LOG.info("testInit_incorrectKeepSignatures");
        WorkerConfig config = createConfig();
        config.setProperty("REPLACESIGNATURE", "_incorrect_value_");
        JArchiveSigner instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("REPLACESIGNATURE"));
    }

    /**
     * Tests that setting an incorrect value for SIGNATURE_NAME_TYPE gives an
     * error.
     */
    @Test
    public void testInit_incorrectSignatureNameType() {
        LOG.info("testInit_incorrectSignatureNameType");
        WorkerConfig config = createConfig();
        config.setProperty("SIGNATURE_NAME_TYPE", "_incorrect_value_");
        JArchiveSigner instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors contains the error: " + actualErrors, actualErrors.contains("SIGNATURE_NAME_TYPE"));
        assertTrue("fatalErrors contains correct type VALUE: " + actualErrors, actualErrors.contains("VALUE"));
        assertTrue("fatalErrors contains correct type KEYALIAS: " + actualErrors, actualErrors.contains("KEYALIAS"));
    }

    /**
     * Tests that setting an incorrect value for SIGNATURE_NAME_VALUE with
     * type KEYALIAS gives an error.
     * error.
     */
    @Test
    public void testInit_incorrectSignatureNameValue_KEYALIAS() {
        LOG.info("testInit_incorrectSignatureNameValue_KEYALIAS");
        WorkerConfig config = createConfig();
        config.setProperty("SIGNATURE_NAME_TYPE", JArchiveSigner.SignatureNameType.KEYALIAS.name());
        config.setProperty("SIGNATURE_NAME_VALUE", "_incorrect_value_");
        JArchiveSigner instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors contains the error: " + actualErrors, actualErrors.contains("SIGNATURE_NAME_VALUE"));
        assertTrue("fatalErrors contains KEYALIAS: " + actualErrors, actualErrors.contains("KEYALIAS"));
    }

    /**
     * Tests that not setting a value for SIGNATURE_NAME_VALUE with
     * type VALUE gives an error.
     * error.
     */
    @Test
    public void testInit_missingSignatureNameValue_VALUE() {
        LOG.info("testInit_missingSignatureNameValue_VALUE");
        WorkerConfig config = createConfig();
        config.setProperty("SIGNATURE_NAME_TYPE", JArchiveSigner.SignatureNameType.VALUE.name());
        config.setProperty("SIGNATURE_NAME_VALUE", "");
        JArchiveSigner instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors contains the error: " + actualErrors, actualErrors.contains("SIGNATURE_NAME_VALUE"));
        assertTrue("fatalErrors contains  VALUE: " + actualErrors, actualErrors.contains(" VALUE"));
    }

    /**
     * Test signing and specifying a signature name value.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigning_SignatureNameType_VALUE() throws Exception {
        LOG.info("testSigning_SignatureNameType_VALUE");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {
                SignatureResponse res = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withSignatureNameType(SignatureNameType.VALUE)
                    .withSignatureNameValue("ADAM")
                    .create(), null);
            assertSignedAndTimestamped(requestData, responseData, tokenRSA, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, res);
            assertContainsSignatures(responseData.toReadableData().getAsByteArray(), "ADAM", "RSA");
        }
    }

    /**
     * Test signing and specifying a signature name value.
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigning_SignatureNameType_KEYALIAS() throws Exception {
        LOG.info("testSigning_SignatureNameType_KEYALIAS");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {
            SignatureResponse resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                .withSignatureNameType(SignatureNameType.KEYALIAS)
                .withSignatureNameValue("")
                .create(), null);
            assertSignedAndTimestamped(requestData, responseData, tokenRSA, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, resp);
            assertContainsSignatures(responseData.toReadableData().getAsByteArray(), KEYALIAS_CONVERTED, "RSA");
        }
    }

    /**
     * Tests that setting an incorrect value (too long) for
     * SIGNATURE_NAME_VALUE with type VALUE gives an error.
     */
    @Test
    public void testInit_incorrectSignatureNameValue_tooLongVALUE() {
        LOG.info("testInit_incorrectSignatureNameValue_tooLongVALUE");
        WorkerConfig config = createConfig();
        config.setProperty("SIGNATURE_NAME_TYPE", JArchiveSigner.SignatureNameType.VALUE.name());
        config.setProperty("SIGNATURE_NAME_VALUE", "abcdefghi"); // 9 ASCII characters is 1 too much
        JArchiveSigner instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors contains the error: " + actualErrors, actualErrors.contains("SIGNATURE_NAME_VALUE"));
    }

    /**
     * Tests that setting an incorrect value (with spaces) for
     * SIGNATURE_NAME_VALUE with type VALUE gives an error.
     */
    @Test
    public void testInit_incorrectSignatureNameValue_spacesInVALUE() {
        LOG.info("testInit_incorrectSignatureNameValue_spacesInVALUE");
        WorkerConfig config = createConfig();
        config.setProperty("SIGNATURE_NAME_TYPE", JArchiveSigner.SignatureNameType.VALUE.name());
        config.setProperty("SIGNATURE_NAME_VALUE", "a cdefgh");
        JArchiveSigner instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors contains the error: " + actualErrors, actualErrors.contains("SIGNATURE_NAME_VALUE"));
        assertTrue("fatalErrors contains the converted value: " + actualErrors, actualErrors.contains("A_CDEFGH"));
    }

    @Test
    public void testConvertToValidSignatureName() {
        LOG.info("testConvertToValidSignatureName");

        // Ok with less than 8 characters and no special ones
        assertEquals("<= 8 characters 1", "A", JArchiveSigner.convertToValidSignatureName("A"));
        assertEquals("<= 8 characters 7", "ABCDEFG", JArchiveSigner.convertToValidSignatureName("ABCDEFG"));
        assertEquals("<= 8 characters 8", "ABCDEFGH", JArchiveSigner.convertToValidSignatureName("ABCDEFGH"));

        // Longer names
        assertEquals("9 characters", "ABCDEFGH", JArchiveSigner.convertToValidSignatureName("ABCDEFGHI"));
        assertEquals("10 characters", "ABCDEFGH", JArchiveSigner.convertToValidSignatureName("ABCDEFGHIJ"));
        assertEquals("19 characters", "ABCDEFGH", JArchiveSigner.convertToValidSignatureName("ABCDEFGHIJKLMNOPQRS"));

        // Empty name
        assertEquals("empty name", "_", JArchiveSigner.convertToValidSignatureName("")); // Special case: We need at least one character in the name

        // Ok with dots, minus and underscore
        assertEquals("dots, minus and understore", "AB.D-F_H", JArchiveSigner.convertToValidSignatureName("AB.D-F_H"));

        // With spaces
        assertEquals("1 space", "A_CDEFGH", JArchiveSigner.convertToValidSignatureName("A CDEFGH"));
        assertEquals("2 space", "A_CDE_GH", JArchiveSigner.convertToValidSignatureName("A CDE GH"));
        assertEquals("2 space", "_BCDEFG_", JArchiveSigner.convertToValidSignatureName(" BCDEFG "));
        assertEquals("3 space and shorter", "_BCDE__", JArchiveSigner.convertToValidSignatureName(" BCDE  "));
        assertEquals("3 space and longer", "AB_DE_G_", JArchiveSigner.convertToValidSignatureName("AB DE G IJKLMNOPQRS"));

        // With other characters
        assertEquals("other characters 1", "A__D_F__", JArchiveSigner.convertToValidSignatureName("A :D!F%+"));
        assertEquals("other characters 2", "________", JArchiveSigner.convertToValidSignatureName("@Ä}:*!&%+"));

        // Convert to uppercase
        assertEquals("uppercase 1", "ABCDEFGH", JArchiveSigner.convertToValidSignatureName("aBcDeFgH"));
    }

    /**
     * Tests including 3 certificate levels in the document.
     *
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigningWithIntermediateCert_3levels() throws Exception {
        LOG.info("testSigningWithIntermediateCert_3levels");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {
            SignatureResponse resp = signData(requestData, responseData, tokenRSAwithIntermediate, new ConfigBuilder()
                    .withIncludeCertificateLevels(3)
                    .withSignatureNameType(SignatureNameType.VALUE).withSignatureNameValue("CERT")
                    .create(), null);
            assertSignedAndTimestamped(requestData, responseData, tokenRSAwithIntermediate, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, resp);

            List<? extends Certificate> certs = getCertificateChainFromJAR(responseData.toReadableData().getAsByteArray());

            // Check that the intermediate cert is included in the chain
            assertEquals(tokenRSAwithIntermediate.getCertificateChain(ICryptoTokenV4.PURPOSE_SIGN), certs);
        }
    }

    /**
     * Tests specifying many more certificates than available to including all 3 certificate levels in the document.
     *
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigningWithIntermediateCert_99levels() throws Exception {
        LOG.info("testSigningWithIntermediateCert_99levels");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {
            SignatureResponse resp = signData(requestData, responseData, tokenRSAwithIntermediate, new ConfigBuilder()
                    .withIncludeCertificateLevels(99)
                    .withSignatureNameType(SignatureNameType.VALUE).withSignatureNameValue("CERT")
                    .create(), null);
            assertSignedAndTimestamped(requestData, responseData, tokenRSAwithIntermediate, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, resp);

            List<? extends Certificate> certs = getCertificateChainFromJAR(responseData.toReadableData().getAsByteArray());

            // Check that the intermediate cert is included in the chain
            assertEquals(tokenRSAwithIntermediate.getCertificateChain(ICryptoTokenV4.PURPOSE_SIGN), certs);
        }
    }

    /**
     * Tests including 1 certificate level in the document.
     *
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigningWithoutIntermediateCert_1levels() throws Exception {
        LOG.info("testSigningWithoutIntermediateCert_1levels");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {
            SignatureResponse resp = signData(requestData, responseData, tokenRSAwithIntermediate, new ConfigBuilder()
                    .withIncludeCertificateLevels(1)
                    .withSignatureNameType(SignatureNameType.VALUE).withSignatureNameValue("CERT")
                    .create(), null);
            assertSignedAndTimestamped(requestData, responseData, tokenRSAwithIntermediate, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, resp);

            List<? extends Certificate> certs = getCertificateChainFromJAR(responseData.toReadableData().getAsByteArray());

            // Check that the intermediate cert is included in the chain
            assertEquals(Arrays.asList(tokenRSAwithIntermediate.getCertificate(ICryptoTokenV4.PURPOSE_SIGN)), certs);
        }
    }

    /**
     * Tests including 2 certificate levels in the document.
     *
     * @throws Exception in case of failure.
     */
    @Test
    public void testSigningWithIntermediateCert_2levels() throws Exception {
        LOG.info("testSigningWithIntermediateCert_2levels");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {
            SignatureResponse resp = signData(requestData, responseData, tokenRSAwithIntermediate, new ConfigBuilder()
                    .withIncludeCertificateLevels(2)
                    .withSignatureNameType(SignatureNameType.VALUE).withSignatureNameValue("CERT")
                    .create(), null);
            assertSignedAndTimestamped(requestData, responseData, tokenRSAwithIntermediate, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, resp);

            List<? extends Certificate> certs = getCertificateChainFromJAR(responseData.toReadableData().getAsByteArray());

            // Check that the intermediate cert is included in the chain
            List<Certificate> configuredChain = new LinkedList<>(tokenRSAwithIntermediate.getCertificateChain(ICryptoTokenV4.PURPOSE_SIGN));
            configuredChain.remove(configuredChain.size() - 1); // Remove last (the root)
            assertEquals(configuredChain, certs);
        }
    }

    /**
     * Tests incorrect values for the INCLUDE_CERTIFICATE_LEVELS worker property.
     */
    @Test
    public void testInit_includeCertificateLevelsProperty() {
        LOG.info("testInit_includeCertificateLevelsProperty");
        WorkerConfig config = createConfig();
        config.setProperty("INCLUDE_CERTIFICATE_LEVELS", "0");
        JArchiveSigner instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(4711, config, null, null);
        List<String> actualErrors = instance.getFatalErrors(null);
        assertTrue("message: " + actualErrors, actualErrors.toString().contains("INCLUDE_CERTIFICATE_LEVELS"));

        config.setProperty("INCLUDE_CERTIFICATE_LEVELS", "-1");
        instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(4711, config, null, null);
        actualErrors = instance.getFatalErrors(null);
        assertTrue("message: " + actualErrors, actualErrors.toString().contains("INCLUDE_CERTIFICATE_LEVELS"));

        config.setProperty("INCLUDE_CERTIFICATE_LEVELS", "qwerty");
        instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(4711, config, null, null);
        actualErrors = instance.getFatalErrors(null);
        assertTrue("message: " + actualErrors, actualErrors.toString().contains("INCLUDE_CERTIFICATE_LEVELS"));
    }

    /**
     * Tests that setting an incorrect value for TSA_POLICYOID gives an error.
     */
    @Test
    public void testInit_incorrectTSAPolicyOID() {
        LOG.info("testInit_incorrectTSAPolicyOID");
        WorkerConfig config = createConfig();
        config.setProperty("TSA_POLICYOID", "_incorrect_value_");
        JArchiveSigner instance = new MockedJArchiveSigner(KEYALIAS_REAL, tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("TSA_POLICYOID"));
    }

    private void gatherPreviousSignatures(ReadableData data, Collection<WrappedJarEntry> sigEntries, Collection<Certificate> signerCerts) throws Exception {
        JarFile jar = new JarFile(data.getAsFile(), true);
        Enumeration<JarEntry> entries = jar.entries();
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            IOUtils.copy(jar.getInputStream(entry), NullOutputStream.NULL_OUTPUT_STREAM);

            // Gather the signer certificates from the first entry which has any
            if (signerCerts.isEmpty() && entry.getCodeSigners().length > 0) {
                signerCerts.addAll(getSignersCertificate(entry.getCodeSigners()));
            }

            // Gather signature entries
            if (entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".SF") || entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".DSA") || entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".EC") || entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".RSA")) {
                sigEntries.add(new WrappedJarEntry(entry));
            }
        }
    }

    private List<? extends Certificate> getCertificateChainFromJAR(byte[] data) throws Exception {
        File origFile = null;
        try {
            origFile = File.createTempFile("orig-file", ".jar");

            FileUtils.writeByteArrayToFile(origFile, data);
            JarFile jar = new JarFile(origFile, true);
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                IOUtils.copy(jar.getInputStream(entry), NullOutputStream.NULL_OUTPUT_STREAM);

                // Gather the signer certificates from the first entry which has any
                if (!entry.isDirectory() && entry.getCodeSigners().length > 0) {
                    return entry.getCodeSigners()[0].getSignerCertPath().getCertificates();
                }
            }
            return Collections.emptyList();
        } finally {
            if (origFile != null) {
                origFile.delete();
            }
        }
    }

    private void assertContainsSignatures(byte[] data, String signatureName, String keyAlg) throws Exception {
        File origFile = null;
        try {
            origFile = File.createTempFile("orig-file", ".jar");

            FileUtils.writeByteArrayToFile(origFile, data);
            JarFile jar = new JarFile(origFile, true);
            Enumeration<JarEntry> entries = jar.entries();
            HashSet<String> names = new HashSet<>();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                names.add(entry.getName());
            }

            assertTrue("contains " + signatureName + ".SF: " + names, names.contains("META-INF/" + signatureName + ".SF"));
            assertTrue("contains " + signatureName + "." + keyAlg + ": " + names, names.contains("META-INF/" + signatureName + "." + keyAlg));
        } finally {
            if (origFile != null) {
                origFile.delete();
            }
        }
    }

    private Collection<Certificate> getSignersCertificate(CodeSigner[] signers) {
        Collection<Certificate> result = new LinkedList<>();
        for (CodeSigner signer : signers) {
            result.add(signer.getSignerCertPath().getCertificates().iterator().next());
        }
        return result;
    }

    private static WorkerConfig createConfig() {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty(WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        return config;
    }

    /** Builder for configuration. */
    private static class ConfigBuilder {
        private final WorkerConfig config = createConfig();

        public WorkerConfig create() {
            return config;
        }

        public ConfigBuilder withSignatureAlgorithm(String signatureAlgorithm) {
            config.setProperty("SIGNATUREALGORITHM", signatureAlgorithm);
            return this;
        }

        public ConfigBuilder withDigestAlgorithm(String digestAlgorithm) {
            config.setProperty("DIGESTALGORITHM", digestAlgorithm);
            return this;
        }

        public ConfigBuilder withLogRequestDigest(String logRequestDigest) {
            config.setProperty("LOGREQUEST_DIGESTALGORITHM", logRequestDigest);
            return this;
        }

        public ConfigBuilder withLogResponseDigest(String logResponseDigest) {
            config.setProperty("LOGRESPONSE_DIGESTALGORITHM", logResponseDigest);
            return this;
        }

        public ConfigBuilder withDoLogRequestDigest(boolean doLogRequestDigest) {
            config.setProperty("DO_LOGREQUEST_DIGEST", String.valueOf(doLogRequestDigest));
            return this;
        }

        public ConfigBuilder withDoLogResponseDigest(boolean doLogResponseDigest) {
            config.setProperty("DO_LOGRESPONSE_DIGEST", String.valueOf(doLogResponseDigest));
            return this;
        }

        private ConfigBuilder withZipAlign(boolean zipAlign) {
            config.setProperty("ZIPALIGN", String.valueOf(zipAlign));
            return this;
        }

        private ConfigBuilder withKeepSignatures(boolean keepSignatures) {
            config.setProperty("KEEPSIGNATURES", String.valueOf(keepSignatures));
            return this;
        }

        private ConfigBuilder withReplaceSignature(boolean keepSignatures) {
            config.setProperty("REPLACESIGNATURE", String.valueOf(keepSignatures));
            return this;
        }

        private ConfigBuilder withSignatureNameType(SignatureNameType type) {
            config.setProperty("SIGNATURE_NAME_TYPE", String.valueOf(type));
            return this;
        }

        private ConfigBuilder withSignatureNameValue(String value) {
            config.setProperty("SIGNATURE_NAME_VALUE", value);
            return this;
        }

        private ConfigBuilder withIncludeCertificateLevels(int levels) {
            config.setProperty("INCLUDE_CERTIFICATE_LEVELS", String.valueOf(levels));
            return this;
        }
    }



    private SignatureResponse signData(final byte[] data, MockedCryptoToken token, WorkerConfig config, RequestContext requestContext) throws Exception {
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(data);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false)
            ) {
            return signData(requestData, responseData, token, config, requestContext);
        }
    }

    private SignatureResponse signData(final ReadableData requestData, final WritableData responseData, MockedCryptoToken token, WorkerConfig config, RequestContext requestContext) throws Exception {
        MockedJArchiveSigner instance = new MockedJArchiveSigner(KEYALIAS_REAL, token);
        instance.init(1, config, new SignServerContext(), null);

        if (requestContext == null) {
            requestContext = new RequestContext();
        }
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");

        SignatureRequest request = new SignatureRequest(100, requestData, responseData);
        return  (SignatureResponse) instance.processData(request, requestContext);
    }

    /*private GenericSignResponse sign(MockedCryptoToken token, WorkerConfig config, RequestContext requestContext) throws Exception {
        final byte[] data = FileUtils.readFileToByteArray(executableFile);
        return signData(data, token, config, requestContext);
    }*/

    private void signAndAssertSignedAndTimestamped(MockedCryptoToken token, WorkerConfig config, RequestContext requestContext, String sfDigestAlg, ASN1ObjectIdentifier cmsDigestAlgOID, ASN1ObjectIdentifier sigAlgOID) throws Exception {
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true)
            ) {
            SignatureResponse res = signData(requestData, responseData, token, config, requestContext);

            assertSignedAndTimestamped(requestData, responseData, token, sfDigestAlg, cmsDigestAlgOID, sigAlgOID, res, Collections.emptyList(), Collections.emptyList());
        }
    }

    private void assertSignedAndTimestamped(ReadableData requestData, WritableData responseData, MockedCryptoToken token, String sfDigestAlg, ASN1ObjectIdentifier cmsDigestAlgOID, ASN1ObjectIdentifier sigAlgOID, SignatureResponse res) throws Exception {
        assertSignedAndTimestamped(requestData, responseData, token, sfDigestAlg, cmsDigestAlgOID, sigAlgOID, res, Collections.emptyList(), Collections.emptyList());
    }

    private void assertSignedAndTimestamped(ReadableData requestData, WritableData responseData, MockedCryptoToken token, String sfDigestAlg, ASN1ObjectIdentifier cmsDigestAlgOID, ASN1ObjectIdentifier sigAlgOID, SignatureResponse res, Collection<Certificate> previousSignerCerts, Collection<WrappedJarEntry> previousSigEntries) throws Exception {
        try (JarFile jar = new JarFile(responseData.toReadableData().getAsFile(), true)) {

            // Need each entry so that future calls to entry.getCodeSigners will return anything
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                LOG.debug("Reading " + entry);
                IOUtils.copy(jar.getInputStream(entry), NullOutputStream.NULL_OUTPUT_STREAM);
            }

            Collection<WrappedJarEntry> sfEntries = new ArrayList<>();
            Collection<WrappedJarEntry> cmsEntries = new ArrayList<>();

            // Now check each entry
            entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".SF")) {
                    sfEntries.add(new WrappedJarEntry(entry));
                } else if (entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".DSA")
                        || entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".EC")
                        || entry.getName().toUpperCase(Locale.ENGLISH).endsWith(".RSA")) {
                    cmsEntries.add(new WrappedJarEntry(entry));
                } else if (!entry.isDirectory()) {
                    // Check that there is a code signer
                    LOG.debug("Verifying " + entry);
                    assertNotNull("code signers for entry: " + entry, entry.getCodeSigners());
                    assertEquals("Number of signatures in entry: " + entry, previousSignerCerts.size() + 1, entry.getCodeSigners().length);

                    // Check certificate returned
                    final Certificate signercert = res.getSignerCertificate();
                    final X509Certificate configuredSignerCert = (X509Certificate) token.getCertificate(ICryptoTokenV4.PURPOSE_SIGN);
                    assertNotNull("Signer certificate", signercert);
                    assertEquals("same cert returned", signercert, configuredSignerCert);

                    // Check that the signer's certificate is included
                    Collection<Certificate> certs = getSignersCertificate(entry.getCodeSigners());

                    assertTrue("should contain the configured certificate: " + configuredSignerCert.getSubjectX500Principal() + " in " + certs, certs.contains(configuredSignerCert));
                    assertTrue("should contain the previous signer certificate(s): " + previousSignerCerts + " in " + certs, certs.containsAll(previousSignerCerts));

                    // Check the right digest is used for the entry (Except for the manifest)
                    if (!"META-INF/MANIFEST.MF".equals(entry.getName().toUpperCase(Locale.ENGLISH))) {
                        assertTrue(sfDigestAlg + "-Digest missing for entry " + entry,
                            entry.getAttributes().containsKey(new Attributes.Name(sfDigestAlg + "-Digest")));
                    }
                }
            }

            // Get the signature file
            byte[] sfData;
            Collection<WrappedJarEntry> newSFEntries = new LinkedList<>(sfEntries);
            newSFEntries.removeAll(previousSigEntries);
            assertEquals("expected 1 new .SF in " + newSFEntries, 1, newSFEntries.size());
            JarEntry sfEntry = newSFEntries.iterator().next();
            sfData = IOUtils.toByteArray(jar.getInputStream(sfEntry));

            // Parse the signature file and check the manifest digest
            final Manifest sf = new Manifest(new ByteArrayInputStream(sfData));
            final Attributes mainAttributes = sf.getMainAttributes();
            assertTrue("x-Digest-Manifest in " + mainAttributes.keySet(),
                    mainAttributes.containsKey(new Attributes.Name(sfDigestAlg + "-Digest-Manifest")));

            // Check the signature files
            final byte[] cmsData;
            Collection<JarEntry> newCMSEntries = new LinkedList<>(cmsEntries);
            newCMSEntries.removeAll(previousSigEntries);
            assertEquals("expected 1 new .RSA/.DSA/.EC in " + newCMSEntries, 1, newCMSEntries.size());
            cmsData = IOUtils.toByteArray(jar.getInputStream(newCMSEntries.iterator().next()));

            //System.out.println(ASN1Dump.dumpAsString(new ASN1InputStream(cmsData).readObject()));

            // SignedData with the content-to-be-signed filled in
            final CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(sfData), cmsData);

            // TODO: assertEquals("eContentType <TODO>", "1.3.6.1.4.1.311.2.1.4", signedData.getSignedContentTypeOID());

            final SignerInformation si = signedData.getSignerInfos().getSigners().iterator().next();

            // Check certificate returned
            final Certificate signercert = res.getSignerCertificate();
            final X509Certificate configuredSignerCert = (X509Certificate) token.getCertificate(ICryptoTokenV4.PURPOSE_SIGN);
            assertNotNull("Signer certificate", signercert);
            assertEquals("same cert returned", signercert, configuredSignerCert);

            // Verify using the signer's certificate (the configured one)
            assertTrue("Verification using signer certificate",
                    si.verify(new JcaSimpleSignerInfoVerifierBuilder().build(configuredSignerCert)));

            // Check that the signer's certificate is included
            Store certs = signedData.getCertificates();
            Collection matches = certs.getMatches(new JcaX509CertificateHolderSelector(configuredSignerCert));
            assertEquals("should match the configured certificate: " + matches, 1, matches.size());

            // Testing that the SID works
            Collection certCollection = certs.getMatches(si.getSID());
            assertTrue("Matched signer cert", si.getSID().match(new X509CertificateHolder(configuredSignerCert.getEncoded())));
            X509CertificateHolder certHolder = (X509CertificateHolder) certCollection.iterator().next();
            assertArrayEquals("same cert returned", certHolder.getEncoded(), configuredSignerCert.getEncoded());

            // Check the signature algorithm
            assertEquals("Digest algorithm", cmsDigestAlgOID.toString(), si.getDigestAlgorithmID().getAlgorithm().toString());
            assertEquals("Encryption algorithm", sigAlgOID.getId(), si.getEncryptionAlgOID());
        }
    }

    /** JarEntry wrapper implementing equals/hashCode using the name. */
    private static class WrappedJarEntry extends JarEntry {
        private final String name;

        public WrappedJarEntry(JarEntry je) {
            super(je);
            this.name = je.getName();
        }

        @Override
        public int hashCode() {
            int hash = 5;
            hash = 83 * hash + Objects.hashCode(this.name);
            return hash;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final WrappedJarEntry other = (WrappedJarEntry) obj;
            if (!Objects.equals(this.name, other.name)) {
                return false;
            }
            return true;
        }
    }

    /**
     * Constructs a file with longer entries and compares the digests with the
     * expected ones that jarsigner has calculated before.
     *
     * Expected digests are from running:
     * cp /tmp/unsigned.jar /tmp/signed-jarsigner.jar && jarsigner -keystore res/test/dss10/dss10_keystore.p12 -storepass foo123 /tmp/signed-jarsigner.jar code00003
     * and then checking the SHA-256-Digest entries in the META-INF/KEY_ALIA.SF file
     *
     * @throws Exception in case of error
     */
    @Test
    public void testSignLongPackageNames() throws Exception {
        LOG.info("testSignLongPackageNames");

        final TreeMap<String, String> expectedSfDigests = new TreeMap<>();

        // Given: Create a ZIP file with both short, long and longer entries
        byte[] data;
        try (
                ByteArrayOutputStream bout = new ByteArrayOutputStream();
                JarOutputStream out = new JarOutputStream(bout);
            ) {

            // Short.txt
            JarEntry shortEntry1 = new JarEntry("com/primekey/signserver/prototyping/a/Short.txt");
            expectedSfDigests.put(shortEntry1.getName(), "FGQiSxQK9knzlbeoU8+DAanbY9JoiM02SCRtab7Kwqs=");

            shortEntry1.setMethod(ZipEntry.DEFLATED);
            out.putNextEntry(shortEntry1);
            out.write("The content of Short.txt".getBytes(StandardCharsets.UTF_8));

            // Long.txt
            JarEntry longEntry2 = new JarEntry("com/primekey/signserver/prototyping/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/x/y/z/longproject/Long.txt");
            expectedSfDigests.put(longEntry2.getName(), "cAE69D/qQHprv6gcCWLci+m7h3dZUjVVYB7Ou/m82S4=");
            longEntry2.setMethod(ZipEntry.DEFLATED);
            out.putNextEntry(longEntry2);
            out.write("The content of Long.txt".getBytes(StandardCharsets.UTF_8));

            // Longer.txt
            JarEntry longEntry3 = new JarEntry("com/primekey/signserver/prototyping/a20/b20/c20/d20/e20/f20/g20/h20/i20/j20/k20/l20/m20/n20/o20/p20/q20/r20/s20/t20/u20/v20/x20/y20/z2/longproject/Longer.txt");
            expectedSfDigests.put(longEntry3.getName(), "waWfa8Zi53/SG3Sq6xCVUZxV6W9UMj5FNc/yQVWFkD4=");
            longEntry3.setMethod(ZipEntry.DEFLATED);
            out.putNextEntry(longEntry3);
            out.write("The content of Longer.txt".getBytes(StandardCharsets.UTF_8));

            out.close();
            data = bout.toByteArray();
        }

        // Remove comment to write out unsigned file:
        //FileUtils.writeByteArrayToFile(new File("/tmp/unsigned.jar"), data);

        // When: Sign the file and gather actual digests
        final TreeMap<String, String> actualSfDigests = new TreeMap<>();
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(data);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false)
            ) {

            SignatureResponse resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withDigestAlgorithm(JAVA_SHA_256)
                    .withSignatureAlgorithm("SHA256WithRSA")
                    .withKeepSignatures(true)
                    .create(),
                    null);

            assertSignedAndTimestamped(requestData, responseData, tokenRSA, JAVA_SHA_256, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.sha256WithRSAEncryption, resp);

            // Remove comment to write out signed file:
            //FileUtils.writeByteArrayToFile(new File("/tmp/signed.jar"), responseData.toReadableData().getAsByteArray());

            // Read signed file and gather the SF digests for the expected entries
            try (JarFile jar = new JarFile(responseData.toReadableData().getAsFile(), true)) {

                ZipEntry entry = jar.getEntry("META-INF/KEY_ALIA.SF");
                Manifest sf = new Manifest(jar.getInputStream(entry));

                Map<String, Attributes> sfEntries = sf.getEntries();
                for (String name : expectedSfDigests.keySet()) {
                    actualSfDigests.put(name, sfEntries.get(name).getValue("SHA-256-Digest"));
                }
            }
        }

        // Then:
        assertEquals("Comparing expected SHA-256-Digest entries in SF file",
                expectedSfDigests.toString(), actualSfDigests.toString());
    }

}
