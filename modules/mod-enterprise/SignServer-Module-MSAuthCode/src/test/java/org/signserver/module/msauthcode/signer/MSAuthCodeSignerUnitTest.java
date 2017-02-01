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
package org.signserver.module.msauthcode.signer;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import net.jsign.DigestAlgorithm;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcPeImageData;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import net.jsign.pe.PEFile;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.apache.poi.poifs.filesystem.DirectoryNode;
import org.apache.poi.poifs.filesystem.DocumentEntry;
import org.apache.poi.poifs.filesystem.DocumentInputStream;
import org.apache.poi.poifs.filesystem.Entry;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.selector.jcajce.JcaX509CertificateHolderSelector;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
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
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcECContentVerifierProviderBuilder;

/**
 * Unit tests for the AuthenticodeSigner class.
 * 
 * For system tests see AuthenticodeSignerTest instead.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class MSAuthCodeSignerUnitTest {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(MSAuthCodeSignerUnitTest.class);
    
    private static final ASN1ObjectIdentifier ID_SHA1WITHDSA = new ASN1ObjectIdentifier("1.2.840.10040.4.3");
    private static final ASN1ObjectIdentifier ID_SHA256WITHDSA = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.2");

    private static MockedCryptoToken tokenRSA;
    private static MockedCryptoToken tokenDSA;
    private static MockedCryptoToken tokenECDSA;
    private static File executableFile;
    private static File executableFileWithSignature;
    private static File msiFile;
    private static File msiFileWithSignature;
    private static File msiFileWithSignatureEx;
    private static File otherFile;
    
    private static final String PROGRAM_NAME = "SignServer-JUnit-Test-åäö";
    private static final String PROGRAM_URL = "http://www.signserver.org/junit/test.html";

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
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
                        .addExtension(new CertExt(X509Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairRSA.getPublic())))
                        .addExtension(new CertExt(X509Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                        .build()),

                    // CA
                    caCertificate
                };
        tokenRSA = new MockedCryptoToken(signerKeyPairRSA.getPrivate(), signerKeyPairRSA.getPublic(), certChainRSA[0], Arrays.asList(certChainRSA), "BC");
        
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
                        .addExtension(new CertExt(X509Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairDSA.getPublic())))
                        .addExtension(new CertExt(X509Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                        .build()),

                    // CA
                    caCertificate
                };
        tokenDSA = new MockedCryptoToken(signerKeyPairDSA.getPrivate(), signerKeyPairDSA.getPublic(), certChainDSA[0], Arrays.asList(certChainDSA), "BC");
        
        // Create signer key-pair (ECDSA) and issue certificate
        final KeyPair signerKeyPairECDSA = CryptoUtils.generateEcCurve("prime256v1");
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

        // Sample binaries to test with
        executableFile = new File(PathUtil.getAppHome(), "res/test/HelloPE.exe");
        if (!executableFile.exists()) {
            throw new Exception("Missing sample binary: " + executableFile);
        }
        executableFileWithSignature = new File(PathUtil.getAppHome(), "res/test/HelloPE-signed.exe");
        if (!executableFileWithSignature.exists()) {
            throw new Exception("Missing sample binary: " + executableFileWithSignature);
        }
        msiFile = new File(PathUtil.getAppHome(), "res/test/sample.msi");
        if (!msiFile.exists()) {
            throw new Exception("Missing sample MSI package: " + msiFile);
        }
        msiFileWithSignature = new File(PathUtil.getAppHome(), "res/test/sample-signed.msi");
        if (!msiFileWithSignature.exists()) {
            throw new Exception("Missing sample signed MSI package: " + msiFileWithSignature);
        }
        msiFileWithSignatureEx = new File(PathUtil.getAppHome(), "res/test/sample-signed-ex.msi");
        if (!msiFileWithSignatureEx.exists()) {
            throw new Exception("Missing sample signed MSI package: " + msiFileWithSignatureEx);
        }
        otherFile = new File(PathUtil.getAppHome(), "res/test/HelloJar.jar");
        if (!otherFile.exists()) {
            throw new Exception("Missing sample non-executable file: " + otherFile);
        }

        try ( // Fist check that test file does not already have a signature
                PEFile peOriginal = new PEFile(executableFile)) {
            if (!peOriginal.getSignatures().isEmpty()) {
                throw new Exception("Test expect the test file to not have any signatures");
            }
        }
    }

    /**
     * Tests that setting both TSA_URL and TSA_WORKER gives a fatal error.
     * @throws java.lang.Exception
     */
    @Test
    public void testInit_noTSAURLandWorker() throws Exception {
        LOG.info("testInit_noTSAURLandWorker");
        WorkerConfig config = createConfig();
        config.setProperty("TSA_URL", "https://example.com/tsa");
        config.setProperty("TSA_WORKER", "TimeStampSigner4");
        MSAuthCodeSigner instance = new MockedMSAuthCodeSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("TSA_URL") && actualErrors.contains("TSA_WORKER"));
    }
    
    /**
     * Tests that if TSA_USERNAME is given then TSA_PASSWORD must also be
     * specified, but empty password is fine.
     * @throws java.lang.Exception
     */
    @Test
    public void testInit_TSA_PASSWORD() throws Exception {
        LOG.info("testInit_TSA_PASSWORD");
        WorkerConfig config = createConfig();
        config.setProperty("TSA_URL", "https://example.com/tsa");
        config.setProperty("TSA_USERNAME", "user1");
        MSAuthCodeSigner instance = new MockedMSAuthCodeSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("TSA_PASSWORD"));
        
        config.setProperty("TSA_PASSWORD", "");
        instance = new MockedMSAuthCodeSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("expecting no fatalErrors: " + actualErrors, instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Tests that one can set a true/false value for
     * ALLOW_PROGRAM_NAME_OVERRIDE.
     * @throws java.lang.Exception
     */
    @Test
    public void testInit_programNameOverride() throws Exception {
        LOG.info("testInit_programNameOverride");
        WorkerConfig config = createConfig();
        config.setProperty("ALLOW_PROGRAM_NAME_OVERRIDE", "_incorrect_value_");
        MSAuthCodeSigner instance = new MockedMSAuthCodeSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("ALLOW_PROGRAM_NAME_OVERRIDE"));
        
        config.setProperty("ALLOW_PROGRAM_NAME_OVERRIDE", "true");
        instance = new MockedMSAuthCodeSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("expecting no fatalErrors: " + actualErrors, instance.getFatalErrors(null).isEmpty());
        
        config.setProperty("ALLOW_PROGRAM_NAME_OVERRIDE", "false");
        instance = new MockedMSAuthCodeSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("expecting no fatalErrors: " + actualErrors, instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Tests that one can set a true/false value for
     * ALLOW_PROGRAM_URL_OVERRIDE.
     * @throws java.lang.Exception
     */
    @Test
    public void testInit_programURLOverride() throws Exception {
        LOG.info("testInit_programURLOverride");
        WorkerConfig config = createConfig();
        config.setProperty("ALLOW_PROGRAM_URL_OVERRIDE", "_incorrect_value_");
        MSAuthCodeSigner instance = new MockedMSAuthCodeSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("ALLOW_PROGRAM_URL_OVERRIDE"));
        
        config.setProperty("ALLOW_PROGRAM_URL_OVERRIDE", "true");
        instance = new MockedMSAuthCodeSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("expecting no fatalErrors: " + actualErrors, instance.getFatalErrors(null).isEmpty());
        
        config.setProperty("ALLOW_PROGRAM_URL_OVERRIDE", "false");
        instance = new MockedMSAuthCodeSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("expecting no fatalErrors: " + actualErrors, instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Tests that setting an unknown digest algorithm name gives an error.
     * @throws Exception 
     */
    @Test
    public void testInit_incorrectDigestAlg() throws Exception {
        LOG.info("testInit_incorrectDigestAlg");
        WorkerConfig config = createConfig();
        config.setProperty("DIGESTALGORITHM", "_incorrect_value_");
        MSAuthCodeSigner instance = new MockedMSAuthCodeSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("DIGESTALGORITHM"));
    }

    /**
     * Test signing using an RSA key-pair.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_RSA() throws Exception {
        LOG.info("testNormalSigning_RSA");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertSignedAndNotTimestamped(tokenRSA, X509ObjectIdentifiers.id_SHA1, X509ObjectIdentifiers.id_SHA1, PKCSObjectIdentifiers.rsaEncryption, resp, pe);
        }
    }
    
    /**
     * Test signing when explicitly specified the SHA1WithRSA algorithm.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_SHA1WithRSA() throws Exception {
        LOG.info("testNormalSigning_SHA1WithRSA");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withSignatureAlgorithm("SHA1WithRSA")
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertSignedAndNotTimestamped(tokenRSA, X509ObjectIdentifiers.id_SHA1, X509ObjectIdentifiers.id_SHA1, PKCSObjectIdentifiers.rsaEncryption, resp, pe);
        }
    }
    
    /**
     * Test signing when specified the SHA256WithRSA algorithm.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_SHA256WithRSA() throws Exception {
        LOG.info("testNormalSigning_SHA256WithRSA");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withSignatureAlgorithm("SHA256WithRSA")
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertSignedAndNotTimestamped(tokenRSA, X509ObjectIdentifiers.id_SHA1, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.rsaEncryption, resp, pe);
        }
    }
    
    /**
     * Test signing using a DSA key-pair.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_DSA() throws Exception {
        LOG.info("testNormalSigning_DSA");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenDSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertSignedAndNotTimestamped(tokenDSA, X509ObjectIdentifiers.id_SHA1, X509ObjectIdentifiers.id_SHA1, ID_SHA1WITHDSA, resp, pe);
        }
    }
    
    /**
     * Test signing when explicitly specified the SHA-1 digest algorithm.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_digestSHA1() throws Exception {
        LOG.info("testNormalSigning_digestSHA1");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withDigestAlgorithm("SHA-1")
                    .withSignatureAlgorithm("SHA256WithRSA")
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertSignedAndNotTimestamped(tokenRSA, X509ObjectIdentifiers.id_SHA1, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.rsaEncryption, resp, pe);
        }
    }
    
    /**
     * Test signing when specified the SHA-256 digest algorithm.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_digestSHA256() throws Exception {
        LOG.info("testNormalSigning_digestSHA256");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withDigestAlgorithm("SHA-256")
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertSignedAndNotTimestamped(tokenRSA, CMSAlgorithm.SHA256, CMSAlgorithm.SHA1, PKCSObjectIdentifiers.rsaEncryption, resp, pe);
        } 
    }
    
    /**
     * Test signing when specified the SHA256WithDSA algorithm.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_SHA256WithDSA() throws Exception {
        LOG.info("testNormalSigning_SHA256WithDSA");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenDSA, new ConfigBuilder()
                    .withSignatureAlgorithm("SHA256WithDSA")
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertSignedAndNotTimestamped(tokenDSA, X509ObjectIdentifiers.id_SHA1, CMSAlgorithm.SHA256, ID_SHA256WITHDSA, resp, pe);
        }
    }
    
    /**
     * Test signing when explicitly specified the SHA1WithDSA algorithm.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_SHA1WithDSA() throws Exception {
        LOG.info("testNormalSigning_SHA1WithDSA");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenDSA, new ConfigBuilder()
                    .withSignatureAlgorithm("SHA1WithDSA")
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertSignedAndNotTimestamped(tokenDSA, X509ObjectIdentifiers.id_SHA1, X509ObjectIdentifiers.id_SHA1, ID_SHA1WITHDSA, resp, pe);
        }
    }

    /**
     * Test signing with a ECDSA key-pair.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_ECDSA() throws Exception {
        LOG.info("testNormalSigning_ECDSA");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenECDSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertSignedAndNotTimestamped(tokenECDSA, X509ObjectIdentifiers.id_SHA1, X509ObjectIdentifiers.id_SHA1, X9ObjectIdentifiers.ecdsa_with_SHA1, resp, pe);
        }
    }

    /**
     * Test signing when explicitly specified the SHA1WithECDSA algorithm.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_SHA1WithECDSA() throws Exception {
        LOG.info("testNormalSigning_SHA1WithECDSA");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenECDSA, new ConfigBuilder()
                    .withSignatureAlgorithm("SHA1WithECDSA")
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertSignedAndNotTimestamped(tokenECDSA, X509ObjectIdentifiers.id_SHA1, X509ObjectIdentifiers.id_SHA1, X9ObjectIdentifiers.ecdsa_with_SHA1, resp, pe);
        }
    }

    /**
     * Test signing when specified the SHA256WithECDSA algorithm.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_SHA256WithECDSA() throws Exception {
        LOG.info("testNormalSigning_SHA256WithECDSA");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenECDSA, new ConfigBuilder()
                    .withSignatureAlgorithm("SHA256WithECDSA")
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertSignedAndNotTimestamped(tokenECDSA, X509ObjectIdentifiers.id_SHA1, CMSAlgorithm.SHA256, X9ObjectIdentifiers.ecdsa_with_SHA256, resp, pe);
        }
    }
    
    /**
     * Tests that submitting an empty document gives an error.
     * @throws Exception 
     */
    @Test
    public void testIncorrectDocument_empty() throws Exception {
        LOG.info("testIncorrectDocument_empty");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(new byte[0]);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            fail("Expected IllegalRequestException");
        } catch (IllegalRequestException expected) { // NOPMD
            // OK
        }
    }

    /**
     * Tests that submitting a document with garbage gives an error.
     * @throws Exception 
     */
    @Test
    public void testIncorrectDocument_garbage() throws Exception {
        LOG.info("testIncorrectDocument_garbage");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData("anything-not-correct-123-".getBytes(StandardCharsets.US_ASCII));
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            fail("Expected IllegalRequestException");
        } catch (IllegalRequestException expected) { // NOPMD
            // OK
        }
    }

    /**
     * Test signing a document with the the DOS file-marker followed by
     * garbage gives an error.
     * @throws Exception 
     */
    @Test
    public void testIncorrectDocument_garbageMZ() throws Exception {
        LOG.info("testIncorrectDocument_garbageMZ");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData("MZ+not-correct-123-".getBytes(StandardCharsets.US_ASCII));
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            fail("Expected IllegalRequestException");
        } catch (IllegalRequestException expected) { // NOPMD
            // OK
        }
    }

// Jsign seems to have an issue with signing already signed binaries
// See https://github.com/ebourg/jsign/issues/11
// Until a solution for that is found we instead reject already signed documents
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
//            assertSignedAndTimestamped(tokenRSA, X509ObjectIdentifiers.id_SHA1, CMSAlgorithm.SHA1, PKCSObjectIdentifiers.rsaEncryption, resp, pe);
//        } finally {
//            if (pe != null) {
//                pe.close();
//            }
//            if (file != null) {
//                file.delete();
//            }
//        }
//    }
    
    /**
     * Tests that already signed files are rejected with an error.
     * @throws Exception 
     */
    @Test
    public void testSigningAlreadySigned() throws Exception {
        LOG.info("testSigningAlreadySigned");
        
        try ( // Fist check that test file already has a signature
                PEFile peOriginal = new PEFile(executableFileWithSignature)) {
            if (peOriginal.getSignatures().size() != 1) {
                throw new Exception("Test expect the test file already have one signature but was " + peOriginal.getSignatures().size());
            }
        }

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFileWithSignature);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            fail("Expected IllegalRequestException");
        } catch(IllegalRequestException expected) { // NOPMD
            // OK
        }
    }

    /**
     * Tests that by default there is no program name.
     * @throws Exception 
     */
    @Test
    public void testNoProgramName() throws Exception {
        LOG.info("testNoProgramName");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertNull(getProgramName(pe));
        }
    }
    
    /**
     * Tests that by default there is no program name for MSI files.
     * @throws Exception
     */
    @Test
    public void testNoProgramNameMSI() throws Exception {
        LOG.info("testNoProgramNameMSI");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsFile());
            assertNull(getProgramName(fs));
        }
    }
    
    /**
     * Use configured name as override is not allowed (and no requested).
     * @throws Exception 
     */
    @Test
    public void testProgramNameOverride_defaults() throws Exception {
        LOG.info("testProgramNameOverride_defaults");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertEquals(PROGRAM_NAME, getProgramName(pe));
        }
    }
    
    /**
     * Use configured name as override is not allowed (and no requested) for MSI.
     * @throws Exception 
     */
    @Test
    public void testProgramNameOverride_defaultsMSI() throws Exception {
        LOG.info("testProgramNameOverride_defaultsMSI");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsFile());
            assertEquals(PROGRAM_NAME, getProgramName(fs));
        }
    }
     
    /**
     * Use configured name as override is not allowed (and no requested).
     * @throws Exception 
     */
    @Test
    public void testProgramNameOverride_notAllowed() throws Exception {
        LOG.info("testProgramNameOverride_notAllowed");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramNameOverride(false)
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertEquals(PROGRAM_NAME, getProgramName(pe));
        }
    }
    
    /**
     * Use configured name as override is not allowed (and no requested) for MSI.
     * @throws Exception 
     */
    @Test
    public void testProgramNameOverride_notAllowedMSI() throws Exception {
        LOG.info("testProgramNameOverride_notAllowedMSI");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramNameOverride(false)
                    .create(), null, null, null);
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsFile());
            assertEquals(PROGRAM_NAME, getProgramName(fs));
        }
    }
    
    /**
     * Fail as override is not allowed but requested.
     * @throws Exception 
     */
    @Test
    public void testProgramNameOverride_notAllowedButRequested() throws Exception {
        LOG.info("testProgramNameOverride_notAllowedButRequested");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramNameOverride(false)
                    .create(), null, "Overridden name should not be used", null);
            fail("Should have failed with IllegalArgumentException");
        } catch (IllegalRequestException expected) { // NOPMD
            // OK
        }
    }
    
    /**
     * Fail as override is not allowed but requested for MSI.
     * @throws Exception 
     */
    @Test
    public void testProgramNameOverride_notAllowedButRequestedMSI() throws Exception {
        LOG.info("testProgramNameOverride_notAllowedButRequestedMSI");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramNameOverride(false)
                    .create(), null, "Overridden name should not be used", null);
            fail("Should have failed with IllegalArgumentException");
        } catch (IllegalRequestException expected) { // NOPMD
            // OK
        }
    }
    
    /**
     * Overriding is allowed but not used.
     * @throws Exception 
     */
    @Test
    public void testProgramNameOverride_allowedNotRequested() throws Exception {
        LOG.info("testProgramNameOverride_allowedNotRequested");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramNameOverride(true)
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertEquals(PROGRAM_NAME, getProgramName(pe));
        }
    }
    
    /**
     * Overriding is allowed but not used for MSI.
     * @throws Exception 
     */
    @Test
    public void testProgramNameOverride_allowedNotRequestedMSI() throws Exception {
        LOG.info("testProgramNameOverride_allowedNotRequestedMSI");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramNameOverride(true)
                    .create(), null, null, null);
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsFile());
            assertEquals(PROGRAM_NAME, getProgramName(fs));
        }
    }
    
    /**
     * Tests overriding with new name.
     * @throws Exception 
     */
    @Test
    public void testProgramNameOverride_newName() throws Exception {
        LOG.info("testProgramNameOverride_newName");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            final String reqName = "Overridden name ok";
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramNameOverride(true)
                    .create(), null, reqName, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertEquals(reqName, getProgramName(pe));
        }
    }
    
    /**
     * Tests overriding with new name for MSI. 
     * @throws Exception 
     */
    @Test
    public void testProgramNameOverride_newNameMSI() throws Exception {
        LOG.info("testProgramNameOverride_newNameMSI");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            final String reqName = "Overridden name ok";
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramNameOverride(true)
                    .create(), null, reqName, null);
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsFile());
            assertEquals(reqName, getProgramName(fs));
        }
    }
    
    /**
     * Tests overriding by removing name.
     * @throws Exception 
     */
    @Test
    public void testProgramNameOverride_removeName() throws Exception {
        LOG.info("testProgramNameOverride_removeName");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramNameOverride(true)
                    .create(), null, "", null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertNull(getProgramName(pe));
        }
    }
    
    /**
     * Tests overriding by removing name for MSI.
     * @throws Exception 
     */
    @Test
    public void testProgramNameOverride_removeNameMSI() throws Exception {
        LOG.info("testProgramNameOverride_removeNameMSI");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramNameOverride(true)
                    .create(), null, "", null);
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsFile());
            assertNull(getProgramName(fs));
        }
    }

    /**
     * Tests overriding by adding name.
     * @throws Exception 
     */
    @Test
    public void testProgramNameOverride_newNameNoDefault() throws Exception {
        LOG.info("testProgramNameOverride_newNameNoDefault");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            final String reqName = "Overridden name ok";
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramNameOverride(true)
                    .create(), null, reqName, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertEquals(reqName, getProgramName(pe));
        }
    }
    
    /**
     * Tests overriding by adding name for MSI.
     * @throws Exception 
     */
    @Test
    public void testProgramNameOverride_newNameNoDefaultMSI() throws Exception {
        LOG.info("testProgramNameOverride_newNameNoDefaultMSI");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            final String reqName = "Overridden name ok";
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramNameOverride(true)
                    .create(), null, reqName, null);
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsFile());
            assertEquals(reqName, getProgramName(fs));
        }
    }

    /**
     * Tests that by default there is no program URL.
     * @throws Exception 
     */
    @Test
    public void testNoProgramURL() throws Exception {
        LOG.info("testNoProgramURL");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertNull(getProgramURL(pe));
        }
    }
    
    /**
     * Tests that by default there is no program URL for MSI.
     * @throws Exception 
     */
    @Test
    public void testNoProgramURLMSI() throws Exception {
        LOG.info("testNoProgramURLMSI");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .create(), null, null, null);
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsFile());
            assertNull(getProgramURL(fs));
        }
    }
    
    /**
     * Use configured name as override is not allowed (and no requested).
     * @throws Exception 
     */
    @Test
    public void testProgramURLOverride_defaults() throws Exception {
        LOG.info("testProgramUROverride_defaults");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertEquals(PROGRAM_URL, getProgramURL(pe));
        }
    }
    
    /**
     * Use configured name as override is not allowed (and no requested) for MSI.
     * @throws Exception 
     */
    @Test
    public void testProgramURLOverride_defaultsMSI() throws Exception {
        LOG.info("testProgramUROverride_defaultsMSI");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsFile());
            assertEquals(PROGRAM_URL, getProgramURL(fs));
        }
    }
     
    /**
     * Use configured name as override is not allowed (and no requested).
     * @throws Exception 
     */
    @Test
    public void testProgramURLOverride_notAllowed() throws Exception {
        LOG.info("testProgramURLOverride_notAllowed");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramURLOverride(false)
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertEquals(PROGRAM_URL, getProgramURL(pe));
        }
    }
    
    /**
     * Use configured name as override is not allowed (and no requested) for MSI.
     * @throws Exception 
     */
    @Test
    public void testProgramURLOverride_notAllowedMSI() throws Exception {
        LOG.info("testProgramURLOverride_notAllowedMSI");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramURLOverride(false)
                    .create(), null, null, null);
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsFile());
            assertEquals(PROGRAM_URL, getProgramURL(fs));
        }
    }
    
    /**
     * Fail as override is not allowed but requested.
     * @throws Exception 
     */
    @Test
    public void testProgramURLOverride_notAllowedButRequested() throws Exception {
        LOG.info("testProgramURLOverride_notAllowedButRequested");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramURLOverride(false)
                    .create(), null, null, "http://example.com/should-not-be-used");
            fail("Should have failed with IllegalArgumentException");
        } catch (IllegalRequestException expected) { // NOPMD
            // OK
        }
    }
    
    /**
     * Fail as override is not allowed but requested for MSI.
     * @throws Exception 
     */
    @Test
    public void testProgramURLOverride_notAllowedButRequestedMSI() throws Exception {
        LOG.info("testProgramURLOverride_notAllowedButRequestedMSI");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramURLOverride(false)
                    .create(), null, null, "http://example.com/should-not-be-used");
            fail("Should have failed with IllegalArgumentException");
        } catch (IllegalRequestException expected) { // NOPMD
            // OK
        }
    }
    
    /**
     * Overriding is allowed but not used.
     * @throws Exception 
     */
    @Test
    public void testProgramURLOverride_allowedNotRequested() throws Exception {
        LOG.info("testProgramURLOverride_allowedNotRequested");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramURLOverride(true)
                    .create(), null, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertEquals(PROGRAM_URL, getProgramURL(pe));
        }
    }
    
    /**
     * Overriding is allowed but not used for MSI.
     * @throws Exception 
     */
    @Test
    public void testProgramURLOverride_allowedNotRequestedMSI() throws Exception {
        LOG.info("testProgramURLOverride_allowedNotRequestedMSI");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramURLOverride(true)
                    .create(), null, null, null);
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsFile());
            assertEquals(PROGRAM_URL, getProgramURL(fs));
        }
    }
    
    /**
     * Tests overriding the URL with a new one.
     * @throws Exception 
     */
    @Test
    public void testProgramURLOverride_newName() throws Exception {
        LOG.info("testProgramURLOverride_newName");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            final String reqName = "https://example.com/Overridden-name-ok";
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramURLOverride(true)
                    .create(), null, null, reqName);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertEquals(reqName, getProgramURL(pe));
        }
    }
    
    /**
     * Tests overriding the URL with a new one for MSI.
     * @throws Exception 
     */
    @Test
    public void testProgramURLOverride_newNameMSI() throws Exception {
        LOG.info("testProgramURLOverride_newNameMSI");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            final String reqName = "https://example.com/Overridden-name-ok";
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramURLOverride(true)
                    .create(), null, null, reqName);
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsFile());
            assertEquals(reqName, getProgramURL(fs));
        }
    }

    /**
     * Tests overriding URL by removing it.
     * @throws Exception 
     */
    @Test
    public void testProgramURLOverride_removeName() throws Exception {
        LOG.info("testProgramURLOverride_removeName");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramURLOverride(true)
                    .create(), null, null, "");
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertNull(getProgramURL(pe));
        }
    }
    
    /**
     * Tests overriding URL by removing it for MSI.
     * @throws Exception 
     */
    @Test
    public void testProgramURLOverride_removeNameMSI() throws Exception {
        LOG.info("testProgramURLOverride_removeNameMSI");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .withAllowProgramURLOverride(true)
                    .create(), null, null, "");
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsFile());
            assertNull(getProgramURL(fs));
        }
    }

    /**
     * Tests overriding URL by adding one.
     * @throws Exception 
     */
    @Test
    public void testProgramURLOverride_newNameNoDefault() throws Exception {
        LOG.info("testProgramURLOverride_newNameNoDefault");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            final String reqName = "https://example.com/Overridden-name-ok";
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withAllowProgramURLOverride(true)
                    .create(), null, null, reqName);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
            assertEquals(reqName, getProgramURL(pe));
        }
    }
    
    /**
     * Tests overriding URL by adding one for MSI.
     * @throws Exception 
     */
    @Test
    public void testProgramURLOverride_newNameNoDefaultMSI() throws Exception {
        LOG.info("testProgramURLOverride_newNameNoDefaultMSI");   
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            final String reqName = "https://example.com/Overridden-name-ok";
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withAllowProgramURLOverride(true)
                    .create(), null, null, reqName);
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsFile());
            assertEquals(reqName, getProgramURL(fs));
        }
    }
    
    /**
     * Test that explicitly setting timestamp format to AUTHENTICODE works.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_timestampFormatAuthenticode() throws Exception {
        LOG.info("testInit_incorrectDigestAlg");
        WorkerConfig config = createConfig();
        config.setProperty("TIMESTAMP_FORMAT", "AUTHENTICODE");
        MSAuthCodeSigner instance = new MockedMSAuthCodeSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        assertTrue("no fatal errors", instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Test that setting timestamp format to RFC3161 works.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_timestampFormatRFC3161() throws Exception {
        LOG.info("testInit_incorrectDigestAlg");
        WorkerConfig config = createConfig();
        config.setProperty("TIMESTAMP_FORMAT", "RFC3161");
        MSAuthCodeSigner instance = new MockedMSAuthCodeSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        assertTrue("no fatal errors", instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Test that setting timestamp format to rfc3161 (using lower case works).
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_timestampFormatRFC3161LowerCase() throws Exception {
        LOG.info("testInit_incorrectDigestAlg");
        WorkerConfig config = createConfig();
        config.setProperty("TIMESTAMP_FORMAT", "rfc3161");
        MSAuthCodeSigner instance = new MockedMSAuthCodeSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        assertTrue("no fatal errors", instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Test that setting an unknown timestamp format results in a fatal error.
     *
     * @throws Exception 
     */
    @Test
    public void testInit_timestampFormatInvalid() throws Exception {
        LOG.info("testInit_timestampFormatInvalid");
        WorkerConfig config = createConfig();
        config.setProperty("TIMESTAMP_FORMAT", "_invalid_");
        MSAuthCodeSigner instance = new MockedMSAuthCodeSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("should contain fatal error: " + actualErrors,
                   actualErrors.contains("Illegal value for TIMESTAMP_FORMAT: _invalid_"));
    }
    
    /**
     * Test that setting timestamp format to an empty value works.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_timestampFormatEmpty() throws Exception {
        LOG.info("testInit_incorrectDigestAlg");
        WorkerConfig config = createConfig();
        config.setProperty("TIMESTAMP_FORMAT", "");
        MSAuthCodeSigner instance = new MockedMSAuthCodeSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        assertTrue("no fatal errors", instance.getFatalErrors(null).isEmpty());
    }
    
    private void assertRequestDigestMatches(File file, String digestAlgorithm, RequestContext context) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, UnsupportedEncodingException, IOException {
        final LogMap logMap = LogMap.getInstance(context);
        final Object digestAlgLoggable = logMap.get("REQUEST_DIGEST_ALGORITHM");
        assertEquals("digestAlg", digestAlgorithm, String.valueOf(digestAlgLoggable));
        
        final byte[] data = FileUtils.readFileToByteArray(file);
        
        final MessageDigest md = MessageDigest.getInstance(digestAlgorithm);
        final String expected = Hex.toHexString(md.digest(data));
        final Object digestLoggable = logMap.get("REQUEST_DIGEST");
        final String actual = String.valueOf(digestLoggable);
        assertEquals("digest", expected, actual);
    }
    
    private void assertResponseDigestMatches(byte[] data, String digestAlgorithm, RequestContext context) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, UnsupportedEncodingException, IOException {
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
     * @throws Exception 
     */
    @Test
    public void testLogRequestDigestDefault() throws Exception {
        LOG.info("testLogRequestDigestDefault");
        final RequestContext context = new RequestContext();
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            final SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .create(), context, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
        }
        assertRequestDigestMatches(executableFile, "SHA256", context);
    }
    
    /**
     * Tests logging of the request digest and request digest algorithm using
     * SHA1.
     * @throws Exception 
     */
    @Test
    public void testLogRequestDigestSHA1() throws Exception {
        LOG.info("testLogRequestDigestSHA1");
        final RequestContext context = new RequestContext();
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            final SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withLogRequestDigest("SHA1")
                    .create(), context, null, null);
            PEFile pe = new PEFile(responseData.toReadableData().getAsFile());
        }
        assertRequestDigestMatches(executableFile, "SHA1", context);
    }
    
    /**
     * Tests logging of the response digest and response digest algorithm using
     * the default algorithm.
     * @throws Exception 
     */
    @Test
    public void testLogResponseDigestDefault() throws Exception {
        LOG.info("testLogResponseDigestDefault");
        final RequestContext context = new RequestContext();
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            final SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .create(), context, null, null);
            assertResponseDigestMatches(responseData.toReadableData().getAsByteArray(), "SHA256", context);
        }
    }
    
    /**
     * Tests logging of the response digest and response digest algorithm using
     * SHA1.
     * @throws Exception 
     */
    @Test
    public void testLogResponseDigestSHA1() throws Exception {
        LOG.info("testLogResponsetDigestSHA1");
        final RequestContext context = new RequestContext();
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            final SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withLogResponseDigest("SHA1")
                    .create(), context, null, null);
            assertResponseDigestMatches(responseData.toReadableData().getAsByteArray(), "SHA1", context);
        }
    }
    
    /**
     * Tests no request digest is logged if it is disabled.
     * @throws Exception 
     */
    @Test
    public void testLogNoRequestDigest() throws Exception {
        LOG.info("testLogNoRequestDigest");
        final RequestContext context = new RequestContext();
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withDoLogRequestDigest(false)
                    .create(), context, null, null);
            assertNull("logRequest", LogMap.getInstance(context).get(IWorkerLogger.LOG_REQUEST_DIGEST));
            assertNull("logRequestAlg", LogMap.getInstance(context).get(IWorkerLogger.LOG_REQUEST_DIGEST_ALGORITHM));
        }
    }
    
    /**
     * Tests no response digest is logged if it is disabled.
     * @throws Exception 
     */
    @Test
    public void testLogNoResponseDigest() throws Exception {
        LOG.info("testLogNoResponseDigest");
        final RequestContext context = new RequestContext();
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(executableFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withDoLogResponseDigest(false)
                    .create(), context, null, null);
            assertNull("logResponse", LogMap.getInstance(context).get(IWorkerLogger.LOG_RESPONSE_DIGEST));
            assertNull("logResponseAlg", LogMap.getInstance(context).get(IWorkerLogger.LOG_RESPONSE_DIGEST_ALGORITHM));
        }
    }
    
    /**
     * Test that trying to sign a non-PE or MSI files fails as expected.
     * 
     * @throws Exception 
     */
    @Test
    public void testOtherFileNotAccepted() throws Exception {
       LOG.info("testOtherFileAccepted");
       final RequestContext context = new RequestContext();
       try (
           CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(otherFile);
           CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
       ) {
           sign(requestData, responseData, tokenRSA, new ConfigBuilder().create(),
                context, null, null);
           fail("Should cause an IllegalRequestExcetion");
       } catch (IllegalRequestException ex) {
           // Expected
       }
    }
    
    /**
     * Test signing using an RSA key-pair.
     * @throws Exception 
     */
    @Test
    public void testNormalSigningMSI_RSA() throws Exception {
        LOG.info("testNormalSigningMSI_RSA");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            FileUtils.writeByteArrayToFile(new File("/tmp/test-signed.msi"), responseData.toReadableData().getAsByteArray());
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsInputStream());
            assertSignedAndNotTimestampedMSI(tokenRSA, "SHA1", X509ObjectIdentifiers.id_SHA1, X509ObjectIdentifiers.id_SHA1, PKCSObjectIdentifiers.rsaEncryption, resp, fs);
        }
    }
    
    /**
     * Test signing using a DSA key-pair.
     * @throws Exception 
     */
    @Test
    public void testNormalSigningMSI_DSA() throws Exception {
        LOG.info("testNormalSigningMSI_DSA");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenDSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            FileUtils.writeByteArrayToFile(new File("/tmp/test-signed.msi"), responseData.toReadableData().getAsByteArray());
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsInputStream());
            assertSignedAndNotTimestampedMSI(tokenDSA, "SHA1", X509ObjectIdentifiers.id_SHA1, X509ObjectIdentifiers.id_SHA1, ID_SHA1WITHDSA, resp, fs);
        }
    }
    
    /**
     * Test signing using a ECDSA key-pair.
     * @throws Exception 
     */
    @Test
    public void testNormalSigningMSI_ECDSA() throws Exception {
        LOG.info("testNormalSigningMSI_ECDSA");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenECDSA, new ConfigBuilder()
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            FileUtils.writeByteArrayToFile(new File("/tmp/test-signed.msi"), responseData.toReadableData().getAsByteArray());
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsInputStream());
            assertSignedAndNotTimestampedMSI(tokenECDSA, "SHA1", X509ObjectIdentifiers.id_SHA1, X509ObjectIdentifiers.id_SHA1, X9ObjectIdentifiers.ecdsa_with_SHA1, resp, fs);
        }
    }
    
    /**
     * Test signing using an RSA key-pair, using SHA-256 digest algo.
     * @throws Exception 
     */
    @Test
    public void testNormalSigningMSI_digestSHA256() throws Exception {
        LOG.info("testNormalSigningMSI_digestSHA256");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withDigestAlgorithm("SHA-256")
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            FileUtils.writeByteArrayToFile(new File("/tmp/test-signed.msi"), responseData.toReadableData().getAsByteArray());
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsInputStream());
            assertSignedAndNotTimestampedMSI(tokenRSA, "SHA256", CMSAlgorithm.SHA256, X509ObjectIdentifiers.id_SHA1, PKCSObjectIdentifiers.rsaEncryption, resp, fs);
        }
    }
    
    /**
     * Test signing using an RSA key-pair using SHA256withRSA signature algo.
     * @throws Exception 
     */
    @Test
    public void testNormalSigningMSI_SHA256withRSA() throws Exception {
        LOG.info("testNormalSigningMSI_SHA256withRSA");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withSignatureAlgorithm("SHA256withRSA")
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            FileUtils.writeByteArrayToFile(new File("/tmp/test-signed.msi"), responseData.toReadableData().getAsByteArray());
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsInputStream());
            assertSignedAndNotTimestampedMSI(tokenRSA, "SHA1", X509ObjectIdentifiers.id_SHA1, CMSAlgorithm.SHA256, PKCSObjectIdentifiers.rsaEncryption, resp, fs);
        }
    }
    
    /**
     * Test signing using an DSA key-pair using SHA256withDSA signature algo.
     * @throws Exception 
     */
    @Test
    public void testNormalSigningMSI_SHA256withDSA() throws Exception {
        LOG.info("testNormalSigningMSI_SHA256withDSA");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenDSA, new ConfigBuilder()
                    .withSignatureAlgorithm("SHA256withDSA")
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            FileUtils.writeByteArrayToFile(new File("/tmp/test-signed.msi"), responseData.toReadableData().getAsByteArray());
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsInputStream());
            assertSignedAndNotTimestampedMSI(tokenDSA, "SHA1", X509ObjectIdentifiers.id_SHA1, CMSAlgorithm.SHA256, ID_SHA256WITHDSA, resp, fs);
        }
    }
    
    /**
     * Test signing using an DSA key-pair using SHA256withECDSA signature algo.
     * @throws Exception 
     */
    @Test
    public void testNormalSigningMSI_SHA256withECDSA() throws Exception {
        LOG.info("testNormalSigningMSI_SHA256withECDSA");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenECDSA, new ConfigBuilder()
                    .withSignatureAlgorithm("SHA256withECDSA")
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            FileUtils.writeByteArrayToFile(new File("/tmp/test-signed.msi"), responseData.toReadableData().getAsByteArray());
            POIFSFileSystem fs = new POIFSFileSystem(responseData.toReadableData().getAsInputStream());
            assertSignedAndNotTimestampedMSI(tokenECDSA, "SHA1", X509ObjectIdentifiers.id_SHA1, CMSAlgorithm.SHA256, X9ObjectIdentifiers.ecdsa_with_SHA256, resp, fs);
        }
    }
    
    /** Test signing an already signed file.
     *  Should fail with an IllegalRequestException.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignAlreadySignedMSI() throws Exception {
        LOG.info("testSignAlreadySignedMSI");
        
        POIFSFileSystem in = new POIFSFileSystem(msiFileWithSignature);
        
        if (!in.getRoot().hasEntry("\05DigitalSignature") ||
            !in.getRoot().getEntry("\05DigitalSignature").isDocumentEntry()) {
            throw new Exception("Expected test file with one DigitalSignature entry");
        }

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFileWithSignature);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenECDSA, new ConfigBuilder()
                    .withSignatureAlgorithm("SHA256withECDSA")
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            fail("Expected IllegalRequestException");
        } catch (IllegalRequestException ex) {
            // Expected
        }
    }
    
    /**
     * Test signing a file wich has a signature in an MsiDigitalSignatureEx
     * entry.
     * Should fail with an IllegalRequestException.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignAlreadySignedExMSI() throws Exception {
        LOG.info("testSignAlreadySignedExMSI");
        
        POIFSFileSystem in = new POIFSFileSystem(msiFileWithSignatureEx);
        
        if ((!in.getRoot().hasEntry("\05MsiDigitalSignatureEx") ||
             !in.getRoot().getEntry("\05MsiDigitalSignatureEx").isDocumentEntry()) ||
            in.getRoot().hasEntry("\05DigitalSignature")) {
            throw new Exception("Expected test file with one MsiDigitalSignatureEx entry and no DigitalSignature entry");
        }

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(msiFileWithSignatureEx);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            ) {
            SignatureResponse resp = sign(requestData, responseData, tokenECDSA, new ConfigBuilder()
                    .withSignatureAlgorithm("SHA256withECDSA")
                    .withProgramName("SignServer-JUnit-Test-åäö")
                    .withProgramURL("http://www.signserver.org/junit/test.html")
                    .create(), null, null, null);
            fail("Expected IllegalRequestException");
        } catch (IllegalRequestException ex) {
            // Expected
        }
    }

    private static WorkerConfig createConfig() {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty(WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        return config;
    }

    /** Builder for configuration. */
    private static class ConfigBuilder {
        private final WorkerConfig config = createConfig();
        
        
        public ConfigBuilder withSignatureAlgorithm(String signatureAlgorithm) {
            config.setProperty("SIGNATUREALGORITHM", signatureAlgorithm);
            return this;
        }
        
        public ConfigBuilder withDigestAlgorithm(String digestAlgorithm) {
            config.setProperty("DIGESTALGORITHM", digestAlgorithm);
            return this;
        }
        
        public ConfigBuilder withProgramName(String programName) {
            config.setProperty("PROGRAM_NAME", programName);
            return this;
        }
        
        public ConfigBuilder withProgramURL(String programURL) {
            config.setProperty("PROGRAM_URL", programURL);
            return this;
        }
        
        public ConfigBuilder withAllowProgramNameOverride(Boolean allowProgramNameOverride) {
            if (allowProgramNameOverride != null) {
                config.setProperty("ALLOW_PROGRAM_NAME_OVERRIDE", String.valueOf(allowProgramNameOverride));
            }
            return this;
        }
        
        public ConfigBuilder withAllowProgramURLOverride(Boolean allowProgramURLOverride) {
            if (allowProgramURLOverride != null) {
                config.setProperty("ALLOW_PROGRAM_URL_OVERRIDE", String.valueOf(allowProgramURLOverride));
            }
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
        
        public ConfigBuilder withTimestampFormat(String timestampFormat) {
            config.setProperty("TIMESTAMP_FORMAT", timestampFormat);
            return this;
        }
        
        public WorkerConfig create() {
            return config;
        }
    }
   
    // TODO: remove
    private SignatureResponse sign(ReadableData requestData, WritableData responseData, MockedCryptoToken token, WorkerConfig config, RequestContext requestContext, String reqProgramName, String reqProgramURL) throws Exception {
        
        return signData(requestData, responseData, token, config, requestContext, reqProgramName, reqProgramURL);
    }
    
    private SignatureResponse signData(ReadableData requestData, WritableData responseData, MockedCryptoToken token, WorkerConfig config, RequestContext requestContext, String reqProgramName, String reqProgramURL) throws Exception {
        MockedMSAuthCodeSigner instance = new MockedMSAuthCodeSigner(token);
        instance.init(1, config, new SignServerContext(), null);

        if (requestContext == null) {
            requestContext = new RequestContext();
        }
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");

        if (reqProgramName != null) {
            RequestMetadata.getInstance(requestContext).put("PROGRAM_NAME", reqProgramName);
        }
        if (reqProgramURL != null) {
            RequestMetadata.getInstance(requestContext).put("PROGRAM_URL", reqProgramURL);
        }

        SignatureRequest request = new SignatureRequest(100, requestData, responseData);
        SignatureResponse res = (SignatureResponse) instance.processData(request, requestContext);
        
        return res;
    }
    
    private void assertSignedAndNotTimestampedMSI(MockedCryptoToken token,
                                               String digestAlgString,
                                               ASN1ObjectIdentifier digestAlgOID,
                                               ASN1ObjectIdentifier cmsDigestAlgOID,
                                               ASN1ObjectIdentifier sigAlgOID,
                                               SignatureResponse resp,
                                               POIFSFileSystem fs)
            throws Exception {
        // TODO: check timestamp
        final DirectoryNode root = fs.getRoot();

        assertTrue("Digital signature entry", root.hasEntry("\05DigitalSignature"));
        
        final Entry entry = fs.getRoot().getEntry("\05DigitalSignature");

        assertTrue("Document entry", entry.isDocumentEntry());

        try (
            final DocumentInputStream dis =
                fs.createDocumentInputStream("\05DigitalSignature")) {
            final byte[] buf = new byte[dis.available()];

            dis.read(buf);
            dis.close();

            final CMSSignedData cms = new CMSSignedData(buf);

            final MessageDigest md = MessageDigest.getInstance(digestAlgString);

            MSIUtils.traverseDirectory(fs, root, md);

            LOG.info("Version: " + cms.getVersion());
            LOG.info("Detached: " + cms.isDetachedSignature());

            Store certStore = cms.getCertificates(); 
            SignerInformationStore signers = cms.getSignerInfos(); 
            Collection c = signers.getSigners(); 
            Iterator it = c.iterator(); 
            while (it.hasNext()) { 
                SignerInformation signer = (SignerInformation) it.next(); 

                // Check the signature algorithm
                assertEquals("Digest algorithm", cmsDigestAlgOID.toString(),
                             signer.getDigestAlgorithmID().getAlgorithm().toString());
                assertEquals("Encryption algorithm", sigAlgOID.getId(),
                             signer.getEncryptionAlgOID());

                Collection certCollection = certStore.getMatches(signer.getSID()); 
                Iterator certIt = certCollection.iterator(); 
                X509CertificateHolder cert = (X509CertificateHolder) certIt.next();

                ContentVerifierProvider cvp = null;
                final String encryptionAlg =
                    token.getPrivateKey(ICryptoTokenV4.PURPOSE_SIGN).getAlgorithm();    
                
                switch (encryptionAlg) {
                    case "RSA":
                        cvp = new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(cert);
                        break;
                    case "DSA":
                        cvp = new BcDSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(cert);
                        break;
                    case "ECDSA":
                        cvp = new BcECContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(cert);
                        break;
                    default:
                        fail("Unknown encryption algorithm: " + encryptionAlg);
                }
                
                final boolean result =
                        signer.verify(new SignerInformationVerifier(
                                            new DefaultCMSSignatureAlgorithmNameGenerator(),
                                            new DefaultSignatureAlgorithmIdentifierFinder(),
                                            cvp,
                                            new BcDigestCalculatorProvider()));
                assertTrue("Verified", result);

                // assert not timestamped
                assertTrue("No counter signature",
                           signer.getCounterSignatures().getSigners().isEmpty());
            }

            CMSTypedData signedContent = cms.getSignedContent();
            assertEquals("Content-type", AuthenticodeObjectIdentifiers.SPC_INDIRECT_DATA_OBJID,
                         signedContent.getContentType());

            ASN1Sequence seq = (ASN1Sequence) signedContent.getContent();

            SpcIndirectDataContent idc = SpcIndirectDataContent.getInstance(seq);
            assertEquals("Message digest algorithm", digestAlgOID,
                         idc.messageDigest.getAlgorithmId().getAlgorithm());

            byte[] expectedDigest = idc.messageDigest.getDigest();

            SpcSipInfo sipInfo = SpcSipInfo.getInstance((ASN1Sequence) idc.data.value);
            assertNotNull("SpcSipInfo present", sipInfo);

            byte[] actualDigest = md.digest();

            assertTrue("Digest matches", Arrays.equals(expectedDigest, actualDigest));

            // Check certificate returned
            final Certificate signercert = resp.getSignerCertificate();
            final X509Certificate configuredSignerCert = (X509Certificate) token.getCertificate(ICryptoTokenV4.PURPOSE_SIGN);
            assertNotNull("Signer certificate", signercert);
            assertEquals("same cert returned", signercert, configuredSignerCert);

            // Check that the signer's certificate is included
            Store certs = cms.getCertificates();
            Collection matches = certs.getMatches(new JcaX509CertificateHolderSelector(configuredSignerCert));
            assertEquals("should match the configured certificate: " + matches, 1, matches.size());
        }
    }
    
    private void assertSignedAndNotTimestamped(MockedCryptoToken token, ASN1ObjectIdentifier peDigestAlg, ASN1ObjectIdentifier cmsDigestAlgOID, ASN1ObjectIdentifier sigAlgOID, SignatureResponse res, PEFile pe) throws Exception {
        List<CMSSignedData> signatures = pe.getSignatures();
        assertEquals("Number of signatures", 1, signatures.size());

        // Reconstruct the data "to be signed"
        DigestAlgorithm digestAlg = DigestAlgorithm.of(peDigestAlg);
        byte[] digest = pe.computeDigest(digestAlg);
        ASN1ObjectIdentifier digestAlgOID =
                new ASN1ObjectIdentifier(peDigestAlg.getId());
        DERNull derNull = DERNull.INSTANCE;
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgOID, derNull);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, digest);
        
        SpcAttributeTypeAndOptionalValue sataov =
                new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_PE_IMAGE_DATA_OBJID,
                                                     new SpcPeImageData());
        net.jsign.asn1.authenticode.SpcIndirectDataContent spcIndirectDataContent =
                new net.jsign.asn1.authenticode.SpcIndirectDataContent(sataov, digestInfo);
        final byte[] idcBytes = spcIndirectDataContent.toASN1Primitive().getEncoded("DER");
        
        final byte[] content = new byte[idcBytes.length - 2];
        System.arraycopy(idcBytes, 2, content, 0, idcBytes.length - 2);

        // SignedData with the content-to-be-signed filled in
        final CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(content), signatures.get(0).getEncoded());

        assertEquals("eContentType SpcIndirectDataContent", "1.3.6.1.4.1.311.2.1.4", signedData.getSignedContentTypeOID());

        final SignerInformation si = (SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();

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

        // Check that there is no timestamp
        assertTrue("counterSignature", si.getCounterSignatures().getSigners().isEmpty());
    }
    
    private String getProgramName(final CMSSignedData signedData) {
        SignerInformation si = signedData.getSignerInfos().getSigners().iterator().next();

        Attribute attr = si.getSignedAttributes().get(AuthenticodeObjectIdentifiers.SPC_SP_OPUS_INFO_OBJID);
        ASN1Sequence seq =
                (ASN1Sequence) attr.getAttrValues().getObjectAt(0);

        // Check program name
        DERTaggedObject programNameObject = (DERTaggedObject) seq.getObjectAt(0);
        
        String actualProgramName = null;
        if (programNameObject.getTagNo() == 0) {
            if (((ASN1TaggedObject)programNameObject.getObject()).getTagNo() == 0) {
                // unicode
                actualProgramName = DERBMPString.getInstance((DERTaggedObject) programNameObject.getObject(), false).getString();
            } else if (((ASN1TaggedObject)programNameObject.getObject()).getTagNo() == 1) {
                // ascii
                actualProgramName = DERIA5String.getInstance((DERTaggedObject) programNameObject.getObject(), false).getString();
            } else {
                fail("Unespected tag in programName of type SpcString");
                return null;
            }
        }
        return actualProgramName;
    }
    
    private String getProgramName(PEFile pe) throws Exception { 
        List<CMSSignedData> signatures = pe.getSignatures();
        assertEquals("Number of signatures", 1, signatures.size());

        // Reconstruct the data "to be signed"
        CMSSignedData signedData = signatures.get(0);
        
        return getProgramName(signedData);
    }
    
    private String getProgramName(final POIFSFileSystem fs) throws Exception {
        assertTrue("Signature present", fs.getRoot().hasEntry("\05DigitalSignature"));
        
        try (final DocumentInputStream dis =
            fs.createDocumentInputStream("\05DigitalSignature")) {
            final byte[] buf = new byte[dis.available()];

            dis.read(buf);

            final CMSSignedData cms = new CMSSignedData(buf);
            
            return getProgramName(cms);
        }
    }
    
    private String getProgramURL(final CMSSignedData signedData) {
        SignerInformation si = signedData.getSignerInfos().getSigners().iterator().next();

        Attribute attr = si.getSignedAttributes().get(AuthenticodeObjectIdentifiers.SPC_SP_OPUS_INFO_OBJID);
        ASN1Sequence seq =
                (ASN1Sequence) attr.getAttrValues().getObjectAt(0);

        // Check program name
        DERTaggedObject programURLObject =
                (DERTaggedObject) seq.getObjectAt(seq.size() > 1 ? 1 : 0);
        
        String actualProgramURL = null;
        if (programURLObject.getTagNo() == 1) {
            if (((ASN1TaggedObject)programURLObject.getObject()).getTagNo() == 0) {
                // url
                actualProgramURL = DERIA5String.getInstance((ASN1TaggedObject) programURLObject.getObject(), false).getString();
            } else {
                fail("Unsupported tag in programURL of type SpcLink: " + programURLObject.getTagNo());
                return null;
            }
        }
        return actualProgramURL;
    }
    
    private String getProgramURL(PEFile pe) throws Exception { 
        List<CMSSignedData> signatures = pe.getSignatures();
        assertEquals("Number of signatures", 1, signatures.size());

        // Reconstruct the data "to be signed"
        CMSSignedData signedData = signatures.get(0);
        
        return getProgramURL(signedData);
    }
    
    private String getProgramURL(final POIFSFileSystem fs) throws Exception {
        assertTrue("Signature present", fs.getRoot().hasEntry("\05DigitalSignature"));
        
        try (final DocumentInputStream dis =
            fs.createDocumentInputStream("\05DigitalSignature")) {
            final byte[] buf = new byte[dis.available()];

            dis.read(buf);

            final CMSSignedData cms = new CMSSignedData(buf);
            
            return getProgramURL(cms);
        }
    }
}
