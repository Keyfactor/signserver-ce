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
package org.signserver.module.cmssigner;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import static junit.framework.TestCase.assertTrue;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.server.SignServerContext;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.log.LogMap;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.testutils.ModulesTestCase;

/**
 * Unit tests for the PlainSigner class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class PlainSignerTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(PlainSignerTest.class);

    private static MockedCryptoToken tokenRSA;
    private static MockedCryptoToken tokenECDSA;
    private static MockedCryptoToken tokenSLH_DSA_SHA2_128F;
    private static MockedCryptoToken tokenSLH_DSA_SHA2_192F;
    private static MockedCryptoToken tokenSLH_DSA_SHA2_256F;
    private static MockedCryptoToken tokenSLH_DSA_SHA2_128S;
    private static MockedCryptoToken tokenSLH_DSA_SHA2_192S;
    private static MockedCryptoToken tokenSLH_DSA_SHA2_256S;
    private static MockedCryptoToken tokenSLH_DSA_SHAKE_128F;
    private static MockedCryptoToken tokenSLH_DSA_SHAKE_192F;
    private static MockedCryptoToken tokenSLH_DSA_SHAKE_256F;
    private static MockedCryptoToken tokenSLH_DSA_SHAKE_128S;
    private static MockedCryptoToken tokenSLH_DSA_SHAKE_192S;
    private static MockedCryptoToken tokenSLH_DSA_SHAKE_256S;
    private static MockedCryptoToken tokenML_DSA_44;
    private static MockedCryptoToken tokenML_DSA_65;
    private static MockedCryptoToken tokenML_DSA_87;


    public PlainSignerTest() {
    }
    
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
                        .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairRSA.getPublic())))
                        .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                        .build()),

                    // CA
                    caCertificate
                };
        tokenRSA = new MockedCryptoToken(signerKeyPairRSA.getPrivate(), signerKeyPairRSA.getPublic(), certChainRSA[0], Arrays.asList(certChainRSA), "BC");

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
                        .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairECDSA.getPublic())))
                        .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                        .build()),

                    // CA
                    caCertificate
                };
        tokenECDSA = new MockedCryptoToken(signerKeyPairECDSA.getPrivate(), signerKeyPairECDSA.getPublic(), certChainECDSA[0], Arrays.asList(certChainECDSA), "BC");

        // Create signer key-pair (SLH-DSA-SHA2-128F) and issue certificate
        final KeyPair signerKeyPairSLHDSA_SHA2_128F = CryptoUtils.generateSLHDSA("SLH-DSA-SHA2-128F");
        final Certificate[] certChainSLHDSA_SHA2_128F =
                new Certificate[] {
                        // Code Signer
                        new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                                .setIssuerPrivateKey(caKeyPair.getPrivate())
                                .setSubjectPublicKey(signerKeyPairSLHDSA_SHA2_128F.getPublic())
                                .setNotBefore(new Date(currentTime - 60000))
                                .setSignatureAlgorithm(signatureAlgorithm)
                                .setIssuer(caDN)
                                .setSubject("CN=Code Signer SLH-DSA 1")
                                .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairSLHDSA_SHA2_128F.getPublic())))
                                .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                                .build()),

                        // CA
                        caCertificate
                };
        tokenSLH_DSA_SHA2_128F = new MockedCryptoToken(signerKeyPairSLHDSA_SHA2_128F.getPrivate(), signerKeyPairSLHDSA_SHA2_128F.getPublic(), certChainSLHDSA_SHA2_128F[0], Arrays.asList(certChainSLHDSA_SHA2_128F), "BC");

        // Create signer key-pair (SLH-DSA-SHA2-192F) and issue certificate
        final KeyPair signerKeyPairSLHDSA_SHA2_192F = CryptoUtils.generateSLHDSA("SLH-DSA-SHA2-192F");
        final Certificate[] certChainSLHDSA_SHA2_192F =
                new Certificate[] {
                        // Code Signer
                        new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                                .setIssuerPrivateKey(caKeyPair.getPrivate())
                                .setSubjectPublicKey(signerKeyPairSLHDSA_SHA2_192F.getPublic())
                                .setNotBefore(new Date(currentTime - 60000))
                                .setSignatureAlgorithm(signatureAlgorithm)
                                .setIssuer(caDN)
                                .setSubject("CN=Code Signer SLH-DSA 1")
                                .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairSLHDSA_SHA2_192F.getPublic())))
                                .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                                .build()),

                        // CA
                        caCertificate
                };
        tokenSLH_DSA_SHA2_192F = new MockedCryptoToken(signerKeyPairSLHDSA_SHA2_192F.getPrivate(), signerKeyPairSLHDSA_SHA2_192F.getPublic(), certChainSLHDSA_SHA2_192F[0], Arrays.asList(certChainSLHDSA_SHA2_192F), "BC");

        // Create signer key-pair (SLH-DSA-SHA2-256F) and issue certificate
        final KeyPair signerKeyPairSLHDSA_SHA2_256F = CryptoUtils.generateSLHDSA("SLH-DSA-SHA2-256F");
        final Certificate[] certChainSLHDSA_SHA2_256F =
                new Certificate[] {
                        // Code Signer
                        new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                                .setIssuerPrivateKey(caKeyPair.getPrivate())
                                .setSubjectPublicKey(signerKeyPairSLHDSA_SHA2_256F.getPublic())
                                .setNotBefore(new Date(currentTime - 60000))
                                .setSignatureAlgorithm(signatureAlgorithm)
                                .setIssuer(caDN)
                                .setSubject("CN=Code Signer SLH-DSA 1")
                                .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairSLHDSA_SHA2_256F.getPublic())))
                                .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                                .build()),

                        // CA
                        caCertificate
                };
        tokenSLH_DSA_SHA2_256F = new MockedCryptoToken(signerKeyPairSLHDSA_SHA2_256F.getPrivate(), signerKeyPairSLHDSA_SHA2_256F.getPublic(), certChainSLHDSA_SHA2_256F[0], Arrays.asList(certChainSLHDSA_SHA2_256F), "BC");

        // Create signer key-pair (SLH-DSA-SHA2-128S) and issue certificate
        final KeyPair signerKeyPairSLHDSA_SHA2_128S = CryptoUtils.generateSLHDSA("SLH-DSA-SHA2-128S");
        final Certificate[] certChainSLHDSA_SHA2_128S =
                new Certificate[] {
                        // Code Signer
                        new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                                .setIssuerPrivateKey(caKeyPair.getPrivate())
                                .setSubjectPublicKey(signerKeyPairSLHDSA_SHA2_128S.getPublic())
                                .setNotBefore(new Date(currentTime - 60000))
                                .setSignatureAlgorithm(signatureAlgorithm)
                                .setIssuer(caDN)
                                .setSubject("CN=Code Signer SLH-DSA 1")
                                .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairSLHDSA_SHA2_128S.getPublic())))
                                .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                                .build()),

                        // CA
                        caCertificate
                };
        tokenSLH_DSA_SHA2_128S = new MockedCryptoToken(signerKeyPairSLHDSA_SHA2_128S.getPrivate(), signerKeyPairSLHDSA_SHA2_128S.getPublic(), certChainSLHDSA_SHA2_128S[0], Arrays.asList(certChainSLHDSA_SHA2_128S), "BC");

        // Create signer key-pair (SLH-DSA-SHA2-192S) and issue certificate
        final KeyPair signerKeyPairSLHDSA_SHA2_192S = CryptoUtils.generateSLHDSA("SLH-DSA-SHA2-192S");
        final Certificate[] certChainSLHDSA_SHA2_192S =
                new Certificate[] {
                        // Code Signer
                        new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                                .setIssuerPrivateKey(caKeyPair.getPrivate())
                                .setSubjectPublicKey(signerKeyPairSLHDSA_SHA2_192S.getPublic())
                                .setNotBefore(new Date(currentTime - 60000))
                                .setSignatureAlgorithm(signatureAlgorithm)
                                .setIssuer(caDN)
                                .setSubject("CN=Code Signer SLH-DSA 1")
                                .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairSLHDSA_SHA2_192S.getPublic())))
                                .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                                .build()),

                        // CA
                        caCertificate
                };
        tokenSLH_DSA_SHA2_192S = new MockedCryptoToken(signerKeyPairSLHDSA_SHA2_192S.getPrivate(), signerKeyPairSLHDSA_SHA2_192S.getPublic(), certChainSLHDSA_SHA2_192S[0], Arrays.asList(certChainSLHDSA_SHA2_192S), "BC");

        // Create signer key-pair (SLH-DSA-SHA2-256S) and issue certificate
        final KeyPair signerKeyPairSLHDSA_SHA2_256S = CryptoUtils.generateSLHDSA("SLH-DSA-SHA2-256S");
        final Certificate[] certChainSLHDSA_SHA2_256S =
                new Certificate[] {
                        // Code Signer
                        new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                                .setIssuerPrivateKey(caKeyPair.getPrivate())
                                .setSubjectPublicKey(signerKeyPairSLHDSA_SHA2_256S.getPublic())
                                .setNotBefore(new Date(currentTime - 60000))
                                .setSignatureAlgorithm(signatureAlgorithm)
                                .setIssuer(caDN)
                                .setSubject("CN=Code Signer SLH-DSA 1")
                                .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairSLHDSA_SHA2_256S.getPublic())))
                                .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                                .build()),

                        // CA
                        caCertificate
                };
        tokenSLH_DSA_SHA2_256S = new MockedCryptoToken(signerKeyPairSLHDSA_SHA2_256S.getPrivate(), signerKeyPairSLHDSA_SHA2_256S.getPublic(), certChainSLHDSA_SHA2_256S[0], Arrays.asList(certChainSLHDSA_SHA2_256S), "BC");

        // Create signer key-pair (SLH-DSA-SHAKE-128F) and issue certificate
        final KeyPair signerKeyPairSLHDSA_SHAKE_128F = CryptoUtils.generateSLHDSA("SLH-DSA-SHAKE-128F");
        final Certificate[] certChainSLHDSA_SHAKE_128F =
                new Certificate[] {
                        // Code Signer
                        new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                                .setIssuerPrivateKey(caKeyPair.getPrivate())
                                .setSubjectPublicKey(signerKeyPairSLHDSA_SHAKE_128F.getPublic())
                                .setNotBefore(new Date(currentTime - 60000))
                                .setSignatureAlgorithm(signatureAlgorithm)
                                .setIssuer(caDN)
                                .setSubject("CN=Code Signer SLH-DSA 1")
                                .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairSLHDSA_SHAKE_128F.getPublic())))
                                .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                                .build()),
                        // CA
                        caCertificate
                };
        tokenSLH_DSA_SHAKE_128F = new MockedCryptoToken(signerKeyPairSLHDSA_SHAKE_128F.getPrivate(), signerKeyPairSLHDSA_SHAKE_128F.getPublic(), certChainSLHDSA_SHAKE_128F[0], Arrays.asList(certChainSLHDSA_SHAKE_128F), "BC");


    // Create signer key-pair (SLH-DSA-SHAKE-192F) and issue certificate
    final KeyPair signerKeyPairSLHDSA_SHAKE_192F = CryptoUtils.generateSLHDSA("SLH-DSA-SHAKE-192F");
    final Certificate[] certChainSLHDSA_SHAKE_192F =
            new Certificate[] {
                    // Code Signer
                    new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                            .setIssuerPrivateKey(caKeyPair.getPrivate())
                            .setSubjectPublicKey(signerKeyPairSLHDSA_SHAKE_192F.getPublic())
                            .setNotBefore(new Date(currentTime - 60000))
                            .setSignatureAlgorithm(signatureAlgorithm)
                            .setIssuer(caDN)
                            .setSubject("CN=Code Signer SLH-DSA 1")
                            .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairSLHDSA_SHAKE_192F.getPublic())))
                            .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                            .build()),
                    // CA
                    caCertificate
            };
        tokenSLH_DSA_SHAKE_192F = new MockedCryptoToken(signerKeyPairSLHDSA_SHAKE_192F.getPrivate(), signerKeyPairSLHDSA_SHAKE_192F.getPublic(), certChainSLHDSA_SHAKE_192F[0], Arrays.asList(certChainSLHDSA_SHAKE_192F), "BC");

        // Create signer key-pair (SLH-DSA-SHAKE-256F) and issue certificate
        final KeyPair signerKeyPairSLHDSA_SHAKE_256F = CryptoUtils.generateSLHDSA("SLH-DSA-SHAKE-256F");
        final Certificate[] certChainSLHDSA_SHAKE_256F =
                new Certificate[] {
                        // Code Signer
                        new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                                .setIssuerPrivateKey(caKeyPair.getPrivate())
                                .setSubjectPublicKey(signerKeyPairSLHDSA_SHAKE_256F.getPublic())
                                .setNotBefore(new Date(currentTime - 60000))
                                .setSignatureAlgorithm(signatureAlgorithm)
                                .setIssuer(caDN)
                                .setSubject("CN=Code Signer SLH-DSA 1")
                                .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairSLHDSA_SHAKE_256F.getPublic())))
                                .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                                .build()),
                        // CA
                        caCertificate
                };
        tokenSLH_DSA_SHAKE_256F = new MockedCryptoToken(signerKeyPairSLHDSA_SHAKE_256F.getPrivate(), signerKeyPairSLHDSA_SHAKE_256F.getPublic(), certChainSLHDSA_SHAKE_256F[0], Arrays.asList(certChainSLHDSA_SHAKE_256F), "BC");


        // Create signer key-pair (SLH-DSA-SHAKE-128S) and issue certificate
        final KeyPair signerKeyPairSLHDSA_SHAKE_128S = CryptoUtils.generateSLHDSA("SLH-DSA-SHAKE-128S");
        final Certificate[] certChainSLHDSA_SHAKE_128S =
                new Certificate[] {
                        // Code Signer
                        new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                                .setIssuerPrivateKey(caKeyPair.getPrivate())
                                .setSubjectPublicKey(signerKeyPairSLHDSA_SHAKE_128S.getPublic())
                                .setNotBefore(new Date(currentTime - 60000))
                                .setSignatureAlgorithm(signatureAlgorithm)
                                .setIssuer(caDN)
                                .setSubject("CN=Code Signer SLH-DSA 1")
                                .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairSLHDSA_SHAKE_128S.getPublic())))
                                .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                                .build()),
                        // CA
                        caCertificate
                };
        tokenSLH_DSA_SHAKE_128S = new MockedCryptoToken(signerKeyPairSLHDSA_SHAKE_128S.getPrivate(), signerKeyPairSLHDSA_SHAKE_128S.getPublic(), certChainSLHDSA_SHAKE_128S[0], Arrays.asList(certChainSLHDSA_SHAKE_128S), "BC");

        // Create signer key-pair (SLH-DSA-SHAKE-192S) and issue certificate
        final KeyPair signerKeyPairSLHDSA_SHAKE_192S = CryptoUtils.generateSLHDSA("SLH-DSA-SHAKE-192S");
        final Certificate[] certChainSLHDSA_SHAKE_192S =
                new Certificate[] {
                        // Code Signer
                        new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                                .setIssuerPrivateKey(caKeyPair.getPrivate())
                                .setSubjectPublicKey(signerKeyPairSLHDSA_SHAKE_192S.getPublic())
                                .setNotBefore(new Date(currentTime - 60000))
                                .setSignatureAlgorithm(signatureAlgorithm)
                                .setIssuer(caDN)
                                .setSubject("CN=Code Signer SLH-DSA 1")
                                .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairSLHDSA_SHAKE_192S.getPublic())))
                                .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                                .build()),
                        // CA
                        caCertificate
                };
        tokenSLH_DSA_SHAKE_192S = new MockedCryptoToken(signerKeyPairSLHDSA_SHAKE_192S.getPrivate(), signerKeyPairSLHDSA_SHAKE_192S.getPublic(), certChainSLHDSA_SHAKE_192S[0], Arrays.asList(certChainSLHDSA_SHAKE_192S), "BC");

        // Create signer key-pair (SLH-DSA-SHAKE-256S) and issue certificate
        final KeyPair signerKeyPairSLHDSA_SHAKE_256S = CryptoUtils.generateSLHDSA("SLH-DSA-SHAKE-256S");
        final Certificate[] certChainSLHDSA_SHAKE_256S =
                new Certificate[] {
                        // Code Signer
                        new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                                .setIssuerPrivateKey(caKeyPair.getPrivate())
                                .setSubjectPublicKey(signerKeyPairSLHDSA_SHAKE_256S.getPublic())
                                .setNotBefore(new Date(currentTime - 60000))
                                .setSignatureAlgorithm(signatureAlgorithm)
                                .setIssuer(caDN)
                                .setSubject("CN=Code Signer SLH-DSA 1")
                                .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairSLHDSA_SHAKE_256S.getPublic())))
                                .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                                .build()),
                        // CA
                        caCertificate
                };
        tokenSLH_DSA_SHAKE_256S = new MockedCryptoToken(signerKeyPairSLHDSA_SHAKE_256S.getPrivate(), signerKeyPairSLHDSA_SHAKE_256S.getPublic(), certChainSLHDSA_SHAKE_256S[0], Arrays.asList(certChainSLHDSA_SHAKE_256S), "BC");

        // Create signer key-pair (ML-DSA-44) and issue certificate
        final KeyPair signerKeyPairMLDSA_44 = CryptoUtils.generateSLHDSA("ML-DSA-44");
        final Certificate[] certChainMLDSA_44 =
                new Certificate[] {
                        // Code Signer
                        new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                                .setIssuerPrivateKey(caKeyPair.getPrivate())
                                .setSubjectPublicKey(signerKeyPairMLDSA_44.getPublic())
                                .setNotBefore(new Date(currentTime - 60000))
                                .setSignatureAlgorithm(signatureAlgorithm)
                                .setIssuer(caDN)
                                .setSubject("CN=Code Signer ML-DSA 1")
                                .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairMLDSA_44.getPublic())))
                                .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                                .build()),

                        // CA
                        caCertificate
                };
        tokenML_DSA_44 = new MockedCryptoToken(signerKeyPairMLDSA_44.getPrivate(), signerKeyPairMLDSA_44.getPublic(), certChainMLDSA_44[0], Arrays.asList(certChainMLDSA_44), "BC");

        // Create signer key-pair (ML-DSA-65) and issue certificate
        final KeyPair signerKeyPairMLDSA_65 = CryptoUtils.generateSLHDSA("ML-DSA-65");
        final Certificate[] certChainMLDSA_65 =
                new Certificate[] {
                        // Code Signer
                        new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                                .setIssuerPrivateKey(caKeyPair.getPrivate())
                                .setSubjectPublicKey(signerKeyPairMLDSA_65.getPublic())
                                .setNotBefore(new Date(currentTime - 60000))
                                .setSignatureAlgorithm(signatureAlgorithm)
                                .setIssuer(caDN)
                                .setSubject("CN=Code Signer ML-DSA 1")
                                .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairMLDSA_65.getPublic())))
                                .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                                .build()),

                        // CA
                        caCertificate
                };
        tokenML_DSA_65 = new MockedCryptoToken(signerKeyPairMLDSA_65.getPrivate(), signerKeyPairMLDSA_65.getPublic(), certChainMLDSA_65[0], Arrays.asList(certChainMLDSA_65), "BC");

        // Create signer key-pair (ML-DSA-87) and issue certificate
        final KeyPair signerKeyPairMLDSA_87 = CryptoUtils.generateSLHDSA("ML-DSA-87");
        final Certificate[] certChainMLDSA_87 =
                new Certificate[] {
                        // Code Signer
                        new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                                .setIssuerPrivateKey(caKeyPair.getPrivate())
                                .setSubjectPublicKey(signerKeyPairMLDSA_87.getPublic())
                                .setNotBefore(new Date(currentTime - 60000))
                                .setSignatureAlgorithm(signatureAlgorithm)
                                .setIssuer(caDN)
                                .setSubject("CN=Code Signer ML-DSA 1")
                                .addExtension(new CertExt(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(signerKeyPairMLDSA_87.getPublic())))
                                .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning).toASN1Primitive()))
                                .build()),

                        // CA
                        caCertificate
                };
        tokenML_DSA_87 = new MockedCryptoToken(signerKeyPairMLDSA_87.getPrivate(), signerKeyPairMLDSA_87.getPublic(), certChainMLDSA_87[0], Arrays.asList(certChainMLDSA_87), "BC");
    }


    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test signing using an RSA key-pair.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_RSA() throws Exception {
        LOG.info("testNormalSigning_RSA");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenRSA, createConfig(null));
        assertSignedAndVerifiable(plainText, "SHA256withRSA", tokenRSA, resp);
    }
    
    /**
     * Test signing using empty Signature Algorithms.
     * @throws Exception 
     */
    @Test
    public void testNormalSigningWithEmptyParams() throws Exception {
        LOG.info("testNormalSigningWithEmptyParams");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenRSA, createConfig("  "));
        assertSignedAndVerifiable(plainText, "SHA256withRSA", tokenRSA, resp);
    }

    /**
     * Test signing using an ECDSA key-pair.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_ECDSA() throws Exception {
        LOG.info("testNormalSigning_ECDSA");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenECDSA, createConfig(null));
        assertSignedAndVerifiable(plainText, "SHA256withECDSA", tokenECDSA, resp);
    }

    /**
     * Test signing using an SLH-DSA-SHA2-128F key-pair.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_SLHDSA_SHA2_128F() throws Exception {
        LOG.info("testNormalSigning_SLHDSA_SHA2_128F");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenSLH_DSA_SHA2_128F, createConfig("SLH-DSA-SHA2-128F"));
        assertSignedAndVerifiable(plainText, "SLH-DSA-SHA2-128F", tokenSLH_DSA_SHA2_128F, resp);
    }

    /**
     * Test signing using an SLH-DSA-SHA2-192F key-pair.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_SLHDSA_SHA2_192F() throws Exception {
        LOG.info("testNormalSigning_SLHDSA_SHA2_192F");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenSLH_DSA_SHA2_192F, createConfig("SLH-DSA-SHA2-192F"));
        assertSignedAndVerifiable(plainText, "SLH-DSA-SHA2-192F", tokenSLH_DSA_SHA2_192F, resp);
    }

    /**
     * Test signing using an SLH-DSA-SHA2-256F key-pair.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_SLHDSA_SHA2_256F() throws Exception {
        LOG.info("testNormalSigning_SLHDSA_SHA2_256F");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenSLH_DSA_SHA2_256F, createConfig("SLH-DSA-SHA2-256F"));
        assertSignedAndVerifiable(plainText, "SLH-DSA-SHA2-256F", tokenSLH_DSA_SHA2_256F, resp);
    }

    /**
     * Test signing using an SLH-DSA-SHA2-128F key-pair.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_SLHDSA_SHA2_128S() throws Exception {
        LOG.info("testNormalSigning_SLHDSA_SHA2_128S");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenSLH_DSA_SHA2_128S, createConfig("SLH-DSA-SHA2-128S"));
        assertSignedAndVerifiable(plainText, "SLH-DSA-SHA2-128S", tokenSLH_DSA_SHA2_128S, resp);
    }

    /**
     * Test signing using an SLH-DSA-SHA2-192S key-pair.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_SLHDSA_SHA2_192S() throws Exception {
        LOG.info("testNormalSigning_SLHDSA_SHA2_192S");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenSLH_DSA_SHA2_192S, createConfig("SLH-DSA-SHA2-192S"));
        assertSignedAndVerifiable(plainText, "SLH-DSA-SHA2-192S", tokenSLH_DSA_SHA2_192S, resp);
    }

    /**
     * Test signing using an SLH-DSA-SHA2-256S key-pair.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_SLHDSA_SHA2_256S() throws Exception {
        LOG.info("testNormalSigning_SLHDSA_SHA2_256S");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenSLH_DSA_SHA2_256S, createConfig("SLH-DSA-SHA2-256S"));
        assertSignedAndVerifiable(plainText, "SLH-DSA-SHA2-256S", tokenSLH_DSA_SHA2_256S, resp);
    }

    /**
     * Test signing using an SLH-DSA-SHAKE-128F key-pair.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_SLHDSA_SHAKE_128F() throws Exception {
        LOG.info("testNormalSigning_SLHDSA_SHAKE_128F");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenSLH_DSA_SHAKE_128F, createConfig("SLH-DSA-SHAKE-128F"));
        assertSignedAndVerifiable(plainText, "SLH-DSA-SHAKE-128F", tokenSLH_DSA_SHAKE_128F, resp);
    }

    /**
     * Test signing using an SLH-DSA-SHAKE-192F key-pair.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_SLHDSA_SHAKE_192F() throws Exception {
        LOG.info("testNormalSigning_SLHDSA_SHAKE_192F");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenSLH_DSA_SHAKE_192F, createConfig("SLH-DSA-SHAKE-192F"));
        assertSignedAndVerifiable(plainText, "SLH-DSA-SHAKE-192F", tokenSLH_DSA_SHAKE_192F, resp);
    }

    /**
     * Test signing using an SLH-DSA-SHAKE-256F key-pair.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_SLHDSA_SHAKE_256F() throws Exception {
        LOG.info("testNormalSigning_SLHDSA_SHAKE_256F");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenSLH_DSA_SHAKE_256F, createConfig("SLH-DSA-SHAKE-256F"));
        assertSignedAndVerifiable(plainText, "SLH-DSA-SHAKE-256F", tokenSLH_DSA_SHAKE_256F, resp);
    }

    /**
     * Test signing using an SLH-DSA-SHAKE-128S key-pair.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_SLHDSA_SHAKE_128S() throws Exception {
        LOG.info("testNormalSigning_SLHDSA_SHAKE_128S");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenSLH_DSA_SHAKE_128S, createConfig("SLH-DSA-SHAKE-128S"));
        assertSignedAndVerifiable(plainText, "SLH-DSA-SHAKE-128S", tokenSLH_DSA_SHAKE_128S, resp);
    }

    /**
     * Test signing using an SLH-DSA-SHAKE-192S key-pair.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_SLHDSA_SHAKE_192S() throws Exception {
        LOG.info("testNormalSigning_SLHDSA_SHAKE_192S");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenSLH_DSA_SHAKE_192S, createConfig("SLH-DSA-SHAKE-192S"));
        assertSignedAndVerifiable(plainText, "SLH-DSA-SHAKE-192S", tokenSLH_DSA_SHAKE_192S, resp);
    }

    /**
     * Test signing using an SLH-DSA-SHAKE-256S key-pair.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_SLHDSA_SHAKE_256S() throws Exception {
        LOG.info("testNormalSigning_SLHDSA_SHAKE_256S");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenSLH_DSA_SHAKE_256S, createConfig("SLH-DSA-SHAKE-256S"));
        assertSignedAndVerifiable(plainText, "SLH-DSA-SHAKE-256S", tokenSLH_DSA_SHAKE_256S, resp);
    }

    /**
     * Test signing using an ML-DSA-44 key-pair.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_MLDSA_44() throws Exception {
        LOG.info("testNormalSigning_MLDSA_44");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenML_DSA_44, createConfig("ML-DSA-44"));
        assertSignedAndVerifiable(plainText, "ML-DSA-44", tokenML_DSA_44, resp);
    }

    /**
     * Test signing using an ML-DSA-65 key-pair.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_MLDSA_65() throws Exception {
        LOG.info("testNormalSigning_MLDSA_65");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenML_DSA_65, createConfig("ML-DSA-65"));
        assertSignedAndVerifiable(plainText, "ML-DSA-65", tokenML_DSA_65, resp);
    }

    /**
     * Test signing using an ML-DSA-87 key-pair.
     * @throws Exception
     */
    @Test
    public void testNormalSigning_MLDSA_87() throws Exception {
        LOG.info("testNormalSigning_MLDSA_87");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenML_DSA_87, createConfig("ML-DSA-87"));
        assertSignedAndVerifiable(plainText, "ML-DSA-87", tokenML_DSA_87, resp);
    }
    
    /**
     * Test signing using when SHA1withRSA is explicitly specified.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_SHA1withRSA() throws Exception {
        LOG.info("testNormalSigning_RSA");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenRSA, createConfig("SHA1withRSA"));
        assertSignedAndVerifiable(plainText, "SHA1withRSA", tokenRSA, resp);
    }
    
    /**
     * Test signing using when SHA1withECDSA is explicitly specified.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_SHA1withECDSA() throws Exception {
        LOG.info("testNormalSigning_ECDSA");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenECDSA, createConfig("SHA1withECDSA"));
        assertSignedAndVerifiable(plainText, "SHA1withECDSA", tokenECDSA, resp);
    }
    
    /**
     * Test signing using when SHA256withRSA is explicitly specified.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_SHA256withRSA() throws Exception {
        LOG.info("testNormalSigning_RSA");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenRSA, createConfig("SHA256withRSA"));
        assertSignedAndVerifiable(plainText, "SHA256withRSA", tokenRSA, resp);
    }

    /**
     * Test signing using when SHA256withRSAandMGF1 is explicitly specified.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_SHA256withRSAandMGF1() throws Exception {
        LOG.info("testNormalSigning_RSAandMGF1");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenRSA, createConfig("SHA256withRSAandMGF1"));
        assertSignedAndVerifiable(plainText, "SHA256withRSAandMGF1", tokenRSA, resp);
    }
    
    /**
     * Test signing using when SHA256withECDSA is explicitly specified.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_SHA256withECDSA() throws Exception {
        LOG.info("testNormalSigning_ECDSA");
        byte[] plainText = "some-data".getBytes("ASCII");
        SimplifiedResponse resp = sign(plainText, tokenECDSA, createConfig("SHA256withECDSA"));
        assertSignedAndVerifiable(plainText, "SHA256withECDSA", tokenECDSA, resp);
    }
    
    private WorkerConfig createConfig(String signatureAlgorithm) throws Exception {
        return createConfig(signatureAlgorithm, null);
    }
    
    private WorkerConfig createConfig(final String signatureAlgorithm,
                                      final String logDigestAlgorithm) throws Exception {
        return createConfig(signatureAlgorithm, logDigestAlgorithm, null);
    }

    private WorkerConfig createConfig(final String signatureAlgorithm,
                                      final String logDigestAlgorithm,
                                      final String doLogRequestDigest) throws Exception {
        return createConfig(signatureAlgorithm, logDigestAlgorithm,
                            doLogRequestDigest, false, null);
    }

     private WorkerConfig createConfig(final String signatureAlgorithm,
                                       final String logDigestAlgorithm,
                                       final String doLogRequestDigest,
                                       final boolean allowClientSideOverride,
                                       final String acceptedHashDigestAlgorithms)
             throws Exception {
        WorkerConfig config = new WorkerConfig();
        if (signatureAlgorithm != null) {
            config.setProperty("SIGNATUREALGORITHM", signatureAlgorithm);
        }
        if (logDigestAlgorithm != null) {
            config.setProperty("LOGREQUEST_DIGESTALGORITHM", logDigestAlgorithm);
        }
        if (doLogRequestDigest != null) {
            config.setProperty("DO_LOGREQUEST_DIGEST", doLogRequestDigest);
        }
        if (allowClientSideOverride) {
            config.setProperty("ALLOW_CLIENTSIDEHASHING_OVERRIDE", "true");
        }
        if (acceptedHashDigestAlgorithms != null) {
            config.setProperty("ACCEPTED_HASH_DIGEST_ALGORITHMS",
                               acceptedHashDigestAlgorithms);
        }
        return config;
    }

    private SimplifiedResponse sign(final byte[] data, MockedCryptoToken token, WorkerConfig config) throws Exception {
        return sign(data, token, config, null);
    }
    
    private SimplifiedResponse sign(final byte[] data, MockedCryptoToken token, WorkerConfig config, RequestContext requestContext) throws Exception {
        MockedPlainSigner instance = new MockedPlainSigner(token);
        instance.init(1, config, new SignServerContext(), null);

        if (requestContext == null) {
            requestContext = new RequestContext();
        }
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(data);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            SignatureRequest request = new SignatureRequest(100, requestData, responseData);
            SignatureResponse response = (SignatureResponse) instance.processData(request, requestContext);

            byte[] signedBytes = responseData.toReadableData().getAsByteArray();
            Certificate signerCertificate = response.getSignerCertificate();
            return new SimplifiedResponse(signedBytes, signerCertificate);
        }
    }
    

    private void assertSignedAndVerifiable(byte[] plainText, String signatureAlgorithm, MockedCryptoToken token, SimplifiedResponse resp) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(signatureAlgorithm, "BC");
        signature.initVerify(resp.getSignerCertificate());
        signature.update(plainText);
        assertTrue("consistent signature", signature.verify(resp.getProcessedData()));
    }
    
    private void assertRequestDigestMatches(byte[] plainText, String digestAlgorithm, SimplifiedResponse resp, RequestContext context) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        assertEquals("digestAlg", digestAlgorithm, String.valueOf(LogMap.getInstance(context).get("REQUEST_DIGEST_ALGORITHM")));
        
        final MessageDigest md = MessageDigest.getInstance(digestAlgorithm);
        final String expected = Hex.toHexString(md.digest(plainText));
        Object actual = LogMap.getInstance(context).get("REQUEST_DIGEST");
        assertEquals("digest", expected, String.valueOf(actual));
    }
    
    private void assertNoRequestDigest(final RequestContext context) throws Exception {
        final Object requestDigest = LogMap.getInstance(context).get("REQUEST_DIGEST");
        assertNull("no digest", requestDigest);
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
        final byte[] plainText = "some-data".getBytes("ASCII");
        final SimplifiedResponse resp = sign(plainText, tokenRSA, createConfig(null), context);

        assertRequestDigestMatches(plainText, "SHA256", resp, context);
    }
    
    /**
     * Tests that setting DO_LOGREQUEST_DIGEST to false results in no logging
     * of the request digest.
     * 
     * @throws Exception 
     */
    @Test
    public void testNoLogRequestDigest() throws Exception {
        LOG.info("testNoLogRequestDigest");
        
        final WorkerConfig config = createConfig(null);
        config.setProperty("DO_LOGREQUEST_DIGEST", "false");
        final RequestContext context = new RequestContext();
        final byte[] plainText = "some-data".getBytes("ASCII");
        final SimplifiedResponse resp = sign(plainText, tokenRSA, config, context);

        assertNoRequestDigest(context);
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
        final byte[] plainText = "some-data".getBytes("ASCII");
        final SimplifiedResponse resp = sign(plainText, tokenRSA, createConfig(null, "SHA1"), context);

        assertRequestDigestMatches(plainText, "SHA1", resp, context);
    }

    /**
     * Tests logging of the response.
     * @throws Exception 
     */
    @Test
    public void testLogResponseEncoded() throws Exception {
        LOG.info("testLogResponseEncoded");
        final RequestContext context = new RequestContext();
        final byte[] plainText = "some-data".getBytes("ASCII");
        final SimplifiedResponse resp = sign(plainText, tokenRSA, createConfig(null), context);

        final String expected = new String(Base64.encode(resp.getProcessedData()), "ASCII");
        assertEquals("responseEncoded", expected, String.valueOf(LogMap.getInstance(context).get("RESPONSE_ENCODED")));
    }

    /**
     * Test that setting an empty value for DO_LOGREQUEST_DIGEST works.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_doLogrequestDigestEmpty() throws Exception {
        LOG.info("testInit_doLogrequestDigestEmpty");
        WorkerConfig config = new WorkerConfig();
        config.setProperty(WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        config.setProperty("DO_LOGREQUEST_DIGEST", "");
        PlainSigner instance = new MockedPlainSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        assertTrue("no fatal errors", instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Test that setting "true" for DO_LOGREQUEST_DIGEST works.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_doLogrequestDigestTrue() throws Exception {
        LOG.info("testInit_noLogrequestDigestTrue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty(WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        config.setProperty("DO_LOGREQUEST_DIGEST", "true");
        PlainSigner instance = new MockedPlainSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        assertTrue("no fatal errors", instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Test that setting "false" for DO_LOGREQUEST_DIGEST works.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_doLogrequestDigestFalse() throws Exception {
        LOG.info("testInit_doLogrequestDigestFalse");
        WorkerConfig config = new WorkerConfig();
        config.setProperty(WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        config.setProperty("DO_LOGREQUEST_DIGEST", "false");
        PlainSigner instance = new MockedPlainSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        assertTrue("no fatal errors", instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Test that setting "TRUE" (upper case) for DO_LOGREQUEST_DIGEST works.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_doLogrequestDigestTrueUpper() throws Exception {
        LOG.info("testInit_doLogrequestDigestTrueUpper");
        WorkerConfig config = new WorkerConfig();
        config.setProperty(WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        config.setProperty("DO_LOGREQUEST_DIGEST", "TRUE");
        PlainSigner instance = new MockedPlainSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        assertTrue("no fatal errors", instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Test that setting "true " (invalid with extra space) for DO_LOGREQUEST_DIGEST
     * results in a configuration error.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_noRequestArchivingInvalid() throws Exception {
        LOG.info("testInit_doLogrequestDigestInvalid");
        WorkerConfig config = new WorkerConfig();
        config.setProperty(WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        config.setProperty("DO_LOGREQUEST_DIGEST", "true ");
        PlainSigner instance = new MockedPlainSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        assertTrue("should contain error: " + instance.getFatalErrors(null).toString(),
                   instance.getFatalErrors(null).contains("Incorrect value for DO_LOGREQUEST_DIGEST"));
    }
    
    /**
     * Test that Signing works and signature is verified when Signature algorithm is NONEwithRSA and input is SHA-512 hash digest.
     * 
     * @throws Exception 
     */
    @Test
    public void testNONESigning_RSA_SHA512_structure() throws Exception {
        LOG.info("testNONESigning_RSA_SHA512_structure");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(plainText);
        byte[] hash = md.digest();

        // Taken from RFC 3447, page 42 for SHA-512, create input for signing
        byte[] modifierBytes = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(modifierBytes);
        baos.write(hash);

        SimplifiedResponse resp = sign(baos.toByteArray(), tokenRSA, createConfig("NONEwithRSA"));
        assertSignedAndVerifiable(plainText, "SHA512withRSA", tokenRSA, resp);
    }

    /**
     * Test that Signing works and signature is verified when Signature algorithm is NONEwithRSA and input is SHA-512 hash digest.
     * Use server-side padding with the clientside request parameters.
     * 
     * @throws Exception 
     */
    @Test
    public void testNONESigning_RSA_SHA512_serverSidePadding() throws Exception {
        LOG.info("testNONESigning_RSA_SHA512_serverSidePadding");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(plainText);
        byte[] hash = md.digest();

        final RequestContext context = new RequestContext();

        RequestMetadata.getInstance(context).put("USING_CLIENTSUPPLIED_HASH", "true");
        RequestMetadata.getInstance(context).put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-512");

        final SimplifiedResponse resp =
                sign(hash, tokenRSA,
                     createConfig("NONEwithRSA", null, null, true,
                                  "SHA-512"), context);
        assertSignedAndVerifiable(plainText, "SHA512withRSA", tokenRSA, resp);
    }
    
    /**
     * Test that Signing works and signature is verified when Signature algorithm is NONEwithECDSA and input is SHA-512 hash digest.
     * 
     * @throws Exception 
     */
    @Test
    public void testNONESigning_ECDSA_SHA512_structure() throws Exception {
        LOG.info("testNONESigning_ECDSA_SHA512_structure");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(plainText);
        byte[] hash = md.digest();
        SimplifiedResponse resp = sign(hash, tokenECDSA, createConfig("NONEwithECDSA"));
        assertSignedAndVerifiable(plainText, "SHA512withECDSA", tokenECDSA, resp);
    }

    /**
     * Test that Signing works and signature is verified when Signature algorithm is NONEwithECDSA and input is SHA-512 hash digest.
     * Using client-side request parameters.
     * 
     * @throws Exception 
     */
     @Test
    public void testNONESigning_ECDSA_SHA512_clientSideParams() throws Exception {
        LOG.info("testNONESigning_ECDSA_SHA512_clientSideParams");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(plainText);
        byte[] hash = md.digest();

        final RequestContext context = new RequestContext();

        RequestMetadata.getInstance(context).put("USING_CLIENTSUPPLIED_HASH", "true");
        RequestMetadata.getInstance(context).put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-512");

        SimplifiedResponse resp =
                sign(hash, tokenECDSA, createConfig("NONEwithECDSA", null, null,
                                                    true, "SHA-512"), context);
        assertSignedAndVerifiable(plainText, "SHA512withECDSA", tokenECDSA, resp);
    }
    
    /**
     * Test that Signing works and signature is verified when Signature algorithm is NONEwithRSA and input is SHA-256 hash digest.
     * 
     * @throws Exception 
     */
    @Test
    public void testNONESigning_RSA_SHA256_structure() throws Exception {
        LOG.info("testNONESigning_RSA_SHA256_structure");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(plainText);
        byte[] hash = md.digest();

        // Taken from RFC 3447, page 42 for SHA-256, create input for signing
        byte[] modifierBytes = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(modifierBytes);
        baos.write(hash);

        SimplifiedResponse resp = sign(baos.toByteArray(), tokenRSA, createConfig("NONEwithRSA"));
        assertSignedAndVerifiable(plainText, "SHA256withRSA", tokenRSA, resp);
    }

    /**
     * Test that Signing would fail when trying to do client-side padding
     * while using the client-side request parameters to indicate that
     * server-side padding should be performed.
     * 
     * @throws Exception 
     */
    @Test
    public void testNONESigning_RSA_SHA256_clientSidePaddingNotAccepted() throws Exception {
        LOG.info("testNONESigning_RSA_SHA256_structure");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(plainText);
        byte[] hash = md.digest();

        // Taken from RFC 3447, page 42 for SHA-256, create input for signing
        byte[] modifierBytes = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(modifierBytes);
        baos.write(hash);

        final RequestContext context = new RequestContext();

        RequestMetadata.getInstance(context).put("USING_CLIENTSUPPLIED_HASH", "true");
        RequestMetadata.getInstance(context).put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-256");

        try {
            final SimplifiedResponse resp =
                    sign(baos.toByteArray(), tokenRSA,
                         createConfig("NONEwithRSA", null, null, true,
                                      "SHA-256"), context);
        } catch (IllegalRequestException ex) {
            assertEquals("Input length doesn't match hash digest algorithm specified through request metadata",
                         ex.getMessage());
        }
    }

    /**
     * Test that Signing works and signature is verified when Signature algorithm is NONEwithRSA and input is SHA-256 hash digest.
     * Use server-side padding with the clientside request parameters.
     * 
     * @throws Exception 
     */
    @Test
    public void testNONESigning_RSA_SHA256_serverSidePadding() throws Exception {
        LOG.info("testNONESigning_RSA_SHA256_serverSidePadding");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(plainText);
        byte[] hash = md.digest();

        final RequestContext context = new RequestContext();

        RequestMetadata.getInstance(context).put("USING_CLIENTSUPPLIED_HASH", "true");
        RequestMetadata.getInstance(context).put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-256");

        final SimplifiedResponse resp =
                sign(hash, tokenRSA,
                     createConfig("NONEwithRSA", null, null, true,
                                  "SHA-256"), context);
        assertSignedAndVerifiable(plainText, "SHA256withRSA", tokenRSA, resp);
    }
    
    /**
     * Test that Signing works and signature is verified when Signature algorithm is NONEwithECDSA and input is SHA-256 hash digest.
     * 
     * @throws Exception 
     */
     @Test
    public void testNONESigning_ECDSA_SHA256_structure() throws Exception {
         LOG.info("testNONESigning_ECDSA_SHA256_structure");
         // code example includes MessageDigest for the sake of completeness
         byte[] plainText = "some-data".getBytes("ASCII");
         MessageDigest md = MessageDigest.getInstance("SHA-256");
         md.update(plainText);
         byte[] hash = md.digest();
         SimplifiedResponse resp = sign(hash, tokenECDSA, createConfig("NONEwithECDSA"));
         assertSignedAndVerifiable(plainText, "SHA256withECDSA", tokenECDSA, resp);
    }

    /**
     * Test that Signing works and signature is verified when Signature algorithm is NONEwithECDSA and input is SHA-256 hash digest.
     * Using client-side request parameters.
     * 
     * @throws Exception 
     */
     @Test
    public void testNONESigning_ECDSA_SHA256_clientSideParams() throws Exception {
        LOG.info("testNONESigning_ECDSA_SHA256_clientSideParams");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(plainText);
        byte[] hash = md.digest();

        final RequestContext context = new RequestContext();

        RequestMetadata.getInstance(context).put("USING_CLIENTSUPPLIED_HASH", "true");
        RequestMetadata.getInstance(context).put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-256");

        SimplifiedResponse resp =
                sign(hash, tokenECDSA, createConfig("NONEwithECDSA", null, null,
                                                    true, "SHA-256"), context);
        assertSignedAndVerifiable(plainText, "SHA256withECDSA", tokenECDSA, resp);
    }
    
    /**
     * Test that Signing works and signature is verified when Signature algorithm is NONEwithRSA and input is SHA-384 hash digest.
     * 
     * @throws Exception 
     */
    @Test
    public void testNONESigning_RSA_SHA384_structure() throws Exception {
        LOG.info("testNONESigning_RSA_SHA384_structure");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-384");
        md.update(plainText);
        byte[] hash = md.digest();

        // Taken from RFC 3447, page 42 for SHA-384, create input for signing
        byte[] modifierBytes = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(modifierBytes);
        baos.write(hash);

        SimplifiedResponse resp = sign(baos.toByteArray(), tokenRSA, createConfig("NONEwithRSA"));
        assertSignedAndVerifiable(plainText, "SHA384withRSA", tokenRSA, resp);
    }

    /**
     * Test that Signing works and signature is verified when Signature algorithm is NONEwithRSA and input is SHA-384 hash digest.
     * Use server-side padding with the clientside request parameters.
     * 
     * @throws Exception 
     */
    @Test
    public void testNONESigning_RSA_SHA384_serverSidePadding() throws Exception {
        LOG.info("testNONESigning_RSA_SHA384_serverSidePadding");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-384");
        md.update(plainText);
        byte[] hash = md.digest();

        final RequestContext context = new RequestContext();

        RequestMetadata.getInstance(context).put("USING_CLIENTSUPPLIED_HASH", "true");
        RequestMetadata.getInstance(context).put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-384");

        final SimplifiedResponse resp =
                sign(hash, tokenRSA,
                     createConfig("NONEwithRSA", null, null, true,
                                  "SHA-384"), context);
        assertSignedAndVerifiable(plainText, "SHA384withRSA", tokenRSA, resp);
    }
    
    /**
     * Test that Signing works and signature is verified when Signature algorithm is NONEwithECDSA and input is SHA-384 hash digest.
     * 
     * @throws Exception 
     */
    @Test
    public void testNONESigning_ECDSA_SHA384_structure() throws Exception {
        LOG.info("testNONESigning_ECDSA_SHA384_structure");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-384");
        md.update(plainText);
        byte[] hash = md.digest();
        SimplifiedResponse resp = sign(hash, tokenECDSA, createConfig("NONEwithECDSA"));
        assertSignedAndVerifiable(plainText, "SHA384withECDSA", tokenECDSA, resp);
    }

    /**
     * Test that Signing works and signature is verified when Signature algorithm is NONEwithECDSA and input is SHA-384 hash digest.
     * Using client-side request parameters.
     * 
     * @throws Exception 
     */
     @Test
    public void testNONESigning_ECDSA_SHA384_clientSideParams() throws Exception {
        LOG.info("testNONESigning_ECDSA_SHA384_clientSideParams");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-384");
        md.update(plainText);
        byte[] hash = md.digest();

        final RequestContext context = new RequestContext();

        RequestMetadata.getInstance(context).put("USING_CLIENTSUPPLIED_HASH", "true");
        RequestMetadata.getInstance(context).put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-384");

        SimplifiedResponse resp =
                sign(hash, tokenECDSA, createConfig("NONEwithECDSA", null, null,
                                                    true, "SHA-384"), context);
        assertSignedAndVerifiable(plainText, "SHA384withECDSA", tokenECDSA, resp);
    }

    /**
     * Test that signing fails for NONEwithRSAandMGF1 when then request does 
     * not have the client-side request metadata properties.
     * 
     * @throws Exception 
     */
    @Test
    public void testNONESigning_RSAandMGF1_SHA384() throws Exception {
        LOG.info("testNONESigning_RSAandMGF1_SHA384");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-384");
        md.update(plainText);
        byte[] hash = md.digest();
        try {
            sign(hash, tokenRSA, createConfig("NONEwithRSAandMGF1"));
            fail("Should have failed as signature algorithm is NONEwithRSAandMGF1 but the request metadata properties were not supplied");
        } catch (IllegalRequestException ex) {
            assertEquals("NONEwithRSAandMGF1 is not supported without the request metadata properties for client-side hashing", ex.getMessage());
        }
    }

    /**
     * Test that Signing works and signature is verified when Signature algorithm is NONEwithRSAandMGF1 and input is SHA-384 hash digest.
     * 
     * @throws Exception 
     */
    @Test
    public void testNONESigning_RSAandMGF1_SHA384_clientSide() throws Exception {
        LOG.info("testNONESigning_RSAandMGF1_SHA384_clientSide");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-384");
        md.update(plainText);
        byte[] hash = md.digest();

        final RequestContext context = new RequestContext();
        RequestMetadata.getInstance(context).put("USING_CLIENTSUPPLIED_HASH", "true");
        RequestMetadata.getInstance(context).put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-384");

        WorkerConfig config = createConfig("NONEwithRSAandMGF1");
        config.setProperty("CLIENTSIDEHASHING", "true");
        config.setProperty("ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-384");

        SimplifiedResponse resp = sign(hash, tokenRSA, config, context);
        assertSignedAndVerifiable(plainText, "SHA384withRSAandMGF1", tokenRSA, resp);
    }
    
}
