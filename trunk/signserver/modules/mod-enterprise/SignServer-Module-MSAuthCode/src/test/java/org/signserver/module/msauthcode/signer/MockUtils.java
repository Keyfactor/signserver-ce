/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.msauthcode.signer;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertBuilderException;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;

/**
 * Common mock utilities used for MS auth code unit tests.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class MockUtils {
    
    private static final String signatureAlgorithm = "SHA256withRSA";
    private static final String caDN = "CN=Test CA";
    private static X509Certificate caCertificate;
    private static KeyPair caKeyPair;
    private static final long currentTime = System.currentTimeMillis();
    
    private static KeyPair createCAKeyPair()
            throws NoSuchAlgorithmException, NoSuchProviderException {
        if (caKeyPair == null) {
            caKeyPair = CryptoUtils.generateRSA(1024);
        }
        return caKeyPair;
    }
    
    private static X509Certificate createCA()
            throws NoSuchAlgorithmException, NoSuchProviderException,
                   CertificateException, CertBuilderException {
        if (caCertificate == null) {
            final KeyPair keyPair = createCAKeyPair();
            
            caCertificate
                    = new JcaX509CertificateConverter().getCertificate(new CertBuilder()
                            .setSelfSignKeyPair(keyPair)
                            .setNotBefore(new Date(currentTime - 120000))
                            .setSignatureAlgorithm(signatureAlgorithm)
                            .setIssuer(caDN)
                            .setSubject(caDN)
                            .build());
        }

        return caCertificate;
    }
    
    public static MockedCryptoToken createRSAToken()
            throws NoSuchAlgorithmException, NoSuchProviderException, CertificateException, CertBuilderException {
        final X509Certificate ca = createCA();
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
                    ca
                };
        return new MockedCryptoToken(signerKeyPairRSA.getPrivate(),
                                     signerKeyPairRSA.getPublic(),
                                     certChainRSA[0],
                                     Arrays.asList(certChainRSA), "BC");
    }
    
    public static MockedCryptoToken createDSAToken()
            throws NoSuchAlgorithmException, NoSuchProviderException,
                   CertificateException, CertBuilderException {
        final X509Certificate ca = createCA();
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
                    ca
                };
        return new MockedCryptoToken(signerKeyPairDSA.getPrivate(),
                                     signerKeyPairDSA.getPublic(),
                                     certChainDSA[0],
                                     Arrays.asList(certChainDSA), "BC");
    }
    
    public static MockedCryptoToken createECDSAToken()
            throws NoSuchAlgorithmException, NoSuchProviderException,
                   CertificateException, CertBuilderException,
                   InvalidAlgorithmParameterException {
        final X509Certificate ca = createCA();
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
                    ca
                };
        return new MockedCryptoToken(signerKeyPairECDSA.getPrivate(),
                                     signerKeyPairECDSA.getPublic(),
                                     certChainECDSA[0],
                                     Arrays.asList(certChainECDSA), "BC");

    }
}
