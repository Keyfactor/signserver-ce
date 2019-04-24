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
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extension;
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
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;

/**
 * Unit tests for the PlainSigner class.
 *
 * @author Markus Kilås
 * @version $Id: PlainSignerTest.java 6124 2015-06-30 09:30:48Z netmackan $
 */
public class PlainSignerTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(PlainSignerTest.class);

    private static MockedCryptoToken tokenRSA;
    private static MockedCryptoToken tokenDSA;
    private static MockedCryptoToken tokenECDSA;

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
        GenericSignResponse resp = sign(plainText, tokenRSA, createConfig(null));
        assertSignedAndVerifiable(plainText, "SHA1withRSA", tokenRSA, resp);
    }

    /**
     * Test signing using an DSA key-pair.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_DSA() throws Exception {
        LOG.info("testNormalSigning_DSA");
        byte[] plainText = "some-data".getBytes("ASCII");
        GenericSignResponse resp = sign(plainText, tokenDSA, createConfig(null));
        assertSignedAndVerifiable(plainText, "SHA1withDSA", tokenDSA, resp);
    }

    /**
     * Test signing using an ECDSA key-pair.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_ECDSA() throws Exception {
        LOG.info("testNormalSigning_ECDSA");
        byte[] plainText = "some-data".getBytes("ASCII");
        GenericSignResponse resp = sign(plainText, tokenECDSA, createConfig(null));
        assertSignedAndVerifiable(plainText, "SHA1withECDSA", tokenECDSA, resp);
    }
    
    /**
     * Test signing using when SHA1withRSA is explicitly specified.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_SHA1withRSA() throws Exception {
        LOG.info("testNormalSigning_RSA");
        byte[] plainText = "some-data".getBytes("ASCII");
        GenericSignResponse resp = sign(plainText, tokenRSA, createConfig("SHA1withRSA"));
        assertSignedAndVerifiable(plainText, "SHA1withRSA", tokenRSA, resp);
    }

    /**
     * Test signing using when SHA1withDSA is explicitly specified.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_SHA1withDSA() throws Exception {
        LOG.info("testNormalSigning_DSA");
        byte[] plainText = "some-data".getBytes("ASCII");
        GenericSignResponse resp = sign(plainText, tokenDSA, createConfig("SHA1withDSA"));
        assertSignedAndVerifiable(plainText, "SHA1withDSA", tokenDSA, resp);
    }
    
    /**
     * Test signing using when SHA1withECDSA is explicitly specified.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_SHA1withECDSA() throws Exception {
        LOG.info("testNormalSigning_ECDSA");
        byte[] plainText = "some-data".getBytes("ASCII");
        GenericSignResponse resp = sign(plainText, tokenECDSA, createConfig("SHA1withECDSA"));
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
        GenericSignResponse resp = sign(plainText, tokenRSA, createConfig("SHA256withRSA"));
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
        GenericSignResponse resp = sign(plainText, tokenRSA, createConfig("SHA256withRSAandMGF1"));
        assertSignedAndVerifiable(plainText, "SHA256withRSAandMGF1", tokenRSA, resp);
    }

    /**
     * Test signing using when SHA256withDSA is explicitly specified.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_SHA256withDSA() throws Exception {
        LOG.info("testNormalSigning_DSA");
        byte[] plainText = "some-data".getBytes("ASCII");
        GenericSignResponse resp = sign(plainText, tokenDSA, createConfig("SHA256withDSA"));
        assertSignedAndVerifiable(plainText, "SHA256withDSA", tokenDSA, resp);
    }
    
    /**
     * Test signing using when SHA256withECDSA is explicitly specified.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_SHA256withECDSA() throws Exception {
        LOG.info("testNormalSigning_ECDSA");
        byte[] plainText = "some-data".getBytes("ASCII");
        GenericSignResponse resp = sign(plainText, tokenECDSA, createConfig("SHA256withECDSA"));
        assertSignedAndVerifiable(plainText, "SHA256withECDSA", tokenECDSA, resp);
    }
    
    private WorkerConfig createConfig(String signatureAlgorithm) throws Exception {
        return createConfig(signatureAlgorithm, null);
    }

    private WorkerConfig createConfig(final String signatureAlgorithm, final String logDigestAlgorithm) throws Exception {
        WorkerConfig config = new WorkerConfig();
        if (signatureAlgorithm != null) {
            config.setProperty("SIGNATUREALGORITHM", signatureAlgorithm);
        }
        if (logDigestAlgorithm != null) {
            config.setProperty("LOGREQUEST_DIGESTALGORITHM", logDigestAlgorithm);
        }
        return config;
    }

    private GenericSignResponse sign(final byte[] data, MockedCryptoToken token, WorkerConfig config) throws Exception {
        return sign(data, token, config, null);
    }
    
    private GenericSignResponse sign(final byte[] data, MockedCryptoToken token, WorkerConfig config, RequestContext requestContext) throws Exception {
        MockedPlainSigner instance = new MockedPlainSigner(token);
        instance.init(1, config, new SignServerContext(), null);

        if (requestContext == null) {
            requestContext = new RequestContext();
        }
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");

        GenericSignRequest request = new GenericSignRequest(100, data);
        GenericSignResponse res = (GenericSignResponse) instance.processData(request, requestContext);
        return res;
    }
    
    private void assertSignedAndVerifiable(byte[] plainText, String signatureAlgorithm, MockedCryptoToken token, GenericSignResponse resp) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(signatureAlgorithm, "BC");
        signature.initVerify(resp.getSignerCertificate());
        signature.update(plainText);
        assertTrue("consistent signature", signature.verify(resp.getProcessedData()));
    }
    
    private void assertRequestDigestMatches(byte[] plainText, String digestAlgorithm, GenericSignResponse resp, RequestContext context) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        assertEquals("digestAlg", digestAlgorithm, LogMap.getInstance(context).get("REQUEST_DIGEST_ALGORITHM"));
        
        final MessageDigest md = MessageDigest.getInstance(digestAlgorithm);
        final String expected = Hex.toHexString(md.digest(plainText));
        String actual = LogMap.getInstance(context).get("REQUEST_DIGEST");
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
        final byte[] plainText = "some-data".getBytes("ASCII");
        final GenericSignResponse resp = sign(plainText, tokenRSA, createConfig(null), context);

        assertRequestDigestMatches(plainText, "SHA256", resp, context);
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
        final GenericSignResponse resp = sign(plainText, tokenRSA, createConfig(null, "SHA1"), context);

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
        final GenericSignResponse resp = sign(plainText, tokenRSA, createConfig(null), context);

        final String expected = new String(Base64.encode(resp.getProcessedData()), "ASCII");
        assertEquals("responseEncoded", expected, LogMap.getInstance(context).get("RESPONSE_ENCODED"));
    }

}
