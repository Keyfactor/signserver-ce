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
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
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
import org.signserver.test.utils.mock.MockedServicesImpl;
import org.signserver.testutils.ModulesTestCase;

/**
 * Unit tests for the OpenPGPPlainSigner class.
 *
 * @author Vinay Singh 
 * @version $Id$
 */
public class OpenPGPPlainSignerUnitTest {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(OpenPGPPlainSignerUnitTest.class);

    private static MockedCryptoToken tokenRSA;
    private static MockedCryptoToken tokenDSA;
    private static MockedCryptoToken tokenECDSA;

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
        final Certificate[] certChainRSA
                = new Certificate[]{
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
        final Certificate[] certChainDSA
                = new Certificate[]{
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
        final Certificate[] certChainECDSA
                = new Certificate[]{
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
     * Test that providing an incorrect value for PGPPUBLICKEY gives a fatal
     * error.
     *
     * @throws Exception
     */
    @Test
    public void testInit_incorrectPgpPublicKeyValue() throws Exception {
        LOG.info("testInit_incorrectPgpPublicKeyValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("PGPPUBLICKEY", "_incorrect-value--");
        MockedOpenPGPPlainSigner instance = new MockedOpenPGPPlainSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("PGPPUBLICKEY"));
    }

    /**
     * Test that providing an incorrect value for SELFSIGNED_VALIDITY gives a
     * fatal error.
     *
     * @throws Exception
     */
    @Test
    public void testInit_incorrectSelfsignedValidityValue() throws Exception {
        LOG.info("testInit_incorrectSelfsignedValidityValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("SELFSIGNED_VALIDITY", "_incorrect-value--");
        MockedOpenPGPPlainSigner instance = new MockedOpenPGPPlainSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("SELFSIGNED_VALIDITY"));
    }

    /**
     * Test that providing an incorrect value for
     * GENERATE_REVOCATION_CERTIFICATE gives a fatal error.
     *
     * @throws Exception
     */
    @Test
    public void testInit_incorrectGenerateRevocationCertificateValue()
            throws Exception {
        LOG.info("testInit_incorrectGenerateRevocationCertificateValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("GENERATE_REVOCATION_CERTIFICATE", "_incorrect-value--");
        MockedOpenPGPPlainSigner instance = new MockedOpenPGPPlainSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("GENERATE_REVOCATION_CERTIFICATE"));
    }

    /**
     * Tests that no signing is performed when the worker is misconfigured.
     *
     * @throws java.lang.Exception
     */
    @Test(expected = SignServerException.class)
    public void testNoProcessOnFatalErrors() throws Exception {
        LOG.info("testNoProcessOnFatalErrors");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("PGPPUBLICKEY", "_incorrect-value--");
        MockedOpenPGPPlainSigner instance = new MockedOpenPGPPlainSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        sign(data, tokenRSA, config);
        fail("Should have thrown exception");
    }
                              
    private WorkerConfig createConfig(final String logDigestAlgorithm) throws Exception {
        return createConfig(logDigestAlgorithm, null);
    }

    private WorkerConfig createConfig(final String logDigestAlgorithm,
            final String doLogRequestDigest) throws Exception {
        WorkerConfig config = new WorkerConfig();
        
        if (logDigestAlgorithm != null) {
            config.setProperty("LOGREQUEST_DIGESTALGORITHM", logDigestAlgorithm);
        }
        if (doLogRequestDigest != null) {
            config.setProperty("DO_LOGREQUEST_DIGEST", doLogRequestDigest);
        }
        return config;
    }

    private SimplifiedResponse sign(final byte[] data, MockedCryptoToken token, WorkerConfig config) throws Exception {
        return sign(data, token, config, null);
    }

    private SimplifiedResponse sign(final byte[] data, MockedCryptoToken token, WorkerConfig config, RequestContext requestContext) throws Exception {
        MockedOpenPGPPlainSigner instance = new MockedOpenPGPPlainSigner(token);
        instance.init(1, config, new SignServerContext(), null);

        if (requestContext == null) {
            requestContext = new RequestContext();
        }
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(data);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);) {
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
     *
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
     * Tests that setting DO_LOGREQUEST_DIGEST to false results in no logging of
     * the request digest.
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
     *
     * @throws Exception
     */
    @Test
    public void testLogRequestDigestSHA1() throws Exception {
        LOG.info("testLogRequestDigestSHA1");
        final RequestContext context = new RequestContext();
        final byte[] plainText = "some-data".getBytes("ASCII");
        final SimplifiedResponse resp = sign(plainText, tokenRSA, createConfig("SHA1"), context);

        assertRequestDigestMatches(plainText, "SHA1", resp, context);
    }

    /**
     * Tests logging of the response.
     *
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
        MockedOpenPGPPlainSigner instance = new MockedOpenPGPPlainSigner(tokenRSA);
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
        MockedOpenPGPPlainSigner instance = new MockedOpenPGPPlainSigner(tokenRSA);
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
        MockedOpenPGPPlainSigner instance = new MockedOpenPGPPlainSigner(tokenRSA);
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
        MockedOpenPGPPlainSigner instance = new MockedOpenPGPPlainSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        assertTrue("no fatal errors", instance.getFatalErrors(null).isEmpty());
    }

    /**
     * Test that setting "true " (invalid with extra space) for
     * DO_LOGREQUEST_DIGEST results in a configuration error.
     *
     * @throws Exception
     */
    @Test
    public void testInit_noRequestArchivingInvalid() throws Exception {
        LOG.info("testInit_doLogrequestDigestInvalid");
        WorkerConfig config = new WorkerConfig();
        config.setProperty(WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        config.setProperty("DO_LOGREQUEST_DIGEST", "true ");
        MockedOpenPGPPlainSigner instance = new MockedOpenPGPPlainSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        assertTrue("should contain error: " + instance.getFatalErrors(null).toString(),
                instance.getFatalErrors(null).contains("Incorrect value for DO_LOGREQUEST_DIGEST"));
    }

    /**
     * Test that Signing works and signature is verified when Signature
     * algorithm is NONEwithRSA and input is SHA-512 hash digest.
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

        SimplifiedResponse resp = sign(baos.toByteArray(), tokenRSA, createConfig(null));
        assertSignedAndVerifiable(plainText, "SHA512withRSA", tokenRSA, resp);
    }

    /**
     * Test that Signing works and signature is verified when Signature
     * algorithm is NONEwithECDSA and input is SHA-512 hash digest.
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
        SimplifiedResponse resp = sign(hash, tokenECDSA, createConfig(null));
        assertSignedAndVerifiable(plainText, "SHA512withECDSA", tokenECDSA, resp);
    }
    
    /**
     * Test that Signing works and signature is verified when Signature
     * algorithm is NONEwithDSA and input is SHA-512 hash digest.
     *
     * @throws Exception
     */
    @Test
    public void testNONESigning_DSA_SHA512_structure() throws Exception {
        LOG.info("testNONESigning_DSA_SHA512_structure");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(plainText);
        byte[] hash = md.digest();
        SimplifiedResponse resp = sign(hash, tokenDSA, createConfig(null));
        assertSignedAndVerifiable(plainText, "SHA512withDSA", tokenDSA, resp);
    }

    /**
     * Test that Signing works and signature is verified when Signature
     * algorithm is NONEwithRSA and input is SHA-256 hash digest.
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

        SimplifiedResponse resp = sign(baos.toByteArray(), tokenRSA, createConfig(null));
        assertSignedAndVerifiable(plainText, "SHA256withRSA", tokenRSA, resp);
    }

    /**
     * Test that Signing works and signature is verified when Signature
     * algorithm is NONEwithECDSA and input is SHA-256 hash digest.
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
        SimplifiedResponse resp = sign(hash, tokenECDSA, createConfig(null));
        assertSignedAndVerifiable(plainText, "SHA256withECDSA", tokenECDSA, resp);
    }
    
    /**
     * Test that Signing works and signature is verified when Signature
     * algorithm is NONEwithDSA and input is SHA-256 hash digest.
     *
     * @throws Exception
     */
    @Test
    public void testNONESigning_DSA_SHA256_structure() throws Exception {
        LOG.info("testNONESigning_DSA_SHA256_structure");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(plainText);
        byte[] hash = md.digest();
        SimplifiedResponse resp = sign(hash, tokenDSA, createConfig(null));
        assertSignedAndVerifiable(plainText, "SHA256withDSA", tokenDSA, resp);
    }

    /**
     * Test that Signing works and signature is verified when Signature
     * algorithm is NONEwithRSA and input is SHA-384 hash digest.
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

        SimplifiedResponse resp = sign(baos.toByteArray(), tokenRSA, createConfig(null));
        assertSignedAndVerifiable(plainText, "SHA384withRSA", tokenRSA, resp);
    }

    /**
     * Test that Signing works and signature is verified when Signature
     * algorithm is NONEwithECDSA and input is SHA-384 hash digest.
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
        SimplifiedResponse resp = sign(hash, tokenECDSA, createConfig(null));
        assertSignedAndVerifiable(plainText, "SHA384withECDSA", tokenECDSA, resp);
    }
    
    /**
     * Test that Signing works and signature is verified when Signature
     * algorithm is NONEwithDSA and input is SHA-384 hash digest.
     *
     * @throws Exception
     */
    @Test
    public void testNONESigning_DSA_SHA384_structure() throws Exception {
        LOG.info("testNONESigning_DSA_SHA384_structure");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-384");
        md.update(plainText);
        byte[] hash = md.digest();
        SimplifiedResponse resp = sign(hash, tokenDSA, createConfig(null));
        assertSignedAndVerifiable(plainText, "SHA384withDSA", tokenDSA, resp);
    }

}
