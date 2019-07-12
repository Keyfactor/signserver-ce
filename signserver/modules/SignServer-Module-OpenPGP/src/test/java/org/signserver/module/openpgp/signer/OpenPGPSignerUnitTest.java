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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.openpgp.utils.ClearSignedFileProcessorUtils;
import org.signserver.server.IServices;
import org.signserver.server.SignServerContext;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.KeyUsageCounterServiceMock;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.test.utils.mock.MockedServicesImpl;
import org.signserver.testutils.ModulesTestCase;

/**
 * Unit tests for the OpenPGPSigner class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class OpenPGPSignerUnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(OpenPGPSignerUnitTest.class);

    private static MockedCryptoToken tokenRSA;
    private static MockedCryptoToken tokenDSA;
    private static MockedCryptoToken tokenECDSA;
    private static MockedCryptoToken tokenNonExisting; 
         
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

        // Simulating a non-existing key
        tokenNonExisting = new MockedCryptoToken();
    }        

    /**
     * Test that providing an incorrect value for DIGEST_ALGORITHM
     * gives a fatal error.
     * @throws Exception
     */
    @Test
    public void testInit_incorrectDigestAlgorithmValue() throws Exception {
        LOG.info("testInit_incorrectDigestAlgorithmValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("DIGEST_ALGORITHM", "_incorrect-value--");
        OpenPGPSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("DIGEST_ALGORITHM"));
    }
    
    /**
     * Test that providing an incorrect value for DETACHEDSIGNATURE gives a
     * fatal error.
     *
     * @throws Exception
     */
    @Test
    public void testInit_incorrectDetachedSignatureValue() throws Exception {
        LOG.info("testInit_incorrectDetachedSignatureValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("DETACHEDSIGNATURE", "_incorrect-value--");
        OpenPGPSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("DETACHEDSIGNATURE"));
    }
    
    /**
     * Test that not providing DETACHEDSIGNATURE gives a fatal error.
     *
     * @throws Exception
     */
    @Test
    public void testInit_NoDetachedSignatureValue() throws Exception {
        LOG.info("testInit_incorrectDetachedSignatureValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        OpenPGPSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("DETACHEDSIGNATURE"));
    }
    
    /**
     * Test that setting RESPONSE_FORMAT as BINARY & DETACHEDSIGNATURE as FALSE
     * gives a fatal error.
     *
     * @throws Exception
     */
    @Test
    public void testInit_DetachedFalseWithBinaryResponseFormat() throws Exception {
        LOG.info("testInit_incorrectDetachedSignatureValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("DETACHEDSIGNATURE", "FALSE");
        config.setProperty("RESPONSE_FORMAT", "BINARY");
        OpenPGPSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("DETACHEDSIGNATURE"));
    }

    /**
     * Test that providing an incorrect value for GENERATE_REVOCATION_CERTIFICATE
     * gives a fatal error.
     * @throws Exception
     */
    @Test
    public void testInit_incorrectGenerateRevocationCertificateValue()
            throws Exception {
        LOG.info("testInit_incorrectGenerateRevocationCertificateValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("GENERATE_REVOCATION_CERTIFICATE", "_incorrect-value--");
        OpenPGPSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("GENERATE_REVOCATION_CERTIFICATE"));
    }
    
    /**
     * Test that providing an incorrect value for RESPONSE_FORMAT
     * gives a fatal error.
     * @throws Exception
     */
    @Test
    public void testInit_incorrectResponseFormatValue() throws Exception {
        LOG.info("testInit_incorrectResponseFormatValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("RESPONSE_FORMAT", "_incorrect-value--");
        OpenPGPSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("RESPONSE_FORMAT"));
    }

    /**
     * Test that providing an incorrect value for PGPPUBLICKEY gives a fatal
     * error.
     * @throws Exception
     */
    @Test
    public void testInit_incorrectPgpPublicKeyValue() throws Exception {
        LOG.info("testInit_incorrectPgpPublicKeyValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("PGPPUBLICKEY", "_incorrect-value--");
        OpenPGPSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("PGPPUBLICKEY"));
    }
    
    /**
     * Test that providing an incorrect value for SELFSIGNED_VALIDITY gives a 
     * fatal error.
     * @throws Exception
     */
    @Test
    public void testInit_incorrectSelfsignedValidityValue() throws Exception {
        LOG.info("testInit_incorrectSelfsignedValidityValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("SELFSIGNED_VALIDITY", "_incorrect-value--");
        OpenPGPSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("SELFSIGNED_VALIDITY"));
    }
    
    
    // TODO: more testInit_*
    
    
    /**
     * Tests that no signing is performed when the worker is misconfigured.
     * @throws java.lang.Exception
     */
    @Test(expected = SignServerException.class)
    public void testNoProcessOnFatalErrors() throws Exception {
        LOG.info("testNoProcessOnFatalErrors");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("DIGEST_ALGORITHM", "_incorrect-value--");
        OpenPGPSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        signAndVerify(data, tokenRSA, config, null, false, true);
        fail("Should have thrown exception");
    }
    
    
    private void signWithAlgorithm(MockedCryptoToken token, String digestAlgorithmConfig, int expectedDigestAlgorithm, boolean detachedSignature) throws Exception {
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");        
        config.setProperty("DETACHEDSIGNATURE", Boolean.toString(detachedSignature));
        if (digestAlgorithmConfig != null) {
            config.setProperty(OpenPGPSigner.PROPERTY_DIGEST_ALGORITHM, digestAlgorithmConfig);
        }
        boolean armored = true;
        
        // data with new line
        final byte[] data = "my-data\r\n".getBytes("ASCII");
        
        SimplifiedResponse response = signAndVerify(data, token, config, new RequestContext(), detachedSignature, armored);
        assertEquals("hash algorithm", expectedDigestAlgorithm, response.getSignature().getHashAlgorithm());
    }

    /**
     * Tests signing with RESPONSE_FORMAT=BINARY.
     * @throws Exception 
     */
    @Test
    public void testSignWithResponseFormatBinary() throws Exception {
        LOG.info("testSignWithResponseFormatBinary");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("DETACHEDSIGNATURE", "TRUE");
        config.setProperty("RESPONSE_FORMAT", "BINARY");
        boolean armored = false;
        OpenPGPSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        signAndVerify(data, tokenRSA, config, null, true, armored);
    }
    
    /**
     * Tests detached signing with RESPONSE_FORMAT=ARMORED.
     *
     * @throws Exception
     */
    @Test
    public void testDetachedSignWithResponseFormatArmored() throws Exception {
        LOG.info("testDetachedSignWithResponseFormatArmored");
        boolean detachedSignature = true;
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("RESPONSE_FORMAT", "ARMORED");
        config.setProperty("DETACHEDSIGNATURE", Boolean.toString(detachedSignature));
        boolean armored = true;
        OpenPGPSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);        
        
        final byte[] data = "my-data".getBytes("ASCII");
        signAndVerify(data, tokenRSA, config, null, detachedSignature, armored);
    }
    
    /**
     * Tests clear text signing with RESPONSE_FORMAT=ARMORED.
     *
     * @throws Exception
     */
    @Test
    public void testClearTextSignWithResponseFormatArmored() throws Exception {
        LOG.info("testClearTextSignWithResponseFormatArmored");
        boolean detachedSignature = false;
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("RESPONSE_FORMAT", "ARMORED");
        config.setProperty("DETACHEDSIGNATURE", Boolean.toString(detachedSignature));
        boolean armored = true;
        OpenPGPSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        // data without new line
        final byte[] data = "my-data".getBytes("ASCII");
        signAndVerify(data, tokenRSA, config, null, detachedSignature, armored);
    }
    
    /**
     * Test default signing with RSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSign_RSA_default_SHA256() throws Exception {
        LOG.info("testDetachedSign_RSA_default_SHA256");
        signWithAlgorithm(tokenRSA, null, PGPUtil.SHA256, true);
    }
    
    /**
     * Test default signing with RSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testClearTextSign_RSA_default_SHA256() throws Exception {
        LOG.info("testClearTextSign_RSA_default_SHA256");
        signWithAlgorithm(tokenRSA, null, PGPUtil.SHA256, false);
    }
    
    /**
     * Test signing with SHA1 and RSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSign_RSA_SHA1() throws Exception {
        LOG.info("testDetachedSign_RSA_SHA1");
        signWithAlgorithm(tokenRSA, "SHA1", PGPUtil.SHA1, true);
    }
    
    /**
     * Test signing with SHA1 and RSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testClearTextSign_RSA_SHA1() throws Exception {
        LOG.info("testClearTextSign_RSA_SHA1");
        signWithAlgorithm(tokenRSA, "SHA1", PGPUtil.SHA1, false);
    }
    
    /**
     * Test signing with SHA-224 and RSA.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSign_RSA_SHA224() throws Exception {
        LOG.info("testDetachedSign_RSA_SHA224");
        signWithAlgorithm(tokenRSA, "SHA-224", PGPUtil.SHA224, true);
    }    // Note: currently ArmoredOutputStream does not support SHA-224 signature algorithm in scenario of producing clear text signature but this test produces detached signature

    
    /**
     * Test signing with SHA-384 and RSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSign_RSA_SHA384() throws Exception {
        LOG.info("testDetachedSign_RSA_SHA384");
        signWithAlgorithm(tokenRSA, "SHA-384", PGPUtil.SHA384, true);
    }
    
    /**
     * Test signing with SHA-384 and RSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testClearTextSign_RSA_SHA384() throws Exception {
        LOG.info("testClearTextSign_RSA_SHA384");
        signWithAlgorithm(tokenRSA, "SHA-384", PGPUtil.SHA384, false);
    }
    
    /**
     * Test signing with SHA-512 and RSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSign_RSA_SHA512() throws Exception {
        LOG.info("testDetachedSign_RSA_SHA512");
        signWithAlgorithm(tokenRSA, "SHA-512", PGPUtil.SHA512, true);
    }
    
    /**
     * Test signing with SHA-512 and RSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testClearTextSign_RSA_SHA512() throws Exception {
        LOG.info("testClearTextSign_RSA_SHA512");
        signWithAlgorithm(tokenRSA, "SHA-512", PGPUtil.SHA512, false);
    }
    
    /**
     * Test signing with SHA-512 by number and RSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSign_RSA_SHA512_byNumber() throws Exception {
        LOG.info("testDetachedSign_RSA_SHA512_byNumber");
        signWithAlgorithm(tokenRSA, "10", PGPUtil.SHA512, true); // 10 = SHA-512
    }
    
    /**
     * Test signing with SHA-512 by number and RSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testClearTextSign_RSA_SHA512_byNumber() throws Exception {
        LOG.info("testClearTextSign_RSA_SHA512_byNumber");
        signWithAlgorithm(tokenRSA, "10", PGPUtil.SHA512, false); // 10 = SHA-512
    }
    
    /**
     * Test default signing with DSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSign_DSA_default_SHA256() throws Exception {
        LOG.info("testDetachedSign_DSA_default_SHA256");
        signWithAlgorithm(tokenDSA, null, PGPUtil.SHA256, true);
    }
    
    /**
     * Test default signing with DSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testClearTextSign_DSA_default_SHA256() throws Exception {
        LOG.info("testClearTextSign_DSA_default_SHA256");
        signWithAlgorithm(tokenDSA, null, PGPUtil.SHA256, false);
    }
    
    /**
     * Test signing with SHA1 and DSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSign_DSA_SHA1() throws Exception {
        LOG.info("testDetachedSign_DSA_SHA1");
        signWithAlgorithm(tokenDSA, "SHA1", PGPUtil.SHA1, true);
    }
    
    /**
     * Test signing with SHA1 and DSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testClearTextSign_DSA_SHA1() throws Exception {
        LOG.info("testClearTextSign_DSA_SHA1");
        signWithAlgorithm(tokenDSA, "SHA1", PGPUtil.SHA1, false);
    }
    
    /**
     * Test signing with SHA-224 and DSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSign_DSA_SHA224() throws Exception {
        LOG.info("testDetachedSign_DSA_SHA224");
        signWithAlgorithm(tokenDSA, "SHA-224", PGPUtil.SHA224, true);
    }
    
    /**
     * Test signing with SHA-384 and DSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSign_DSA_SHA384() throws Exception {
        LOG.info("testDetachedSign_DSA_SHA384");
        signWithAlgorithm(tokenDSA, "SHA-384", PGPUtil.SHA384, true);
    }
    
    /**
     * Test signing with SHA-384 and DSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testClearTextSign_DSA_SHA384() throws Exception {
        LOG.info("testClearTextSign_DSA_SHA384");
        signWithAlgorithm(tokenDSA, "SHA-384", PGPUtil.SHA384, false);
    }
    
    /**
     * Test signing with SHA-512 and DSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSign_DSA_SHA512() throws Exception {
        LOG.info("testDetachedSign_DSA_SHA512");
        signWithAlgorithm(tokenDSA, "SHA-512", PGPUtil.SHA512, true);
    }
    
    /**
     * Test signing with SHA-512 and DSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testClearTextSign_DSA_SHA512() throws Exception {
        LOG.info("testClearTextSign_DSA_SHA512");
        signWithAlgorithm(tokenDSA, "SHA-512", PGPUtil.SHA512, false);
    }
    
    /**
     * Test default signing with ECDSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSign_ECDSA_default_SHA256() throws Exception {
        LOG.info("testDetachedSign_ECDSA_default_SHA256");
        signWithAlgorithm(tokenECDSA, null, PGPUtil.SHA256, true);
    }
    
    @Test
    public void testClearTextSign_ECDSA_default_SHA256() throws Exception {
        LOG.info("testClearTextSign_ECDSA_default_SHA256");
        signWithAlgorithm(tokenECDSA, null, PGPUtil.SHA256, false);
    }
    
    /**
     * Test signing with SHA1 and ECDSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSign_ECDSA_SHA1() throws Exception {
        LOG.info("testDetachedSign_ECDSA_SHA1");
        signWithAlgorithm(tokenECDSA, "SHA1", PGPUtil.SHA1, true);
    }
    
    /**
     * Test signing with SHA1 and ECDSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testClearTextSign_ECDSA_SHA1() throws Exception {
        LOG.info("testClearTextSign_ECDSA_SHA1");
        signWithAlgorithm(tokenECDSA, "SHA1", PGPUtil.SHA1, false);
    }
    
    /**
     * Test signing with SHA-224 and ECDSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSign_ECDSA_SHA224() throws Exception {
        LOG.info("testDetachedSign_ECDSA_SHA224");
        signWithAlgorithm(tokenECDSA, "SHA-224", PGPUtil.SHA224, true);
    }
    
    /**
     * Test signing with SHA-384 and ECDSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSign_ECDSA_SHA384() throws Exception {
        LOG.info("testDetachedSign_ECDSA_SHA384");
        signWithAlgorithm(tokenECDSA, "SHA-384", PGPUtil.SHA384, true);
    }
    
    /**
     * Test signing with SHA-384 and ECDSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testClearTextSign_ECDSA_SHA384() throws Exception {
        LOG.info("testClearTextSign_ECDSA_SHA384");
        signWithAlgorithm(tokenECDSA, "SHA-384", PGPUtil.SHA384, false);
    }
    
    /**
     * Test signing with SHA-512 and ECDSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSign_ECDSA_SHA512() throws Exception {
        LOG.info("testDetachedSign_ECDSA_SHA512");
        signWithAlgorithm(tokenECDSA, "SHA-512", PGPUtil.SHA512, true);
    }
    
    /**
     * Test signing with SHA-512 and ECDSA.
     * @throws java.lang.Exception
     */
    @Test
    public void testClearTextSign_ECDSA_SHA512() throws Exception {
        LOG.info("testClearTextSign_ECDSA_SHA512");
        signWithAlgorithm(tokenECDSA, "SHA-512", PGPUtil.SHA512, false);
    }

    /**
     * Tests that worker status is active with the default configuration.
     * @throws Exception 
     */
    @Test
    public void testGetStatus_active() throws Exception {
        final OpenPGPSigner instance = createMockSigner(tokenRSA);
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("DETACHEDSIGNATURE", "TRUE");
        instance.init(1, config, new SignServerContext(null, new KeyUsageCounterServiceMock()), null);
        
        final IServices services = new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, new GlobalConfigurationSessionMock());
        
        WorkerStatusInfo status = instance.getStatus(new ArrayList<>(), services);
        List<String> fatalErrors = status.getFatalErrors();
        assertEquals("Status ACTIVE", "[]", fatalErrors.toString());
    }

    /**
     * Tests that there is a fatal error if key is not available.
     * @throws Exception 
     */
    @Test
    public void testGetStatus_wrongKey() throws Exception {
        final OpenPGPSigner instance = createMockSigner(tokenNonExisting);
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("DETACHEDSIGNATURE", "TRUE");
        instance.init(1, config, new SignServerContext(null, new KeyUsageCounterServiceMock()), null);
        
        final IServices services = new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, new GlobalConfigurationSessionMock());
        
        WorkerStatusInfo status = instance.getStatus(new ArrayList<>(), services);
        List<String> fatalErrors = status.getFatalErrors();
        assertEquals("Status OFFLINE", "[Crypto Token is disconnected]", fatalErrors.toString());
    }

    protected OpenPGPSigner createMockSigner(final MockedCryptoToken token) {
        return new MockedOpenPGPSigner(token);
    }
    
    private SimplifiedResponse signAndVerify(final byte[] data, MockedCryptoToken token, WorkerConfig config, RequestContext requestContext, boolean detached, boolean armored) throws Exception {
        if (detached) {
            return signAndVerifyDetachedSignature(data, token, config, requestContext, armored);
        } else {
            return signAndVerifyClearTextSignature(data, token, config, requestContext);
        }
    }
    
    /**
     * Helper method signing the given data.
     * 
     * @param data Data (data to be signed)
     * @param token
     * @param config
     * @param requestContext
     * @param detached If true, assume detached
     * @return
     * @throws Exception 
     */
    private SimplifiedResponse signAndVerifyDetachedSignature(final byte[] data, MockedCryptoToken token, WorkerConfig config, RequestContext requestContext, boolean armored) throws Exception {
        final OpenPGPSigner instance = createMockSigner(token);
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
            String signed = new String(signedBytes, StandardCharsets.US_ASCII);
                
            if (armored) {
                assertTrue("expecting armored: " + signed, signed.startsWith("-----BEGIN PGP SIGNATURE-----"));
            } else {
                assertFalse("expecting binary: " + signed, signed.startsWith("-----BEGIN PGP SIGNATURE-----"));
            }

            PGPSignature sig;
            
            try (InputStream in = createInputStream(new ByteArrayInputStream(signedBytes), armored)) {
                JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(in);
                PGPSignatureList p3 = (PGPSignatureList) objectFactory.nextObject();
                sig = p3.get(0);
            }
            
            final JcaPGPKeyConverter conv = new JcaPGPKeyConverter();
            final X509Certificate x509Cert = (X509Certificate) token.getCertificate(0);
            final PGPPublicKey pgpPublicKey = conv.getPGPPublicKey(getKeyAlg(x509Cert), x509Cert.getPublicKey(), x509Cert.getNotBefore());

            sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pgpPublicKey);
            sig.update(data);
            
            assertTrue("verified", sig.verify());
            
            return new SimplifiedResponse(signedBytes, sig, pgpPublicKey);
        }
    }
    
    /**
     * Helper method signing the given data and producing the clear text
     * signature (either the actual data to be signed or if the signer or
     * request implies client-side hashing, the pre-computed hash) and the
     * original data. When detached mode is assumed, the originalData is used to
     * verify the signature.
     *
     * @param data Data (data to be signed, or pre-computed hash)
     * @param originalData Original data (either the actual data or the data
     * that was pre-hashed)
     * @param token
     * @param config
     * @param requestContext
     * @param detached If true, assume detached
     * @return
     * @throws Exception
     */
    private SimplifiedResponse signAndVerifyClearTextSignature(final byte[] data, final MockedCryptoToken token, final WorkerConfig config, RequestContext requestContext) throws Exception {
        final OpenPGPSigner instance = createMockSigner(token);
        instance.init(1, config, new SignServerContext(), null);

        if (requestContext == null) {
            requestContext = new RequestContext();
        }
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");
        final File resultFile = File.createTempFile("resultFile", "txt");

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(data);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);) {
            SignatureRequest request = new SignatureRequest(100, requestData, responseData);
            SignatureResponse response = (SignatureResponse) instance.processData(request, requestContext);

            byte[] signedBytes = responseData.toReadableData().getAsByteArray();
            String signed = new String(signedBytes, StandardCharsets.US_ASCII);

            assertTrue("expecting armored: " + signed, signed.startsWith("-----BEGIN PGP SIGNED MESSAGE-----"));

            PGPSignature sig;            

            ArmoredInputStream aIn = new ArmoredInputStream(new ByteArrayInputStream(signedBytes));
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

            final JcaPGPKeyConverter conv = new JcaPGPKeyConverter();
            final X509Certificate x509Cert = (X509Certificate) token.getCertificate(0);
            final PGPPublicKey pgpPublicKey = conv.getPGPPublicKey(getKeyAlg(x509Cert), x509Cert.getPublicKey(), x509Cert.getNotBefore());

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

            return new SimplifiedResponse(signedBytes, sig, pgpPublicKey);
        } finally {
            FileUtils.deleteQuietly(resultFile);
        }
    }
    
    private int getKeyAlg(X509Certificate x509Cert) throws SignServerException {
        final int keyAlg;
        switch (x509Cert.getPublicKey().getAlgorithm()) {
            case "RSA":
                keyAlg = PublicKeyAlgorithmTags.RSA_SIGN;
                break;
            case "EC":
                keyAlg = PublicKeyAlgorithmTags.ECDSA;
                break;
            case "DSA":
                keyAlg = PublicKeyAlgorithmTags.DSA;
                break;
            default:
                throw new SignServerException("Unsupported key algorithm: " + x509Cert.getPublicKey().getAlgorithm());
        }
        return keyAlg;
    }
    
    private BCPGInputStream createInputStream(InputStream in, boolean armored) throws IOException {
        return new BCPGInputStream(armored ? new ArmoredInputStream(in) : in);
    }

}
