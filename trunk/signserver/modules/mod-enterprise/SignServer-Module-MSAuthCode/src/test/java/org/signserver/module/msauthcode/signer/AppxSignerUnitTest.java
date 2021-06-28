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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.common.util.PathUtil;
import org.signserver.server.SignServerContext;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.testutils.ModulesTestCase;
import java.io.RandomAccessFile;
import org.signserver.module.msauthcode.common.AppxHelper;
import org.bouncycastle.util.encoders.Hex;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.cms.CMSAlgorithm;
import org.signserver.module.msauthcode.common.SpcSipInfo;

/**
 * Unit tests for the AppxSigner.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class AppxSignerUnitTest {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AppxSignerUnitTest.class);
    private static MockedCryptoToken tokenRSA;
    private static MockedCryptoToken tokenDSA;
    private static MockedCryptoToken tokenECDSA;
    private static File packageFile;

    private static final ASN1ObjectIdentifier ID_SHA1WITHDSA = new ASN1ObjectIdentifier("1.2.840.10040.4.3");
    private static final ASN1ObjectIdentifier ID_SHA256WITHDSA = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.2");

    private static final byte[] P7X_SIGNATURE = new byte[] {(byte) 0x50, (byte) 0x4b, (byte) 0x43, (byte) 0x58};
    
    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        
        tokenRSA = MockUtils.createRSAToken();
        tokenDSA = MockUtils.createDSAToken();
        tokenECDSA = MockUtils.createECDSAToken();

        packageFile = new File(PathUtil.getAppHome(), "res/test/HelloAppx.appx");
        if (!packageFile.exists()) {
            throw new Exception("Missing sample package file: " + packageFile);
        }
    }

    /**
     * Tests that setting both TSA_URL and TSA_WORKER gives a fatal error.
     * @throws java.lang.Exception
     */
    @Test
    public void testInit_noTSAURLandWorker() throws Exception {
        LOG.info("testInit_noTSAURLandWorker");
        WorkerConfig config = new ConfigBuilder().create();
        config.setProperty("TSA_URL", "https://example.com/tsa");
        config.setProperty("TSA_WORKER", "TimeStampSigner4");
        AppxSigner instance = new MockedAppxSigner(tokenRSA);
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
        WorkerConfig config = new ConfigBuilder().create();
        config.setProperty("TSA_URL", "https://example.com/tsa");
        config.setProperty("TSA_USERNAME", "user1");
        AppxSigner instance = new MockedAppxSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("TSA_PASSWORD"));
        
        config.setProperty("TSA_PASSWORD", "");
        instance = new MockedAppxSigner(tokenRSA);
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
        WorkerConfig config = new ConfigBuilder().create();
        config.setProperty("DIGESTALGORITHM", "_incorrect_value_");
        AppxSigner instance = new MockedAppxSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("DIGESTALGORITHM"));
    }

    /**
     * Test that explicitly setting timestamp format to AUTHENTICODE works.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_timestampFormatAuthenticode() throws Exception {
        LOG.info("testInit_incorrectDigestAlg");
        WorkerConfig config = new ConfigBuilder().create();
        config.setProperty("TIMESTAMP_FORMAT", "AUTHENTICODE");
        AppxSigner instance = new MockedAppxSigner(tokenRSA);
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
        WorkerConfig config = new ConfigBuilder().create();
        config.setProperty("TIMESTAMP_FORMAT", "RFC3161");
        AppxSigner instance = new MockedAppxSigner(tokenRSA);
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
        WorkerConfig config = new ConfigBuilder().create();
        config.setProperty("TIMESTAMP_FORMAT", "rfc3161");
        AppxSigner instance = new MockedAppxSigner(tokenRSA);
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
        WorkerConfig config = new ConfigBuilder().create();
        config.setProperty("TIMESTAMP_FORMAT", "_invalid_");
        AppxSigner instance = new MockedAppxSigner(tokenRSA);
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
        LOG.info("testInit_timestampFormatEmpty");
        WorkerConfig config = new ConfigBuilder().create();
        config.setProperty("TIMESTAMP_FORMAT", "");
        AppxSigner instance = new MockedAppxSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        assertTrue("no fatal errors", instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Test that setting timestamp format to an empty value with whitespace works.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_timestampFormatEmptyWithSpace() throws Exception {
        LOG.info("testInit_timestampFormatEmptyWithSpace");
        WorkerConfig config = new ConfigBuilder().create();
        config.setProperty("TIMESTAMP_FORMAT", " ");
        AppxSigner instance = new MockedAppxSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        assertTrue("no fatal errors", instance.getFatalErrors(null).isEmpty());
    }

    /**
     * Test that setting an empty value for NO_REQUEST_ARCHIVING works.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_noRequestArchivingEmpty() throws Exception {
        LOG.info("testInit_noRequestArchivingEmpty");
        WorkerConfig config = new ConfigBuilder().create();
        config.setProperty("NO_REQUEST_ARCHIVING", "");
        AppxSigner instance = new MockedAppxSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        assertTrue("no fatal errors", instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Test that setting "true" for NO_REQUEST_ARCHIVING works.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_noRequestArchivingTrue() throws Exception {
        LOG.info("testInit_noRequestArchivingTrue");
        WorkerConfig config = new ConfigBuilder().create();
        config.setProperty("NO_REQUEST_ARCHIVING", "true");
        AppxSigner instance = new MockedAppxSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        assertTrue("no fatal errors", instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Test that setting "false" for NO_REQUEST_ARCHIVING works.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_noRequestArchivingFalse() throws Exception {
        LOG.info("testInit_noRequestArchivingFalse");
        WorkerConfig config = new ConfigBuilder().create();
        config.setProperty("NO_REQUEST_ARCHIVING", "false");
        AppxSigner instance = new MockedAppxSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        assertTrue("no fatal errors", instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Test that setting "TRUE" (upper case) for NO_REQUEST_ARCHIVING works.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_noRequestArchivingTrueUpper() throws Exception {
        LOG.info("testInit_noRequestArchivingTrueUpper");
        WorkerConfig config = new ConfigBuilder().create();
        config.setProperty("NO_REQUEST_ARCHIVING", "TRUE");
        AppxSigner instance = new MockedAppxSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        assertTrue("no fatal errors", instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Test that setting "true " (invalid with extra space) for NO_REQUEST_ARCHIVING
     * results in a configuration error.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_noRequestArchivingInvalid() throws Exception {
        LOG.info("testInit_noRequestArchivingInvalid");
        WorkerConfig config = new ConfigBuilder().create();
        config.setProperty("NO_REQUEST_ARCHIVING", "true ");
        AppxSigner instance = new MockedAppxSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        assertTrue("should contain error",
                   instance.getFatalErrors(null).contains("Incorrect value for NO_REQUEST_ARCHIVING"));
    }

    /**
     * Test signing using an RSA key-pair.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_RSA() throws Exception {
        LOG.info("testNormalSigning_RSA");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(packageFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);) {
            SignatureResponse resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .create(), null, null, null);
            assertSignedAndNotTimestamped(resp, CMSAlgorithm.SHA256);
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
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(packageFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);) {
            SignatureResponse resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withSignatureAlgorithm("SHA1WithRSA")
                    .create(), null, null, null);
            assertSignedAndNotTimestamped(resp, CMSAlgorithm.SHA256); // Note: Maybe we should not default to SHA-256 in this case?
        }
    }

    /**
     * Test signing when configuration properties specified as empty value.
     *
     * @throws Exception
     */
    @Test
    public void testNormalSigning_EmptyParams() throws Exception {
        LOG.info("testNormalSigning_EmptySignatureAlgo");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(packageFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);) {
            SignatureResponse resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withSignatureAlgorithm("  ").withDigestAlgorithm("  ").withTimestampFormat("  ").create(), null, null, null);
            assertSignedAndNotTimestamped(resp, CMSAlgorithm.SHA256);
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
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(packageFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);) {
            SignatureResponse resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withSignatureAlgorithm("SHA256WithRSA")
                    .create(), null, null, null);
            assertSignedAndNotTimestamped(resp, CMSAlgorithm.SHA256);
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
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(packageFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);) {
            SignatureResponse resp = signData(requestData, responseData, tokenDSA, new ConfigBuilder()
                    .create(), null, null, null);
            assertSignedAndNotTimestamped(resp, CMSAlgorithm.SHA256);
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
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(packageFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);) {
            SignatureResponse resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withDigestAlgorithm("SHA-1")
                    .withSignatureAlgorithm("SHA256WithRSA")
                    .create(), null, null, null);
            assertSignedAndNotTimestamped(resp, CMSAlgorithm.SHA1);
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
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(packageFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);) {
            SignatureResponse resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withDigestAlgorithm("SHA-256")
                    .create(), null, null, null);
            assertSignedAndNotTimestamped(resp, CMSAlgorithm.SHA256);
        }
    }
    
        /**
     * Test signing when specified the SHA-384 digest algorithm.
     * @throws Exception 
     */
    @Test
    public void testNormalSigning_digestSHA384() throws Exception {
        LOG.info("testNormalSigning_digestSHA384");
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(packageFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);) {
            SignatureResponse resp = signData(requestData, responseData, tokenRSA, new ConfigBuilder()
                    .withDigestAlgorithm("SHA-384")
                    .withSignatureAlgorithm("SHA384withRSA")
                    .create(), null, null, null);
            assertSignedAndNotTimestamped(resp, CMSAlgorithm.SHA384);
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
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(packageFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);) {
            SignatureResponse resp = signData(requestData, responseData, tokenDSA, new ConfigBuilder()
                    .withSignatureAlgorithm("SHA256WithDSA")
                    .create(), null, null, null);
            assertSignedAndNotTimestamped(resp, CMSAlgorithm.SHA256);
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
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(packageFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);) {
            SignatureResponse resp = signData(requestData, responseData, tokenDSA, new ConfigBuilder()
                    .withSignatureAlgorithm("SHA1WithDSA")
                    .create(), null, null, null);
            assertSignedAndNotTimestamped(resp, CMSAlgorithm.SHA256); // Note: Maybe we should not default to SHA-256 in this case?
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
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(packageFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);) {
            SignatureResponse resp = signData(requestData, responseData, tokenECDSA, new ConfigBuilder()
                    .create(), null, null, null);
            assertSignedAndNotTimestamped(resp, CMSAlgorithm.SHA256);
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
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(packageFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);) {
            SignatureResponse resp = signData(requestData, responseData, tokenECDSA, new ConfigBuilder()
                    .withSignatureAlgorithm("SHA1WithECDSA")
                    .create(), null, null, null);
                assertSignedAndNotTimestamped(resp, CMSAlgorithm.SHA256);  // Note: Maybe we should not default to SHA-256 in this case?
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
                CloseableReadableData requestData = ModulesTestCase.createRequestDataKeepingFile(packageFile);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(true);) {
            SignatureResponse resp = signData(requestData, responseData, tokenECDSA, new ConfigBuilder()
                    .withSignatureAlgorithm("SHA256WithECDSA")
                    .create(), null, null, null);
            assertSignedAndNotTimestamped(resp, CMSAlgorithm.SHA256);
        }
    }

    private SignatureResponse signData(ReadableData requestData, WritableData responseData, MockedCryptoToken token, WorkerConfig config, RequestContext requestContext, String reqProgramName, String reqProgramURL) throws Exception {
        MockedAppxSigner instance = new MockedAppxSigner(token);
        instance.init(1, config, new SignServerContext(), null);

        if (requestContext == null) {
            requestContext = new RequestContext();
        }
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");

        SignatureRequest request = new SignatureRequest(100, requestData, responseData);
        SignatureResponse res = (SignatureResponse) instance.processData(request, requestContext);
        
        return res;
    }

    private void assertSignedAndNotTimestamped(final SignatureResponse res, final ASN1ObjectIdentifier expectedDigestAlgorithm) throws IOException, CMSException, OperatorCreationException, Exception {
        // Extract signature file (CMS)
        byte[] p7xFileContent;
        try (final ZipFile file = new ZipFile(res.getResponseData().getAsFile())) {
            final ZipEntry entry = file.getEntry("AppxSignature.p7x");
            final ByteArrayOutputStream bout = new ByteArrayOutputStream();
            IOUtils.copy(file.getInputStream(entry), bout);
            p7xFileContent = bout.toByteArray();
        }
        assertNotNull("extracted AppxSignature.p7x", p7xFileContent);
        
        Certificate signerCertificate = res.getSignerCertificate();
        
        // First 4 bytes are the magic
        final byte[] p7xMagic = new byte[4];
        System.arraycopy(p7xFileContent, 0, p7xMagic, 0, 4);
        assertEquals("p7x magic", new String(P7X_SIGNATURE, StandardCharsets.US_ASCII), new String(p7xMagic, StandardCharsets.US_ASCII));

        // Get the data after first 4 bytes
        final byte[] signedBytes = new byte[p7xFileContent.length - 4];
        System.arraycopy(p7xFileContent, 4, signedBytes, 0, signedBytes.length);

        final CMSSignedData signedData = new CMSSignedData(signedBytes);

        assertEquals("eContentType SpcIndirectDataContent", "1.3.6.1.4.1.311.2.1.4", signedData.getSignedContentTypeOID());

        final SignerInformation si = (SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();

        // Verify using the signer's certificate (the configured one)
        assertTrue("Verification using signer certificate",
                si.verify(new JcaSignerInfoVerifierBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signerCertificate.getPublicKey())));

        // Extract the content from the signedData and perform APPX file verification
        final SpcIndirectDataContent idcFromSignature = SpcIndirectDataContent.getInstance((ASN1Sequence) signedData.getSignedContent().getContent());
        LOG.info("Digest from signature: " + Hex.toHexString(idcFromSignature.messageDigest.getDigest()));
        
        // Calculate digest of file and verify the content
        try (
            RandomAccessFile rafInput = new RandomAccessFile(res.getResponseData().getAsFile(), "r");
            CloseableWritableData responseData = ModulesTestCase.createResponseData(true);
            RandomAccessFile rafOutput = new RandomAccessFile(responseData.getAsFile(), "rw");
        ) {
            final byte[] byteArrDigest = AppxHelper.calculateDigestForVerification(rafInput, rafOutput, expectedDigestAlgorithm.getId());
            LOG.info("Digest calculate from file: " + Hex.toHexString(byteArrDigest));

            final SpcSipInfo sipInfo = MSAuthCodeUtils.createAppxSpcSipInfo();
            final SpcIndirectDataContent idcCalculated = new SpcIndirectDataContent(new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID, sipInfo), new DigestInfo(new AlgorithmIdentifier(expectedDigestAlgorithm, DERNull.INSTANCE), byteArrDigest));
            
            assertEquals("idc algorithm id", idcCalculated.messageDigest.getAlgorithmId().getAlgorithm().getId(), idcFromSignature.messageDigest.getAlgorithmId().getAlgorithm().getId());
            assertEquals("idc digest value", Hex.toHexString(idcCalculated.messageDigest.getDigest()), Hex.toHexString(idcFromSignature.messageDigest.getDigest()));
        }
    }

}
