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
import java.io.RandomAccessFile;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import junit.framework.TestCase;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import net.jsign.DigestAlgorithm;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.selector.jcajce.JcaX509CertificateHolderSelector;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.util.PathUtil;
import org.signserver.module.msauthcode.common.AppxHelper;
import org.signserver.module.msauthcode.common.SpcSipInfo;
import org.signserver.server.SignServerContext;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.testutils.ModulesTestCase;

/**
 * Unit tests for the AppxCMSSigner.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class AppxCMSSignerUnitTest {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AppxSignerUnitTest.class);
    private static MockedCryptoToken tokenRSA;
    private static MockedCryptoToken tokenDSA;
    private static MockedCryptoToken tokenECDSA;
    private static File packageFile;
    
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
        AppxCMSSigner instance = new MockedAppxCMSSigner(tokenRSA);
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
        AppxCMSSigner instance = new MockedAppxCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("TSA_PASSWORD"));
        
        config.setProperty("TSA_PASSWORD", "");
        instance = new MockedAppxCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("expecting no fatalErrors: " + actualErrors, instance.getFatalErrors(null).isEmpty());
    }

    /**
     * Tests that setting CONTENT_OID is not allowed.
     * @throws java.lang.Exception
     */
    @Test
    public void testInit_CONTENTOID_NotAllowed() throws Exception {
        LOG.info("testInit_TSA_PASSWORD");
        WorkerConfig config = new ConfigBuilder().create();
        config.setProperty("CONTENTOID", "1.2.3.4");
        AppxCMSSigner instance = new MockedAppxCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("Specifying CONTENTOID is not supported"));
    }

    /**
     * Tests that setting CONTENT_OID is not allowed.
     * @throws java.lang.Exception
     */
    @Test
    public void testInit_ALLOW_CONTENTOID_OVERRIDE_NotAllowed() throws Exception {
        LOG.info("testInit_TSA_PASSWORD");
        WorkerConfig config = new ConfigBuilder().create();
        config.setProperty("ALLOW_CONTENTOID_OVERRIDE", "true");
        AppxCMSSigner instance = new MockedAppxCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("Allowing overriding CONTENTOID is not supported"));
    }

    /**
     * Test signing a pre-computed hash of an MSI file with SHA1.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignSHA1WithRSA() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SHA1WithRSA");
        
        final RequestContext requestContext = new RequestContext();
        final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-1");
        metadata.put("FILE_TYPE", "APPX");
        
        signAndVerify(packageFile, "SHA1", config, requestContext, tokenRSA);
    }

    /**
     * Test signing a pre-computed hash of an MSI file with SHA1.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignSHA256WithRSA() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SHA256WithRSA");
        
        final RequestContext requestContext = new RequestContext();
        final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-256");
        metadata.put("FILE_TYPE", "APPX");
        
        signAndVerify(packageFile, "SHA256", config, requestContext, tokenRSA);
    }

    /**
     * Test signing a pre-computed hash of an MSI file with SHA1.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignSHA512WithRSA() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SHA512WithRSA");
        
        final RequestContext requestContext = new RequestContext();
        final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-512");
        metadata.put("FILE_TYPE", "APPX");
        
        signAndVerify(packageFile, "SHA512", config, requestContext, tokenRSA);
    }

    /**
     * Test signing a pre-computed hash of an MSI file with SHA1.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignSHA256WithDSA() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SHA256WithDSA");
        
        final RequestContext requestContext = new RequestContext();
        final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-256");
        metadata.put("FILE_TYPE", "APPX");
        
        signAndVerify(packageFile, "SHA256", config, requestContext, tokenDSA);
    }

    /**
     * Test signing a pre-computed hash of an MSI file with SHA1.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignSHA256WithECDSA() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SHA256WithECDSA");
        
        final RequestContext requestContext = new RequestContext();
        final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-256");
        metadata.put("FILE_TYPE", "APPX");
        
        signAndVerify(packageFile, "SHA256", config, requestContext, tokenECDSA);
    }

    private void signAndVerify(final File file,
                               final String digestAlgo,
                               final WorkerConfig config,
                               final RequestContext requestContext,
                               final MockedCryptoToken token)
            throws Exception {
        byte[] hash;
        
        try (final RandomAccessFile rafOutput = new RandomAccessFile(File.createTempFile("out", "tmp"), "rw");
             final RandomAccessFile rafInput = new RandomAccessFile(file, "r")) {
            // Wrapper for tracking new central directory offset after repackaging Appx file
            AppxHelper.CentralDirectoryOffset offset = new AppxHelper.CentralDirectoryOffset();

            // Reconstructed central directory after repackaging Appx file
            ByteArrayOutputStream baosReconstructedCentralDirRecords = new ByteArrayOutputStream();

            // EOCD field data - used to reconstruct EOCD
            final AppxHelper.EocdField eocdValues = new AppxHelper.EocdField();

            hash = AppxHelper.produceSignatureInput(rafInput, rafOutput, digestAlgo, offset, baosReconstructedCentralDirRecords, eocdValues);
        }

        MockedAppxCMSSigner instance = new MockedAppxCMSSigner(token);
        instance.init(1, config, new SignServerContext(), null);
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(hash);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            SignatureRequest request = new SignatureRequest(100, requestData, responseData);
            SignatureResponse response = (SignatureResponse) instance.processData(request, requestContext);
         
            byte[] signedBytes = responseData.toReadableData().getAsByteArray();
            Certificate signerCertificate = response.getSignerCertificate();
            
            // Reconstruct the data "to be signed"
            DigestAlgorithm digestAlg = DigestAlgorithm.of(digestAlgo);
            ASN1ObjectIdentifier digestAlgOID = digestAlg.oid;
            DERNull derNull = DERNull.INSTANCE;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgOID, derNull);
            
            DigestInfo digestInfo = new DigestInfo(new AlgorithmIdentifier(algorithmIdentifier.getAlgorithm(), DERNull.INSTANCE), hash);

            final byte[] content = createSignedContent(digestInfo);

            final CMSSignedData signedData =
                    new CMSSignedData(new CMSProcessableByteArray(content), signedBytes);
            
            assertEquals("eContentType SpcIndirectDataContent", "1.3.6.1.4.1.311.2.1.4", signedData.getSignedContentTypeOID());

            final SignerInformation si = (SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();

            // Check certificate returned
            final X509Certificate configuredSignerCert = (X509Certificate) token.getCertificate(ICryptoTokenV4.PURPOSE_SIGN);
            assertNotNull("Signer certificate", signerCertificate);
            TestCase.assertEquals("same cert returned", signerCertificate, configuredSignerCert);
            
            final AlgorithmNameFinder algFinder = new DefaultAlgorithmNameFinder();
        
            final Attribute messageDigest =
                    si.getSignedAttributes().get(CMSAttributes.messageDigest);
            assertEquals("digest algorithm", digestAlgo,
                    algFinder.getAlgorithmName(si.getDigestAlgorithmID()));
            assertNotNull("message digest present", messageDigest);

            // Verify using the signer's certificate (the configured one)
            assertTrue("Verification using signer certificate",
                    si.verify(new JcaSignerInfoVerifierBuilder(new LegacyAuthenticodeDigestCalculatorProvider()).build(configuredSignerCert)));

            // Check that the signer's certificate is included
            Store certs = signedData.getCertificates();
            Collection matches = certs.getMatches(new JcaX509CertificateHolderSelector(configuredSignerCert));
            assertEquals("should match the configured certificate: " + matches, 1, matches.size());

            // Testing that the SID works
            Collection certCollection = certs.getMatches(si.getSID());
            assertTrue("Matched signer cert", si.getSID().match(new X509CertificateHolder(configuredSignerCert.getEncoded())));
            X509CertificateHolder certHolder = (X509CertificateHolder) certCollection.iterator().next();
            assertArrayEquals("same cert returned", certHolder.getEncoded(), configuredSignerCert.getEncoded());
            
        }
    }

    private byte[] createSignedContent(final DigestInfo digestInfo)
            throws IOException {
        final SpcSipInfo sipInfo = MSAuthCodeUtils.createAppxSpcSipInfo();

        AppxSpcIndirectDataContent spcIndirectDataContent =
                new AppxSpcIndirectDataContent(new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID, sipInfo), digestInfo);

        final byte[] idcBytes = spcIndirectDataContent.toASN1Primitive().getEncoded("DER");

        final byte[] signedContent = new byte[idcBytes.length - 2];
        System.arraycopy(idcBytes, 2, signedContent, 0, idcBytes.length - 2);

        LOG.debug("signed content: " + Hex.toHexString(signedContent));

        return signedContent;
    }
}
