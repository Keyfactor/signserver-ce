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

import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import junit.framework.TestCase;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import net.jsign.DigestAlgorithm;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcPeImageData;
import net.jsign.pe.PEFile;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
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
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.util.Store;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.util.PathUtil;
import org.signserver.server.SignServerContext;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.testutils.ModulesTestCase;

/**
 * Unit tests for the MSAuthCodeCMSSigner.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class MSAuthCodeCMSSignerUnitTest {

    private static MockedCryptoToken tokenRSA;
    private static MockedCryptoToken tokenDSA;
    private static MockedCryptoToken tokenECDSA;
    
    private static File peFile;
    private static File msiFile;
    
    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        
        tokenRSA = MockUtils.createRSAToken();
        tokenDSA = MockUtils.createDSAToken();
        tokenECDSA = MockUtils.createECDSAToken();
        
        // Sample binaries to test with
        peFile = new File(PathUtil.getAppHome(), "res/test/HelloPE.exe");
        if (!peFile.exists()) {
            throw new Exception("Missing sample binary: " + peFile);
        }
        
        msiFile = new File(PathUtil.getAppHome(), "res/test/sample.msi");
        if (!msiFile.exists()) {
            throw new Exception("Missing sample MSI package: " + msiFile);
        }
    }
    
    /**
     * Test that setting CONTENTOID is not allowed (as this is hard-coded in
     * this signer).
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_contentOIDNotAllowed() throws Exception {
        final MSAuthCodeCMSSigner instance = new MockedMSAuthCodeCMSSigner(tokenRSA);
        final WorkerConfig config = createConfig();
        
        config.setProperty("CONTENTOID", "1.2.3.4");
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("CONTENTOID"));
    }
    
    /**
     * Test that setting ALLOW_CONTENTOID_OVERRIDE is not allowed to be set to
     * true (as content OID is always hard-coded in this signer).
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_contentOIDOverrideNotAllowed() throws Exception {
        final MSAuthCodeCMSSigner instance = new MockedMSAuthCodeCMSSigner(tokenRSA);
        final WorkerConfig config = createConfig();
        
        config.setProperty("ALLOW_CONTENTOID_OVERRIDE", "true");
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("fatalErrors: " + actualErrors, actualErrors.contains("CONTENTOID"));
    }
    
    /**
     * Test that explicitly not allowing overriding content OID is still
     * allowed.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_contentOIDOverrideFalseAllowed() throws Exception {
        final MSAuthCodeCMSSigner instance = new MockedMSAuthCodeCMSSigner(tokenRSA);
        final WorkerConfig config = createConfig();
        
        config.setProperty("ALLOW_CONTENTOID_OVERRIDE", "false");
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("no errors: " + actualErrors, instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Test that explicitly setting ALLOW_CONTENTOID_OVERRIDE to an empty value
     * (should be equivalent to false) is still allowed.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_contentOIDOverrideEmptyAllowed() throws Exception {
        final MSAuthCodeCMSSigner instance = new MockedMSAuthCodeCMSSigner(tokenRSA);
        final WorkerConfig config = createConfig();
        
        config.setProperty("ALLOW_CONTENTOID_OVERRIDE", "");
        instance.init(1, config, new SignServerContext(), null);

        String actualErrors = instance.getFatalErrors(null).toString();
        assertTrue("no errors: " + actualErrors, instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Test signing a pre-computed hash of a PE file with SHA1.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignPESHA1WithRSA() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SHA1WithRSA");
        
        final RequestContext requestContext = new RequestContext();
        final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA1");
        metadata.put("FILE_TYPE", "PE");
        
        signAndVerify(peFile, false, "SHA1", config, requestContext, tokenRSA);
    }
    
    /**
     * Test signing a pre-computed hash of an MSI file with SHA1.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignMSISHA1WithRSA() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SHA1WithRSA");
        
        final RequestContext requestContext = new RequestContext();
        final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA1");
        metadata.put("FILE_TYPE", "MSI");
        
        signAndVerify(msiFile, true, "SHA1", config, requestContext, tokenRSA);
    }
    
    /**
     * Test signing a pre-computed hash of a PE file with SHA256.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignPESHA256WithRSA() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SHA256WithRSA");
        
        final RequestContext requestContext = new RequestContext();
        final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-256");
        metadata.put("FILE_TYPE", "PE");
        
        signAndVerify(peFile, false, "SHA256", config, requestContext, tokenRSA);
    }
    
    /**
     * Test signing a pre-computed hash of a PE file with SHA256.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignPESHA256WithDSA() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SHA256WithDSA");
        
        final RequestContext requestContext = new RequestContext();
        final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-256");
        metadata.put("FILE_TYPE", "PE");
        
        signAndVerify(peFile, false, "SHA256", config, requestContext, tokenDSA);
    }
    
    /**
     * Test signing a pre-computed hash of a PE file with SHA256.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignPESHA256WithECDSA() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SHA256WithECDSA");
        
        final RequestContext requestContext = new RequestContext();
        final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-256");
        metadata.put("FILE_TYPE", "PE");
        
        signAndVerify(peFile, false, "SHA256", config, requestContext, tokenECDSA);
    }
    
    /**
     * Test signing a pre-computed hash of an MSI file with SHA256.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignMSISHA256WithRSA() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SHA256WithRSA");
        
        final RequestContext requestContext = new RequestContext();
        final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-256");
        metadata.put("FILE_TYPE", "MSI");
        
        signAndVerify(msiFile, true, "SHA256", config, requestContext, tokenRSA);
    }
    
    /**
     * Test signing a pre-computed hash of an MSI file with SHA256.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignMSISHA256WithDSA() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SHA256WithDSA");
        
        final RequestContext requestContext = new RequestContext();
        final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-256");
        metadata.put("FILE_TYPE", "MSI");
        
        signAndVerify(msiFile, true, "SHA256", config, requestContext, tokenDSA);
    }
    
    /**
     * Test signing a pre-computed hash of an MSI file with SHA256.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignMSISHA256WithECDSA() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SHA256WithECDSA");
        
        final RequestContext requestContext = new RequestContext();
        final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-256");
        metadata.put("FILE_TYPE", "MSI");
        
        signAndVerify(msiFile, true, "SHA256", config, requestContext, tokenECDSA);
    }
    
    /**
     * Test signing a pre-computed hash of a PE file with SHA512.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignPESHA512WithRSA() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SHA512WithRSA");
        
        final RequestContext requestContext = new RequestContext();
        final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-512");
        metadata.put("FILE_TYPE", "PE");
        
        signAndVerify(peFile, false, "SHA512", config, requestContext, tokenRSA);
    }
    
    /**
     * Test signing a pre-computed hash of a PE file with empty algorithm parameters.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignWithEmptyParams() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "  ");        
        
        final RequestContext requestContext = new RequestContext();
        final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA256");
        metadata.put("FILE_TYPE", "PE");
        
        signAndVerify(peFile, false, "SHA256", config, requestContext, tokenRSA);
    }
    
    /**
     * Test signing a pre-computed hash of an MSI file with SHA512.
     * 
     * @throws Exception 
     */
    @Test
    public void testSignMSISHA512WithRSA() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SHA512WithRSA");
        
        final RequestContext requestContext = new RequestContext();
        final RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-512");
        metadata.put("FILE_TYPE", "MSI");
        
        signAndVerify(msiFile, true, "SHA512", config, requestContext, tokenRSA);
    }
    
    private void signAndVerify(final File file, final boolean msi,
                               final String digestAlgo,
                               final WorkerConfig config,
                               final RequestContext requestContext,
                               final MockedCryptoToken token)
            throws Exception {
        final MessageDigest digest = MessageDigest.getInstance(digestAlgo);
        final byte[] hash;
        
        if (msi) {
            try (final POIFSFileSystem fs = new POIFSFileSystem(file)) {
                MSIUtils.traverseDirectory(fs, fs.getRoot(), digest);
            }
            hash = digest.digest();
        } else {
            try (final PEFile pe = new PEFile(file)) {
                hash = pe.computeDigest(DigestAlgorithm.of(digestAlgo));
            }
        }
        
        MockedMSAuthCodeCMSSigner instance = new MockedMSAuthCodeCMSSigner(token);
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
            DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, hash);
            
            final byte[] content = createSignedContent(digestInfo, msi);

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
            
        }
    }
    
    private byte[] createSignedContent(final DigestInfo digestInfo,
                                       final boolean msi) throws IOException {
        final SpcAttributeTypeAndOptionalValue sataov;
        
        if (msi) {
            final SpcSipInfo sipInfo = MSIUtils.createMSISpcSipInfo();
            sataov = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID, sipInfo);
        } else {
            sataov = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_PE_IMAGE_DATA_OBJID,
                                                          new SpcPeImageData());
        }
        
        SpcIndirectDataContent spcIndirectDataContent =
                new SpcIndirectDataContent(sataov, digestInfo);
        final byte[] idcBytes = spcIndirectDataContent.toASN1Primitive().getEncoded("DER");

        final byte[] content = new byte[idcBytes.length - 2];
        System.arraycopy(idcBytes, 2, content, 0, idcBytes.length - 2);

        return content;
    }
   
    private static WorkerConfig createConfig() {
        final WorkerConfig config = new WorkerConfig();
        config.setProperty(WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        return config;
    }
}
