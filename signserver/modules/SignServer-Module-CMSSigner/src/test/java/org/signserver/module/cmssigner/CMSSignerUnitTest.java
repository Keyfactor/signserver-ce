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

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.util.encoders.Hex;
import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.server.SignServerContext;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.test.utils.mock.MockedServicesImpl;
import org.signserver.testutils.ModulesTestCase;

/**
 * Unit tests for the CMSSigner class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CMSSignerUnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CMSSignerUnitTest.class);

    private static MockedCryptoToken tokenRSA;

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        final KeyPair signerKeyPair;
        final String signatureAlgorithm;
        signerKeyPair = CryptoUtils.generateRSA(1024);
        signatureAlgorithm = "SHA1withRSA";
        final Certificate[] certChain =
                new Certificate[] {new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSelfSignKeyPair(signerKeyPair).
                        setNotBefore(new Date()).
                        setSignatureAlgorithm(signatureAlgorithm)
                        .build())};
        final Certificate signerCertificate = certChain[0];
        tokenRSA = new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), "BC");
    }

    /**
     * Test that providing an incorrect value for DETACHEDSIGNATURE
     * gives a fatal error.
     * @throws Exception
     */
    @Test
    public void testInit_incorrectDetachedSignatureValue() throws Exception {
        LOG.info("testInit_incorrectDetachedSignatureValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DETACHEDSIGNATURE", "_incorrect-value--");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("DETACHEDSIGNATURE"));
    }
    
    /**
     * Test that providing an incorrect value for CLIENTSIDEHASHING gives
     * a fatal error.
     * @throws Exception 
     */
    @Test
    public void testInit_incorrectClientSideHashingValue() throws Exception {
        LOG.info("testInit_incorrectClientSideHashingValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CLIENTSIDEHASHING", "_incorrect-value--");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("CLIENTSIDEHASHING"));
    }

    /**
     * Test that providing an incorrect value for ALLOW_DETACHEDSIGNATURE_OVERRIDE
     * gives a fatal error.
     * @throws Exception
     */
    @Test
    public void testInit_incorrectAllowDetachedSignatureOverrideValue() throws Exception {
        LOG.info("testInit_incorrectAllowDetachedSignatureOverrideValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("ALLOW_DETACHEDSIGNATURE_OVERRIDE", "_incorrect-value--");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("ALLOW_DETACHEDSIGNATURE_OVERRIDE"));
    }
    
    /**
     * Test that providing an incorrect value for ALLOW_CLIENTSIDESHASHING_OVERRIDE
     * gives a fatal error.
     * @throws Exception
     */
    @Test
    public void testInit_incorrectAllowClientSideHashingOverrideValue() throws Exception {
        LOG.info("testInit_incorrectAllowClientSideHashingOverrideValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("ALLOW_CLIENTSIDEHASHING_OVERRIDE", "_incorrect-value--");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("ALLOW_CLIENTSIDEHASHING_OVERRIDE"));
    }

    /**
     * Test that specifying CLIENTSIDEHASHING without setting
     * ACCEPTED_HASH_DIGEST_ALGORITHMS is not allowed.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_incorrectClientSideHashingNoAcceptedDigestAlgorithms() throws Exception {
        LOG.info("testInit_incorrectClientSideHashingNoAcceptedDigestAlgorithms");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CLIENTSIDEHASHING", "true");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("Must specify ACCEPTED_HASH_DIGEST_ALGORITHMS"));
    }
    
    /**
     * Test that specifying ALLOW_CLIENTSIDEHASHING_OVERRIDE without setting
     * ACCEPTED_HASH_DIGEST_ALGORITHMS is not allowed.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_incorrectAllowClientSideHashingOverrodeNoAcceptedDigestAlgorithms() throws Exception {
        LOG.info("testInit_incorrectClientSideHashingOverrideNoAcceptedDigestAlgorithms");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("ALLOW_CLIENTSIDEHASHING_OVERRIDE", "true");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("Must specify ACCEPTED_HASH_DIGEST_ALGORITHMS"));
    }
    
    /**
     * Test that specifying CLIENTSIDEHASHING and ALLOW_CLIENTSIDEHASHING_OVERRIDE
     * without setting ACCEPTED_HASH_DIGEST_ALGORITHMS is not allowed.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_incorrectClientSideHashingAllowClientSideHashingOverrideNoAcceptedDigestAlgorithms() throws Exception {
        LOG.info("testInit_incorrectClientSideHashingAllowClientSideHashingOverrideNoAcceptedDigestAlgorithms");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CLIENTSIDEHASHING", "true");
        config.setProperty("ALLOW_CLIENTSIDEHASHING_OVERRIDE", "true");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("Must specify ACCEPTED_HASH_DIGEST_ALGORITHMS"));
    }
    
    /**
     * Test that setting an incorrect OID for content OID is not allowed.
     * @throws Exception 
     */
    @Test
    public void testInit_incorrectContentOID() throws Exception {
        LOG.info("testInit_incorrectContentOID");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CONTENTOID", "incorrect_oid");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("Illegal content OID specified: incorrect_oid"));
    }
    
    /**
     * Test that setting an incorrect value for ALLOW_CONTENTOID_OVERRIDE is not
     * allowed (so that it is not implicitly treated as false).
     * @throws Exception 
     */
    @Test
    public void testInit_incorrectAllowContentOIDOverride() throws Exception {
        LOG.info("testInit_incorrectAllowContentOIDOverride");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("ALLOW_CONTENTOID_OVERRIDE", "incorrect");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("Incorrect value for property ALLOW_CONTENTOID_OVERRIDE"));
    }
    
    /**
     * Tests that no signing is performed when the worker is misconfigured.
     * @throws java.lang.Exception
     */
    @Test(expected = SignServerException.class)
    public void testNoProcessOnFatalErrors() throws Exception {
        LOG.info("testNoProcessOnFatalErrors");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("ALLOW_DETACHEDSIGNATURE_OVERRIDE", "_incorrect-value--");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        sign(data, tokenRSA, config);
        fail("Should have thrown exception");
    }

    /**
     * Tests that not specifying the DETACHEDSIGNATURE property and not
     * saying anything in the request about detached signatures gives a
     * signature with the content encapsulated.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSignatureDefaultValue() throws Exception {
        LOG.info("testDetachedSignatureDefaultValue");
        WorkerConfig config = new WorkerConfig();
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = sign(data, tokenRSA, config);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        byte[] actualData = (byte[]) signedContent.getContent();
        assertEquals(Hex.toHexString(data), Hex.toHexString(actualData));
    }

    /**
     * Tests that detached signature is not used if not specified in config and
     * that overriding it is not allowed by default.
     * @throws java.lang.Exception
     */
    @Test(expected = IllegalRequestException.class)
    public void testAllowDetachedSignatureOverrideDefaultValue() throws Exception {
        LOG.info("testAllowDetachedSignatureOverrideDefaultValue");
        WorkerConfig config = new WorkerConfig();
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();

        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("DETACHEDSIGNATURE", "true");
        sign(data, tokenRSA, config, requestContext);
        fail("Should have thrown exception as detached signature option can not be overridden");
    }
    
    /**
     * Test that providing an incorrect value for DER_RE_ENCODE
     * gives a fatal error.
     * @throws Exception
     */
    @Test
    public void testInit_incorrectDERReEncodeValue() throws Exception {
        LOG.info("testInit_incorrectDERReEncodeValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DER_RE_ENCODE", "_incorrect-value--");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("DER_RE_ENCODE"));
    }

    /**
     * Tests that not providing a DER_RE_ENCODE property defaults to not DER.
     * @throws Exception 
     */
    @Test
    public void testDERReEncodeDefaultValue() throws Exception {
        LOG.info("testDERReEncodeDefaultValue");
        WorkerConfig config = new WorkerConfig();
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = sign(data, tokenRSA, config);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        assertNotNull(signedData);
        
        // Not in DER format by default
        final byte[] der = new ASN1InputStream(cms).readObject().getEncoded("DER");
        assertNotEquals("do not expect DER format", Hex.toHexString(der), Hex.toHexString(cms));
    }

    /**
     * Tests that setting DER_RE_ENCODE=false does not give DER encoding.
     * @throws Exception 
     */
    @Test
    public void testDERReEncodeFalse() throws Exception {
        LOG.info("testDERReEncodeFalse");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DER_RE_ENCODE", "False");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = sign(data, tokenRSA, config);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        assertNotNull(signedData);
        
        // Not in DER format by default
        final byte[] der = new ASN1InputStream(cms).readObject().getEncoded("DER");
        assertNotEquals("do not expect DER format", Hex.toHexString(der), Hex.toHexString(cms));
    }

    /**
     * Tests that setting DER_RE_ENCODE=true gives DER encoding.
     * @throws Exception 
     */
    @Test
    public void testDERReEncodeTrue() throws Exception {
        LOG.info("testDERReEncodeTrue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DER_RE_ENCODE", "TruE");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = sign(data, tokenRSA, config);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        assertNotNull(signedData);
        
        // Not in DER format by default
        final byte[] der = new ASN1InputStream(cms).readObject().getEncoded("DER");
        assertEquals("expect DER format", Hex.toHexString(der), Hex.toHexString(cms));
    }

    /**
     * Tests that client-side hashing is not used if not specified in config and
     * that overriding it is not allowed by default.
     * @throws java.lang.Exception
     */
    @Test(expected = IllegalRequestException.class)
    public void testAllowClientSideHashingOverrideDefaultValue() throws Exception {
        LOG.info("testAllowClientSideHashingOverrideDefaultValue");
        WorkerConfig config = new WorkerConfig();
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();

        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "true");
        sign(data, tokenRSA, config, requestContext);
        fail("Should have thrown exception as client-side hashing can not be overridden");
    }
    
    /**
     * Tests that detached signature is used if specified in config and that
     * overriding it can not be done if not allowed.
     * @throws java.lang.Exception
     */
    @Test(expected = IllegalRequestException.class)
    public void testAllowDetachedSignatureOverrideFalseDetached() throws Exception {
        LOG.info("testAllowDetachedSignatureOverrideFalseDetached");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DETACHEDSIGNATURE", "TRUE");
        config.setProperty("ALLOW_DETACHEDSIGNATURE_OVERRIDE", "FALSE");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();

        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("DETACHEDSIGNATURE", "false");
        sign(data, tokenRSA, config, requestContext);
        fail("Should have thrown exception as detached signature option can not be overridden");
    }
    
    /**
     * Tests that client-side hashing is used if specified in config and that
     * overriding it can not be done if not allowed.
     * @throws java.lang.Exception
     */
    @Test(expected = IllegalRequestException.class)
    public void testAllowClientSideHashingOverrideFalseClientSideHashing() throws Exception {
        LOG.info("testAllowDetachedSignatureOverrideFalseDetached");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CLIENTSIDEHASHING", "TRUE");
        config.setProperty("ALLOW_CLIENTSIDEHASHING_OVERRIDE", "FALSE");
        config.setProperty("ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();

        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "false");
        sign(data, tokenRSA, config, requestContext);
        fail("Should have thrown exception as detached signature option can not be overridden");
    }

    /**
     * Tests that requesting no detached is okey if no detached is configured 
     * even if allow override is false.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSignatureFalseRequestFalse() throws Exception {
        LOG.info("testDetachedSignatureFalseRequestFalse");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DETACHEDSIGNATURE", "FALSE");
        config.setProperty("ALLOW_DETACHEDSIGNATURE_OVERRIDE", "FALSE");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("DETACHEDSIGNATURE", "false");
        SimplifiedResponse response = sign(data, tokenRSA, config, requestContext);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        byte[] actualData = (byte[]) signedContent.getContent();
        assertEquals(Hex.toHexString(data), Hex.toHexString(actualData));
    }
    
    /**
     * Tests that requesting no client-side hashing is okey if no client-side hashing is configured 
     * even if allow override is false.
     * @throws java.lang.Exception
     */
    @Test
    public void testClientSideHashingFalseRequestFalse() throws Exception {
        LOG.info("testDetachedSignatureFalseRequestFalse");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CLIENTSIDEHASHING", "FALSE");
        config.setProperty("ALLOW_CLIENTSIDEHASHING_OVERRIDE", "FALSE");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("DETACHEDSIGNATURE", "false");
        SimplifiedResponse response = sign(data, tokenRSA, config, requestContext);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        byte[] actualData = (byte[]) signedContent.getContent();
        assertEquals(Hex.toHexString(data), Hex.toHexString(actualData));
    }

    /**
     * Tests that requesting detached is okey if detached is configured 
     * even if allow override is false.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSignatureTrueRequestTrue() throws Exception {
        LOG.info("testDetachedSignatureTrueRequestTrue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DETACHEDSIGNATURE", "TRUE");
        config.setProperty("ALLOW_DETACHEDSIGNATURE_OVERRIDE", "FALSE");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("DETACHEDSIGNATURE", "TRUE");
        SimplifiedResponse response = sign(data, tokenRSA, config, requestContext);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        assertNull("detached", signedContent);
    }

    /**
     * Tests that requesting detached is okey if allow override is set to true.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSignatureFalseRequestTrue() throws Exception {
        LOG.info("testDetachedSignatureFalseRequestTrue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DETACHEDSIGNATURE", "FALSE");
        config.setProperty("ALLOW_DETACHEDSIGNATURE_OVERRIDE", "TRUE");

        RequestContext requestContext = new RequestContext();

        final byte[] data = "my-data".getBytes("ASCII");
        
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("DETACHEDSIGNATURE", "TRUE");
        
        SimplifiedResponse response = sign(data, tokenRSA, config, requestContext);
        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        assertNull("detached", signedContent);
    }
    
    /**
     * Tests that requesting client-side hashing is okey if allow override is set to true.
     * @throws java.lang.Exception
     */
    @Test
    public void testClientSideHashingFalseRequestTrue() throws Exception {
        LOG.info("testDetachedSignatureFalseRequestTrue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CLIENTSIDEHASHING", "FALSE");
        config.setProperty("ALLOW_CLIENTSIDEHASHING_OVERRIDE", "TRUE");
        config.setProperty("ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256");

        RequestContext requestContext = new RequestContext();

        final MessageDigest digest = MessageDigest.getInstance("SHA256");
        final byte[] data = digest.digest("foo".getBytes("ASCII"));
        
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-256");
        
        SimplifiedResponse response = sign(data, tokenRSA, config, requestContext);
        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        assertNull("detached", signedContent);
        
        final SignerInformation signer =
                (SignerInformation) signedData.getSignerInfos().iterator().next();
        final AlgorithmNameFinder algFinder = new DefaultAlgorithmNameFinder();
        
        final Attribute messageDigest =
                signer.getSignedAttributes().get(CMSAttributes.messageDigest);
        assertEquals("digest algorithm", "SHA256",
                algFinder.getAlgorithmName(signer.getDigestAlgorithmID()));
        assertNotNull("message digest present", messageDigest);
        
        final ASN1OctetString messageDigestObject =
                ASN1OctetString.getInstance(messageDigest.getAttrValues().getObjectAt(0).toASN1Primitive());
        final byte[] encoded = messageDigestObject.getOctets();
        
        assertTrue("digest matches", Arrays.equals(data, encoded));
    }
    
    /**
     * Tests that when CLIENTSIDEHASHING is set to true, the hash is actually
     * taken from the request as expected.
     * @throws java.lang.Exception
     */
    @Test
    public void testClientSideHashingTrue() throws Exception {
        LOG.info("testDetachedSignatureFalseRequestTrue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CLIENTSIDEHASHING", "TRUE");
        config.setProperty("ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256");

        RequestContext requestContext = new RequestContext();

        final MessageDigest digest = MessageDigest.getInstance("SHA256");
        final byte[] data = digest.digest("foo".getBytes("ASCII"));
        
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-256");
        
        SimplifiedResponse response = sign(data, tokenRSA, config, requestContext);
        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        assertNull("detached", signedContent);
        
        final SignerInformation signer =
                (SignerInformation) signedData.getSignerInfos().iterator().next();
        final AlgorithmNameFinder algFinder = new DefaultAlgorithmNameFinder();
        
        final Attribute messageDigest =
                signer.getSignedAttributes().get(CMSAttributes.messageDigest);
        assertEquals("digest algorithm", "SHA256",
                algFinder.getAlgorithmName(signer.getDigestAlgorithmID()));
        assertNotNull("message digest present", messageDigest);
        
        final ASN1OctetString messageDigestObject =
                ASN1OctetString.getInstance(messageDigest.getAttrValues().getObjectAt(0).toASN1Primitive());
        final byte[] encoded = messageDigestObject.getOctets();
        
        assertTrue("digest matches", Arrays.equals(data, encoded));
    }
    
    /**
     * Tests that when CLIENTSIDEHASHING is set to true, the hash is actually
     * taken from the request as expected, using SHA512.
     * Also test multiple accepted algorithms.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testClientSideHashingTrueSHA512() throws Exception {
        LOG.info("testDetachedSignatureFalseRequestTrue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CLIENTSIDEHASHING", "TRUE");
        config.setProperty("ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256,SHA-512");

        RequestContext requestContext = new RequestContext();

        final MessageDigest digest = MessageDigest.getInstance("SHA512");
        final byte[] data = digest.digest("foo".getBytes("ASCII"));
        
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-512");
        
        SimplifiedResponse response = sign(data, tokenRSA, config, requestContext);
        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        assertNull("detached", signedContent);
        
        final SignerInformation signer =
                (SignerInformation) signedData.getSignerInfos().iterator().next();
        final AlgorithmNameFinder algFinder = new DefaultAlgorithmNameFinder();
        
        final Attribute messageDigest =
                signer.getSignedAttributes().get(CMSAttributes.messageDigest);
        assertEquals("digest algorithm", "SHA512",
                algFinder.getAlgorithmName(signer.getDigestAlgorithmID()));
        assertNotNull("message digest present", messageDigest);
        
        final ASN1OctetString messageDigestObject =
                ASN1OctetString.getInstance(messageDigest.getAttrValues().getObjectAt(0).toASN1Primitive());
        final byte[] encoded = messageDigestObject.getOctets();
        
        assertTrue("digest matches", Arrays.equals(data, encoded));
    }
    
    /**
     * Tests that when CLIENTSIDEHASHING is set to true, requesting a non-accepted
     * hash digest algorithm is not allowed.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testClientSideHashingTrueUnacceptedDigestAlgorithm() throws Exception {
        LOG.info("testClientSideHashingTrueUnacceptedDigestAlgorithm");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CLIENTSIDEHASHING", "TRUE");
        config.setProperty("ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256,SHA-512");

        RequestContext requestContext = new RequestContext();

        final MessageDigest digest = MessageDigest.getInstance("SHA1");
        final byte[] data = digest.digest("foo".getBytes("ASCII"));
        
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-1");

        try {
            sign(data, tokenRSA, config, requestContext);
            fail("Should throw IllegalRequestException");
        } catch (IllegalRequestException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }
    
    /**
     * Tests that requesting client-side hashing is rejected when client doesn't specify hash algo.
     * @throws java.lang.Exception
     */
    @Test(expected = IllegalRequestException.class)
    public void testClientSideHashingNoDigestAlgoFails() throws Exception {
        LOG.info("testDetachedSignatureFalseRequestTrue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CLIENTSIDEHASHING", "FALSE");
        config.setProperty("ALLOW_CLIENTSIDEHASHING_OVERRIDE", "TRUE");
        config.setProperty("ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256");

        RequestContext requestContext = new RequestContext();

        final byte[] data = "my-data".getBytes("ASCII");
        
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        
        SimplifiedResponse response = sign(data, tokenRSA, config, requestContext);
    }
    
    /**
     * Tests that client-side hashing is rejected when set as default, but client doesn't specify hash algo.
     * @throws java.lang.Exception
     */
    @Test(expected = IllegalRequestException.class)
    public void testClientSideHashingTrueNoDigestAlgoFails() throws Exception {
        LOG.info("testClientSideHashingTrueNoDigestAlgoFails");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CLIENTSIDEHASHING", "TRUE");
        config.setProperty("ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256");

        RequestContext requestContext = new RequestContext();

        final byte[] data = "my-data".getBytes("ASCII");
        
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        
        sign(data, tokenRSA, config, requestContext);
    }

    /**
     * Tests that requesting no detached is okey if allow override is true.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSignatureTrueRequestFalse() throws Exception {
        LOG.info("testDetachedSignatureTrueRequestFalse");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DETACHEDSIGNATURE", "TRUE");
        config.setProperty("ALLOW_DETACHEDSIGNATURE_OVERRIDE", "TRUE");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("DETACHEDSIGNATURE", "false");
        
        SimplifiedResponse response = sign(data, tokenRSA, config, requestContext);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        byte[] actualData = (byte[]) signedContent.getContent();
        assertEquals(Hex.toHexString(data), Hex.toHexString(actualData));
    }
    
    /**
     * Tests that requesting no client-side hashing is okey if allow override is true.
     * @throws java.lang.Exception
     */
    @Test
    public void testClientSideHashingTrueRequestFalse() throws Exception {
        LOG.info("testClientSideHashingTrueRequestFalse");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CLIENTSIDEHASHING", "TRUE");
        config.setProperty("ALLOW_CLIENTSIDEHASHING_OVERRIDE", "TRUE");
        config.setProperty("ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "false");
        
        SimplifiedResponse response = sign(data, tokenRSA, config, requestContext);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        byte[] actualData = (byte[]) signedContent.getContent();
        assertEquals(Hex.toHexString(data), Hex.toHexString(actualData));
    }

    /**
     * Tests that requesting with empty string is the same as not requesting.
     * @throws java.lang.Exception
     */
    @Test
    public void testDetachedSignatureTrueRequestEmpty() throws Exception {
        LOG.info("testDetachedSignatureTrueRequestEmpty");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DETACHEDSIGNATURE", "TRUE");
        config.setProperty("ALLOW_DETACHEDSIGNATURE_OVERRIDE", "FALSE");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("DETACHEDSIGNATURE", "");
        SimplifiedResponse response = sign(data, tokenRSA, config, requestContext);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        assertNull("detached", signedContent);
    }
    
    /**
     * Tests that requesting client-side hashing with empty string is the same as not requesting.
     * @throws java.lang.Exception
     */
    @Test
    public void testClientSideHashingTrueRequestEmpty() throws Exception {
        LOG.info("testClientSideHashingTrueRequestEmpty");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CLIENTSIDE_HASHING", "TRUE");
        config.setProperty("ALLOW_CLIENTSIDEHASHING_OVERRIDE", "FALSE");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENSUPPLIED_HASH", "");
        sign(data, tokenRSA, config, requestContext);
    }
    
    /**
     * Test that by default, the PKCS#7 signed data OID is used.
     * @throws java.lang.Exception
     */
    @Test
    public void testContentOIDDefaultValue() throws Exception {
        LOG.info("testContentOIDDefaultValue");
        WorkerConfig config = new WorkerConfig();
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = sign(data, tokenRSA, config);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        assertEquals("content OID", "1.2.840.113549.1.7.1",
                     signedData.getSignedContentTypeOID());
    }
    
    /**
     * Test overriding content OID using worker property.
     * @throws java.lang.Exception
     */
    @Test
    public void testContentOIDInConfiguration() throws Exception {
        LOG.info("testContentOIDDefaultValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CONTENTOID", "1.2.3.4");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = sign(data, tokenRSA, config);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        assertEquals("content OID", "1.2.3.4",
                     signedData.getSignedContentTypeOID());
    }
    
    /**
     * Test overriding content OID in request.
     * @throws java.lang.Exception
     */
    @Test
    public void testContentOIDOverride() throws Exception {
        LOG.info("testContentOIDDefaultValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("ALLOW_CONTENTOID_OVERRIDE", "true");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("CONTENTOID", "1.2.3.4");
        SimplifiedResponse response = sign(data, tokenRSA, config, requestContext);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        assertEquals("content OID", "1.2.3.4",
                     signedData.getSignedContentTypeOID());
    }
    
    /**
     * Test overriding content OID in request has higher priority than specified
     * in configuration.
     * @throws java.lang.Exception
     */
    @Test
    public void testContentOIDOverrideAndInConfiguration() throws Exception {
        LOG.info("testContentOIDDefaultValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CONTENTOID", "1.2.3.4");
        config.setProperty("ALLOW_CONTENTOID_OVERRIDE", "TRUE");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("CONTENTOID", "1.2.3.5");
        SimplifiedResponse response = sign(data, tokenRSA, config, requestContext);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        assertEquals("content OID", "1.2.3.5",
                     signedData.getSignedContentTypeOID());
    }
    
    /**
     * Test overriding content OID is not allowed by default.
     * @throws java.lang.Exception
     */
    @Test
    public void testDefaulDontAllowOverridingContentOID() throws Exception {
        LOG.info("testContentOIDDefaultValue");
        WorkerConfig config = new WorkerConfig();
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("CONTENTOID", "1.2.3.5");
        
        try {
            sign(data, tokenRSA, config, requestContext);
            fail("Should throw IllegalRequestException");
        } catch (IllegalRequestException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }
    
    /**
     * Test overriding content OID is not allowed by default with a content OID
     * specified in the configuration.
     * @throws java.lang.Exception
     */
    @Test
    public void testDontAllowOverridingContentOIDWithContentOIDInConfig() throws Exception {
        LOG.info("testContentOIDDefaultValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CONTENTOID", "1.2.3.4");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("CONTENTOID", "1.2.3.5");
        
        try {
            sign(data, tokenRSA, config, requestContext);
            fail("Should throw IllegalRequestException");
        } catch (IllegalRequestException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }
    
    /**
     * Test overriding content OID in request with the default OID value is
     * accepted even when not accepting override.
     * @throws java.lang.Exception
     */
    @Test
    public void testOverrideWithDefaultContentOID() throws Exception {
        LOG.info("testContentOIDDefaultValue");
        WorkerConfig config = new WorkerConfig();
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("CONTENTOID", "1.2.840.113549.1.7.1");
        SimplifiedResponse response = sign(data, tokenRSA, config, requestContext);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        assertEquals("content OID", "1.2.840.113549.1.7.1",
                     signedData.getSignedContentTypeOID());
    }
    
    /**
     * Test overriding content OID in request with the specified value from the
     * configuration is accepted even when not accepting override.
     * @throws java.lang.Exception
     */
    @Test
    public void testOverrideWithSpecifiedContentOIDFromConfiguration() throws Exception {
        LOG.info("testContentOIDDefaultValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CONTENTOID", "1.2.3.4");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("CONTENTOID", "1.2.3.4");
        SimplifiedResponse response = sign(data, tokenRSA, config, requestContext);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        assertEquals("content OID", "1.2.3.4",
                     signedData.getSignedContentTypeOID());
    }
    
    /**
     * Test overriding content OID is not allowed when explicitly configuring.
     * not allowing override.
     * @throws java.lang.Exception
     */
    @Test
    public void testDontAllowOverridingContentOIDExplicit() throws Exception {
        LOG.info("testContentOIDDefaultValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("ALLOW_CONTENTOID_OVERRIDE", "false");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("CONTENTOID", "1.2.3.5");
        
        try {
            sign(data, tokenRSA, config, requestContext);
            fail("Should throw IllegalRequestException");
        } catch (IllegalRequestException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }
    
    /**
     * Test overriding content OID is not allowed with a content OID
     * specified in the configuration also when explicitly configuring not
     * allowing override.
     * @throws java.lang.Exception
     */
    @Test
    public void testDontAllowOverridingContentOIDWithContentOIDInConfigExplicit() throws Exception {
        LOG.info("testContentOIDDefaultValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CONTENTOID", "1.2.3.4");
        config.setProperty("ALLOW_CONTENTOID_OVERRIDE", "FALSE");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("CONTENTOID", "1.2.3.5");
        
        try {
            sign(data, tokenRSA, config, requestContext);
            fail("Should throw IllegalRequestException");
        } catch (IllegalRequestException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }
    
    private SimplifiedResponse sign(final byte[] data, MockedCryptoToken token, WorkerConfig config) throws Exception {
        return sign(data, token, config, null);
    }
    
    private SimplifiedResponse sign(final byte[] data, MockedCryptoToken token, WorkerConfig config, RequestContext requestContext) throws Exception {
        MockedCMSSigner instance = new MockedCMSSigner(token);
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
}
