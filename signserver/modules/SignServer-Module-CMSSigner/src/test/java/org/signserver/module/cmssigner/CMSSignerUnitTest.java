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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.util.Store;
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
import org.bouncycastle.asn1.cms.AttributeTable;
import org.signserver.common.WorkerType;
import org.signserver.server.log.LogMap;

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
    private static MockedCryptoToken tokenPQ;

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        {
            final KeyPair signerKeyPair;
            final String signatureAlgorithm;
            signerKeyPair = CryptoUtils.generateRSA(1024);
            signatureAlgorithm = "SHA1withRSA";
            final Certificate[] certChain =
                    new Certificate[]{new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                            setSelfSignKeyPair(signerKeyPair).
                            setNotBefore(new Date()).
                            setSignatureAlgorithm(signatureAlgorithm)
                            .build())};
            final Certificate signerCertificate = certChain[0];
            tokenRSA = new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), "BC");
        }
        final KeyPair signerKeyPair2 = CryptoUtils.generateSphincsPlus();
        final String signatureAlgorithm = "SPHINCS+";
        final Certificate[] certChain =
                new Certificate[]{new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSelfSignKeyPair(signerKeyPair2).
                        setNotBefore(new Date()).
                        setSignatureAlgorithm(signatureAlgorithm)
                        .build())};
        final Certificate signerCertificate = certChain[0];
        tokenPQ = new MockedCryptoToken(signerKeyPair2.getPrivate(), signerKeyPair2.getPublic(), signerCertificate, Arrays.asList(certChain), "BC");
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
        CMSSigner instance = createMockSigner(tokenRSA);
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
        CMSSigner instance = createMockSigner(tokenRSA);
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
        CMSSigner instance = createMockSigner(tokenRSA);
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
        CMSSigner instance = createMockSigner(tokenRSA);
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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("Must specify ACCEPTED_HASH_DIGEST_ALGORITHMS"));
    }
    
    /**
     * Test that specifying an illegal accepted hash digest algorithm results
     * in a configuration error.
     * 
     * @throws Exception
     */
    @Test
    public void testInit_incorrectAcceptedHashDigestAlgorithm() throws Exception {
        LOG.info("testInit_incorrectClientSideHashingNoAcceptedDigestAlgorithms");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CLIENTSIDEHASHING", "true");
        config.setProperty("ACCEPTED_HASH_DIGEST_ALGORITHMS", "_incorrect_");
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("Illegal algorithm specified for ACCEPTED_HASH_DIGEST_ALGORITHMS: _incorrect_"));
    }
    
    /**
     * Test that specifying an illegal accepted hash digest algorithm results
     * in a configuration error when also a valid alorithm is listed.
     * 
     * @throws Exception
     */
    @Test
    public void testInit_incorrectAndCorrectAcceptedHashDigestAlgorithm() throws Exception {
        LOG.info("testInit_incorrectClientSideHashingNoAcceptedDigestAlgorithms");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CLIENTSIDEHASHING", "true");
        config.setProperty("ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256, _incorrect_");
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("Illegal algorithm specified for ACCEPTED_HASH_DIGEST_ALGORITHMS: _incorrect_"));
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
        CMSSigner instance = createMockSigner(tokenRSA);
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
        CMSSigner instance = createMockSigner(tokenRSA);
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
        CMSSigner instance = createMockSigner(tokenRSA);
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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("Incorrect value for property ALLOW_CONTENTOID_OVERRIDE"));
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
        CMSSigner instance = createMockSigner(tokenRSA);
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
        CMSSigner instance = createMockSigner(tokenRSA);
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
        CMSSigner instance = createMockSigner(tokenRSA);
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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);
        
        assertTrue("no fatal errors", instance.getFatalErrors(null).isEmpty());
    }
    
    /**
     * Tests that there is no request and response logging by default.
     *
     * @throws Exception 
     */
    @Test
    public void testDefaultsToNoRequestOrResponseLogging() throws Exception {
        LOG.info("testDefaultsToNoRequestOrResponseLogging");
        WorkerConfig config = new WorkerConfig();
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        CMSSignerUnitTest.this.signAndVerify(data, tokenRSA, config, requestContext, false);
        LogMap logMap = LogMap.getInstance(requestContext);
        assertNull("no request digest", logMap.get("REQUEST_DIGEST_ALGORITHM"));
        assertNull("no response digest", logMap.get("RESPONSE_DIGEST_ALGORITHM"));
    }
    
    /**
     * Tests that the request digest is correct when enabled.
     *
     * @throws Exception 
     */
    @Test
    public void testRequestDigestMatches() throws Exception {
        LOG.info("testRequestDigestMatches");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DO_LOGREQUEST_DIGEST", "true");
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        CMSSignerUnitTest.this.signAndVerify(data, tokenRSA, config, requestContext, false);
        assertRequestDigestMatches(data, "SHA256", requestContext);
    }
    
    /**
     * Tests that the request digest is correct when enabled.
     * Specifying SHA512.
     *
     * @throws Exception 
     */
    @Test
    public void testRequestDigestMatches_SHA512() throws Exception {
        LOG.info("testRequestDigestMatches_SHA512");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DO_LOGREQUEST_DIGEST", "true");
        config.setProperty("LOGREQUEST_DIGESTALGORITHM", "SHA512");
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        CMSSignerUnitTest.this.signAndVerify(data, tokenRSA, config, requestContext, false);
        assertRequestDigestMatches(data, "SHA512", requestContext);
    }
    
    /**
     * Tests that the response digest is correct when enabled.
     *
     * @throws Exception 
     */
    @Test
    public void testResponseDigestMatches() throws Exception {
        LOG.info("testResponseDigestMatches");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DO_LOGRESPONSE_DIGEST", "true");
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        SimplifiedResponse response = CMSSignerUnitTest.this.signAndVerify(data, tokenRSA, config, requestContext, false);
        assertResponseDigestMatches(response.getProcessedData(), "SHA256", requestContext);
    }

    /**
     * Tests that the response digest is correct when enabled.
     * Specifying SHA512.
     *
     * @throws Exception 
     */
    @Test
    public void testResponseDigestMatches_SHA512() throws Exception {
        LOG.info("testResponseDigestMatches_SHA512");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DO_LOGRESPONSE_DIGEST", "true");
        config.setProperty("LOGRESPONSE_DIGESTALGORITHM", "SHA512");
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        SimplifiedResponse response = CMSSignerUnitTest.this.signAndVerify(data, tokenRSA, config, requestContext, false);
        assertResponseDigestMatches(response.getProcessedData(), "SHA512", requestContext);
    }

    private void assertRequestDigestMatches(byte[] data, String digestAlgorithm, RequestContext context) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, UnsupportedEncodingException, IOException {
        final LogMap logMap = LogMap.getInstance(context);
        final Object digestAlgLoggable = logMap.get("REQUEST_DIGEST_ALGORITHM");
        assertEquals("digestAlg", digestAlgorithm, String.valueOf(digestAlgLoggable));
        
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
     * Tests that no signing is performed when the worker is misconfigured.
     * @throws java.lang.Exception
     */
    @Test(expected = SignServerException.class)
    public void testNoProcessOnFatalErrors() throws Exception {
        LOG.info("testNoProcessOnFatalErrors");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("ALLOW_DETACHEDSIGNATURE_OVERRIDE", "_incorrect-value--");
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        CMSSignerUnitTest.this.signAndVerify(data, tokenRSA, config, null, false);
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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = CMSSignerUnitTest.this.signAndVerify(data, tokenRSA, config, null, false);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        byte[] actualData = (byte[]) signedContent.getContent();
        assertEquals(Hex.toHexString(data), Hex.toHexString(actualData));
    }

    @Test
    public void testDetachedSignature_SPHINCSPlus() throws Exception {
        LOG.info("testDetachedSignature_SPHINCSPlus");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("SIGNATUREALGORITHM", "SPHINCS+");
        CMSSigner instance = createMockSigner(tokenPQ);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = CMSSignerUnitTest.this.signAndVerify(data, tokenPQ, config, null, false);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        byte[] actualData = (byte[]) signedContent.getContent();
        assertEquals(Hex.toHexString(data), Hex.toHexString(actualData));
    }

    @Test
    public void testDetachedSignatureTrueRequestTrue_SPHINCSPlus() throws Exception {
        LOG.info("testDetachedSignatureTrueRequestTrue_SPHINCSPlus");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DETACHEDSIGNATURE", "TRUE");
        config.setProperty("ALLOW_DETACHEDSIGNATURE_OVERRIDE", "FALSE");
        config.setProperty("SIGNATUREALGORITHM", "SPHINCS+");
        CMSSigner instance = createMockSigner(tokenPQ);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("DETACHEDSIGNATURE", "TRUE");
        SimplifiedResponse response = signAndVerify(data, tokenPQ, config, requestContext, true);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        assertNull("detached", signedContent);
    }

    /**
     * Tests that specifying empty value for Signer parameters works.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testSignWithEmptyParams() throws Exception {
        LOG.info("testSignWithEmptyParams");
        WorkerConfig config = new WorkerConfig();
        config.setProperty(CMSSigner.SIGNATUREALGORITHM_PROPERTY, "  ");
        config.setProperty(CMSSigner.DETACHEDSIGNATURE_PROPERTY, "  ");
        config.setProperty(ClientSideHashingHelper.CLIENTSIDEHASHING, "  ");
        config.setProperty(ClientSideHashingHelper.ACCEPTED_HASHDIGEST_ALGORITHMS, "  ");

        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = CMSSignerUnitTest.this.signAndVerify(data, tokenRSA, config, null, false);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        byte[] actualData = (byte[]) signedContent.getContent();
        assertEquals(Hex.toHexString(data), Hex.toHexString(actualData));
    }
    
    /**
     * Test that when length of client supplied hash digest does not match with the length of specified digest algorithm,it fails.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testClientSideHashingMessageDigestLengthNotMatchedWithSpecifiedHashAlgoFails() throws Exception {
        LOG.info("testClientSideHashingMessageDigestLengthNotMatchedWithSpecifiedHashAlgoFails");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("CLIENTSIDEHASHING", "TRUE");
        config.setProperty("ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256,SHA-512");

        RequestContext requestContext = new RequestContext();

        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-512");

        String errorMessage = "Client-side hashing data length must match with the length of client specified digest algorithm";

        try {
            signAndVerifyWithHash("foo".getBytes("ASCII"), "SHA-256", tokenRSA, config, requestContext);
            fail("Should throw IllegalRequestException");
        } catch (IllegalRequestException e) {
            // expected since CLIENTSIDE_HASHDIGESTALGORITHM is SHA-512 but digest generated from SHA-256
            assertEquals(errorMessage, e.getMessage());
        }
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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();

        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("DETACHEDSIGNATURE", "true");
        signAndVerify(data, tokenRSA, config, requestContext, false);
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
        CMSSigner instance = createMockSigner(tokenRSA);
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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = CMSSignerUnitTest.this.signAndVerify(data, tokenRSA, config, null, false);

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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = CMSSignerUnitTest.this.signAndVerify(data, tokenRSA, config, null, false);

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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = CMSSignerUnitTest.this.signAndVerify(data, tokenRSA, config, null, false);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        assertNotNull(signedData);
        
        // expect DER format
        final byte[] der = new ASN1InputStream(cms).readObject().getEncoded("DER");
        assertEquals("expect DER format", Hex.toHexString(der), Hex.toHexString(cms));
    }

    /**
     * Tests that setting DER_RE_ENCODE=true gives DER encoding for
     * clientside.
     *
     * @throws Exception 
     */
    @Test
    public void testDERReEncodeTrueClientside() throws Exception {
        LOG.info("testDERReEncodeTrue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DER_RE_ENCODE", "true");
        config.setProperty("ALLOW_CLIENTSIDEHASHING_OVERRIDE", "true");
        config.setProperty("ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256");
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");

        RequestContext requestContext = new RequestContext();
        
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-256");
        
        SimplifiedResponse response = signAndVerifyWithHash("foo".getBytes("ASCII"), "SHA256", tokenRSA, config, requestContext);
        
        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        assertNotNull(signedData);
        
        // expect DER format
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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();

        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "true");
        signAndVerify(data, tokenRSA, config, requestContext, true);
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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();

        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("DETACHEDSIGNATURE", "false");
        signAndVerify(data, tokenRSA, config, requestContext, true);
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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();

        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "false");
        signAndVerify(data, tokenRSA, config, requestContext, true);
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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("DETACHEDSIGNATURE", "false");
        SimplifiedResponse response = signAndVerify(data, tokenRSA, config, requestContext, false);

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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("DETACHEDSIGNATURE", "false");
        SimplifiedResponse response = signAndVerify(data, tokenRSA, config, requestContext, false);

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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("DETACHEDSIGNATURE", "TRUE");
        SimplifiedResponse response = signAndVerify(data, tokenRSA, config, requestContext, true);

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
        
        SimplifiedResponse response = signAndVerify(data, tokenRSA, config, requestContext, true);
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
        
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-256");
        
        signAndVerifyWithHash("foo".getBytes("ASCII"), "SHA256", tokenRSA, config, requestContext);
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
        
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-256");
        
        signAndVerifyWithHash("foo".getBytes("ASCII"), "SHA256", tokenRSA, config, requestContext);
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
        
        signAndVerifyWithHash("foo".getBytes("ASCII"), "SHA512", tokenRSA, config, requestContext);
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
        
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "TRUE");
        metadata.put("CLIENTSIDE_HASHDIGESTALGORITHM", "SHA-1");

        try {
            signAndVerifyWithHash("foo".getBytes("ASCII"), "SHA1", tokenRSA, config, requestContext);
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
        
        SimplifiedResponse response = signAndVerify(data, tokenRSA, config, requestContext, true);
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
        
        signAndVerify(data, tokenRSA, config, requestContext, true);
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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("DETACHEDSIGNATURE", "false");
        
        SimplifiedResponse response = signAndVerify(data, tokenRSA, config, requestContext, false);

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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENTSUPPLIED_HASH", "false");
        
        SimplifiedResponse response = signAndVerify(data, tokenRSA, config, requestContext, false);

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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("DETACHEDSIGNATURE", "");
        SimplifiedResponse response = signAndVerify(data, tokenRSA, config, requestContext, true);

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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("USING_CLIENSUPPLIED_HASH", "");
        signAndVerify(data, tokenRSA, config, requestContext, false);
    }
    
    /**
     * Test that by default, the PKCS#7 signed data OID is used.
     * @throws java.lang.Exception
     */
    @Test
    public void testContentOIDDefaultValue() throws Exception {
        LOG.info("testContentOIDDefaultValue");
        WorkerConfig config = new WorkerConfig();
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = CMSSignerUnitTest.this.signAndVerify(data, tokenRSA, config, null, false);

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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = CMSSignerUnitTest.this.signAndVerify(data, tokenRSA, config, null, false);

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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("CONTENTOID", "1.2.3.4");
        SimplifiedResponse response = signAndVerify(data, tokenRSA, config, requestContext, false);

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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("CONTENTOID", "1.2.3.5");
        SimplifiedResponse response = signAndVerify(data, tokenRSA, config, requestContext, false);

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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("CONTENTOID", "1.2.3.5");
        
        try {
            signAndVerify(data, tokenRSA, config, requestContext, false);
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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("CONTENTOID", "1.2.3.5");
        
        try {
            signAndVerify(data, tokenRSA, config, requestContext, false);
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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("CONTENTOID", "1.2.840.113549.1.7.1");
        SimplifiedResponse response = signAndVerify(data, tokenRSA, config, requestContext, false);

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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("CONTENTOID", "1.2.3.4");
        SimplifiedResponse response = signAndVerify(data, tokenRSA, config, requestContext, false);

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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("CONTENTOID", "1.2.3.5");
        
        try {
            signAndVerify(data, tokenRSA, config, requestContext, false);
            fail("Should throw IllegalRequestException");
        } catch (IllegalRequestException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }
    
    /**
     * Test overriding content OID with invalid OID should not be allowed.
     * not allowing override.
     * @throws java.lang.Exception
     */
    @Test
    public void testDontAllowOverridingWithInvalidOID() throws Exception {
        LOG.info("testContentOIDDefaultValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("ALLOW_CONTENTOID_OVERRIDE", "true");
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("CONTENTOID", "incorrect_oid");
        
        try {
            signAndVerify(data, tokenRSA, config, requestContext, false);
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
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        RequestContext requestContext = new RequestContext();
        RequestMetadata metadata = RequestMetadata.getInstance(requestContext);
        metadata.put("CONTENTOID", "1.2.3.5");
        
        try {
            signAndVerify(data, tokenRSA, config, requestContext, false);
            fail("Should throw IllegalRequestException");
        } catch (IllegalRequestException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }

    /**
     * Tests that with DIRECTSIGNATURE=true, no signed attributes are included.
     * @throws Exception
     */
    @Test
    public void testDirectSignatureTrue() throws Exception {
        LOG.info("testDirectSignatureTrue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DIRECTSIGNATURE", "true");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = CMSSignerUnitTest.this.signAndVerify(data, tokenRSA, config, null, false);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        AttributeTable signedAttributes = signedData.getSignerInfos().getSigners().iterator().next().getSignedAttributes();
        assertNull("no signed attributes", signedAttributes);
    }

    /**
     * Tests that with DIRECTSIGNATURE=false, there are some signed attributes included.
     * @throws Exception 
     */
    @Test
    public void testDirectSignatureFalse() throws Exception {
        LOG.info("testDirectSignatureFalse");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DIRECTSIGNATURE", "false");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = CMSSignerUnitTest.this.signAndVerify(data, tokenRSA, config, null, false);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        AttributeTable signedAttributes = signedData.getSignerInfos().getSigners().iterator().next().getSignedAttributes();
        assertTrue("signed attributes expected", signedAttributes.size() > 0);
    }
    
    /**
     * Tests that with an empty (or with blank space actually) value for DIRECTSIGNATURE the default is false
     * and thus signed attributes are included.
     * @throws Exception 
     */
    @Test
    public void testDirectSignatureEmptySlashDefault() throws Exception {
        LOG.info("testDirectSignatureFalse");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DIRECTSIGNATURE", " ");
        CMSSigner instance = new MockedCMSSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        final byte[] data = "my-data".getBytes("ASCII");
        SimplifiedResponse response = CMSSignerUnitTest.this.signAndVerify(data, tokenRSA, config, null, false);

        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        AttributeTable signedAttributes = signedData.getSignerInfos().getSigners().iterator().next().getSignedAttributes();
        assertTrue("signed attributes expected", signedAttributes.size() > 0);
    }
    
    /**
     * Test that providing an incorrect value for DIRECTSIGNATURE
     * gives a fatal error.
     * @throws Exception
     */
    @Test
    public void testInit_incorrectDirectSignatureValue() throws Exception {
        LOG.info("testInit_incorrectDirectSignatureValue");
        WorkerConfig config = new WorkerConfig();
        config.setProperty("DIRECTSIGNATURE", "_incorrect-value--");
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs: " + errors, errors.contains("DIRECTSIGNATURE"));
    }

    /**
     * Test that enabling both DIRECTSIGNATURE and CLIENTSIDEHASHING
     * gives a fatal error.
     * @throws Exception
     */
    @Test
    public void testInit_incorrectDirectSignatureAndClientSideHashingCombination() throws Exception {
        LOG.info("testInit_incorrectDirectSignatureAndClientSideHashingCombination");
        WorkerConfig config = new WorkerConfig();
        config.setProperty(CMSSigner.DIRECTSIGNATURE_PROPERTY, Boolean.TRUE.toString());
        config.setProperty(ClientSideHashingHelper.CLIENTSIDEHASHING, Boolean.TRUE.toString());
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs not containing DIRECTSIGNATURE: " + errors, errors.contains("DIRECTSIGNATURE"));
        assertTrue("conf errs not containing CLIENTIDEHASHING: " + errors, errors.contains("CLIENTSIDEHASHING"));
    }
    
    /**
     * Test that enabling both DIRECTSIGNATURE and ALLOW_CLIENTSIDEHASHING_OVERRIDE
     * gives a fatal error.
     * @throws Exception
     */
    @Test
    public void testInit_incorrectDirectSignatureAndClientSideHashingOverrideCombination() throws Exception {
        LOG.info("testInit_incorrectDirectSignatureAndClientSideHashingOverrideCombination");
        WorkerConfig config = new WorkerConfig();
        config.setProperty(CMSSigner.DIRECTSIGNATURE_PROPERTY, Boolean.TRUE.toString());
        config.setProperty(ClientSideHashingHelper.ALLOW_CLIENTSIDEHASHING_OVERRIDE, Boolean.TRUE.toString());
        CMSSigner instance = createMockSigner(tokenRSA);
        instance.init(1, config, new SignServerContext(), null);

        String errors = instance.getFatalErrors(new MockedServicesImpl()).toString();
        assertTrue("conf errs not containing DIRECTSIGNATURE: " + errors, errors.contains("DIRECTSIGNATURE"));
        assertTrue("conf errs not containing ALLOW_CLIENTIDEHASHING_OVERRIDE: " + errors, errors.contains("ALLOW_CLIENTSIDEHASHING_OVERRIDE"));
    }

    /**
     * Helper method requesting signing using a pre-computed hash.
     * Will also check that the message digest in the response matches the
     * pre-computed one.
     * 
     * @param data Data to be hashed for the signer
     * @param digestAlgo Hash digest algorithm to use
     * @param token
     * @param config
     * @param requestContext
     * @return
     * @throws Exception 
     */
    private SimplifiedResponse signAndVerifyWithHash(final byte[] data,
                                                     final String digestAlgo,
                                                     final MockedCryptoToken token,
                                                     final WorkerConfig config,
                                                     final RequestContext requestContext)
            throws Exception {
        final MessageDigest digest = MessageDigest.getInstance(digestAlgo);
        final byte[] hash = digest.digest(data);
        final SimplifiedResponse response = signAndVerify(hash, data, token, config, requestContext, true);
        
        byte[] cms = response.getProcessedData();
        CMSSignedData signedData = new CMSSignedData(cms);
        CMSProcessableByteArray signedContent = (CMSProcessableByteArray) signedData.getSignedContent();
        assertNull("detached", signedContent);
        
        final SignerInformation signer =
                (SignerInformation) signedData.getSignerInfos().iterator().next();
        final AlgorithmNameFinder algFinder = new DefaultAlgorithmNameFinder();
        
        final Attribute messageDigest =
                signer.getSignedAttributes().get(CMSAttributes.messageDigest);
        assertEquals("digest algorithm", digestAlgo,
                algFinder.getAlgorithmName(signer.getDigestAlgorithmID()));
        assertNotNull("message digest present", messageDigest);
        
        final ASN1OctetString messageDigestObject =
                ASN1OctetString.getInstance(messageDigest.getAttrValues().getObjectAt(0).toASN1Primitive());
        final byte[] encoded = messageDigestObject.getOctets();
        
        assertTrue("digest matches", Arrays.equals(hash, encoded));
        
        return response;
    }
    
    private SimplifiedResponse signAndVerify(final byte[] data, MockedCryptoToken token, WorkerConfig config, RequestContext requestContext, boolean detached) throws Exception {
        return signAndVerify(data, data, token, config, requestContext, detached);
    }

    /**
     * Helper method signing the given data (either the actual data to be signed
     * or if the signer or request implies client-side hashing, the pre-computed
     * hash) and the original data. When detached mode is assumed, the originalData
     * is used to verify the signature.
     * 
     * @param data Data (data to be signed, or pre-computed hash)
     * @param originalData Original data (either the actual data or the data that was pre-hashed)
     * @param token
     * @param config
     * @param requestContext
     * @param detached If true, assume detached
     * @return
     * @throws Exception 
     */
    private SimplifiedResponse signAndVerify(final byte[] data, final byte[] originalData, MockedCryptoToken token, WorkerConfig config, RequestContext requestContext, boolean detached) throws Exception {
        final CMSSigner instance = createMockSigner(token);
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
            
            final CMSSignedData signedData;
            if (detached) {
                signedData = new CMSSignedData(new CMSProcessableByteArray(originalData), signedBytes);
            } else {
                signedData = new CMSSignedData(signedBytes);
            }
            int verified = 0;
            
            Store                   certStore = signedData.getCertificates();
            SignerInformationStore  signers = signedData.getSignerInfos();
            Collection              c = signers.getSigners();
            Iterator                it = c.iterator();

            while (it.hasNext()) {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certStore.getMatches(signer.getSID());

                Iterator              certIt = certCollection.iterator();
                X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

                if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
                    verified++;
                    LOG.debug("Verified");
                } else {
                    LOG.debug("Not verified");
                }
            }
            
            assertTrue("verified", verified > 0);
            
            return new SimplifiedResponse(signedBytes, signerCertificate);
        }
    }
    
    /**
     * Create a mock signer instance for the tests.
     * This method can be overridden in test classes for extending signers that
     * want to inherit the tests from this class.
     * 
     * @param token Mock crypto token to use
     * @return Mock implementation
     */
    protected CMSSigner createMockSigner(final MockedCryptoToken token) {
        return new MockedCMSSigner(token);
    }
}
