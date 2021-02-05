/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.apk.signer;

import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.internal.util.ByteArrayDataSink;
import com.novell.ldap.util.Base64;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;

/**
 * Unit tests for ApkSigner.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ApkSignerUnitTest {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ApkSignerUnitTest.class);

    private static MockedCryptoToken tokenRSA;
    private static MockedCryptoToken tokenRSANew;
    private static final String DEFAULT_KEY = "defaultkey";

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPair signerKeyPair;
        final String signatureAlgorithm;
        signerKeyPair = CryptoUtils.generateRSA(1024);
        signatureAlgorithm = "SHA256withRSA";
        Certificate[] certChain =
                new Certificate[] {new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSelfSignKeyPair(signerKeyPair).
                        setNotBefore(new Date()).
                        setSignatureAlgorithm(signatureAlgorithm)
                        .build())};
        Certificate signerCertificate = certChain[0];
        tokenRSA = new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), "BC");
    
        signerKeyPair = CryptoUtils.generateRSA(1024);
        certChain =
                new Certificate[] {new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSelfSignKeyPair(signerKeyPair).
                        setNotBefore(new Date()).
                        setSignatureAlgorithm(signatureAlgorithm)
                        .build())};
        signerCertificate = certChain[0];
        tokenRSANew = new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), "BC");

    }

    /**
     * Test that setting a value other than "true" or "false" for V1_SIGNATURE
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalV1Signature() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("V1_SIGNATURE", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property V1_SIGNATURE. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "true" for V1_SIGNATURE is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueV1Signature() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("V1_SIGNATURE", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property V1_SIGNATURE. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for V1_SIGNATURE is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseV1Signature() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("V1_SIGNATURE", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property V1_SIGNATURE. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for V1_SIGNATURE is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseV1Signature() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("V1_SIGNATURE", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property V1_SIGNATURE. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for V1_SIGNATURE is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseV1Signature() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("V1_SIGNATURE", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property V1_SIGNATURE. Only true, false, or empty is allowed."));
    }

    
    /**
     * Test that setting a value other than "true" or "false" for V2_SIGNATURE
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalV2Signature() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("V2_SIGNATURE", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property V2_SIGNATURE. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "true" for V2_SIGNATURE is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueV2Signature() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("V2_SIGNATURE", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property V2_SIGNATURE. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for V2_SIGNATURE is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseV2Signature() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("V2_SIGNATURE", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property V2_SIGNATURE. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for V2_SIGNATURE is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseV2Signature() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("V2_SIGNATURE", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property V2_SIGNATURE. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for V2_SIGNATURE is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseV2Signature() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("V2_SIGNATURE", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property V2_SIGNATURE. Only true, false, or empty is allowed."));
    }
    
    /**
     * Test that setting a value other than "true" or "false" for V3_SIGNATURE
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalV3Signature() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("V3_SIGNATURE", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property V3_SIGNATURE. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "true" for V3_SIGNATURE is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueV3Signature() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("V3_SIGNATURE", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property V3_SIGNATURE. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for V3_SIGNATURE is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseV3Signature() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("V3_SIGNATURE", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property V3_SIGNATURE. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for V3_SIGNATURE is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseV3Signature() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("V3_SIGNATURE", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property V3_SIGNATURE. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for V3_SIGNATURE is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseV3Signature() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("V3_SIGNATURE", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property V3_SIGNATURE. Only true, false, or empty is allowed."));
    }
    
    /**
     * Test illegal value for MIN_SDK_VERSION.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalMinSDKVersion() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("MIN_SDK_VERSION", "foo");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property MIN_SDK_VERSION: foo"));
    }

    /**
     * Test zero value for MIN_SDK_VERSION should not be supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testZeroMinSDKVersion() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("MIN_SDK_VERSION", "0");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property MIN_SDK_VERSION: 0"));
    }

    /**
     * Test negative value for MIN_SDK_VERSION should not be supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testNegativeMinSDKVersion() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("MIN_SDK_VERSION", "-42");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property MIN_SDK_VERSION: -42"));
    }

    /**
     * Test illegal value for MAX_SDK_VERSION.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalMaxSDKVersion() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("MAX_SDK_VERSION", "foo");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property MAX_SDK_VERSION: foo"));
    }

    /**
     * Test zero value for MAX_SDK_VERSION should not be supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testZeroMaxSDKVersion() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("MAX_SDK_VERSION", "0");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property MAX_SDK_VERSION: 0"));
    }

    /**
     * Test negative value for MAX_SDK_VERSION should not be supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testNegativeMaxSDKVersion() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("MAX_SDK_VERSION", "-42");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property MAX_SDK_VERSION: -42"));
    }

    /**
     * Test that setting MAX_SDK_VERSION to less than MIN_SDK_VERSION is
     * not allowed.
     *
     * @throws Exception 
     */
    @Test
    public void testMaxSDKVersionLessThanMinSDKVersionNotAllowed() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("MAX_SDK_VERSION", "42");
        config.setProperty("MIN_SDK_VERSION", "43");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("MAX_SDK_VERSION can not be lower than MIN_SDK_VERSION"));
    }
    
    /**
     * Test that an illegal value for DEBUGGABLE_APK_PERMITTED results in an error.
     * @throws Exception 
     */
    @Test
    public void testIllegalDebuggableApkPermitted() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("DEBUGGABLE_APK_PERMITTED", "foo");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property DEBUGGABLE_APK_PERMITTED. Only true or false is allowed."));
    }

    /**
     * Test that true is allowed for DEBUGGABLE_APK_PERMITTED.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueDebuggableApkPermitted() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("DEBUGGABLE_APK_PERMITTED", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.toString().contains("Illegal value for property DEBUGGABLE_APK_PERMITTED. Only true or false is allowed."));
    }

    /**
     * Test that TRUE is allowed for DEBUGGABLE_APK_PERMITTED.
     *
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseDebuggableApkPermitted() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("DEBUGGABLE_APK_PERMITTED", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.toString().contains("Illegal value for property DEBUGGABLE_APK_PERMITTED. Only true or false is allowed."));
    }

    /**
     * Test that false is allowed for DEBUGGABLE_APK_PERMITTED.
     *
     * @throws Exception 
     */
    @Test
    public void testFalseDebuggableApkPermitted() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("DEBUGGABLE_APK_PERMITTED", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.toString().contains("Illegal value for property DEBUGGABLE_APK_PERMITTED. Only true or false is allowed."));
    }

    /**
     * Test that FALSE is allowed for DEBUGGABLE_APK_PERMITTED.
     *
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseDebuggableApkPermitted() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("DEBUGGABLE_APK_PERMITTED", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.toString().contains("Illegal value for property DEBUGGABLE_APK_PERMITTED. Only true or false is allowed."));
    }

    /**
     * Test that a malformed base64-encoded lineage is not accepted.
     *
     * @throws Exception 
     */
    @Test
    public void testIllegalLineageFileContent() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("LINEAGE_FILE_CONTENT", "====");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal base64 value for LINEAGE_FILE_CONTENT"));
    }

    /**
     * Test that valid base64-encoded, but not valid lineage gives the correct
     * error.
     *
     * @throws Exception 
     */
    @Test
    public void testInvaldLinageLegalBase64FileContent() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("LINEAGE_FILE_CONTENT", "Zm9vMTIzCg==");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Should not contain error: " + errors.toString(),
                   errors.contains("Illegal base64 value for LINEAGE_FILE_CONTENT"));
        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Failed to parse lineage: Improper SigningCertificateLineage format: insufficient data for header."));
    }

    /**
     * Test that setting a valid lineage file content does not give an error.
     *
     * @throws Exception 
     */
    @Test
    public void testValidLineage() throws Exception {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();
        final SigningCertificateLineage lineage = createLineage();
        final ByteArrayDataSink sink = new ByteArrayDataSink();
        
        lineage.writeToDataSink(sink);
        final ByteBuffer buffer = sink.getByteBuffer(0L, (int) sink.size());
        
        config.setProperty("LINEAGE_FILE_CONTENT", Base64.encode(buffer.array()));
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Should not contain error: " + errors.toString(),
                    errors.contains("Illegal base64 value for LINEAGE_FILE_CONTENT"));
        assertFalse("Should not contain error: " + errors.toString(),
                    errors.toString().contains("Failed to parse lineage"));
    }

    /**
     * Test setting an illegal value for ALLOW_V1_SIGNATURE_OVERRIDE.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalAllowV1SignatureOverride() throws Exception {
        testIllegalAllowOverride("ALLOW_V1_SIGNATURE_OVERRIDE");
    }

    /**
     * Test setting true for ALLOW_V1_SIGNATURE_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowV1SignatureOverrideTrue() throws Exception {
        testAllowOverrideNoError("ALLOW_V1_SIGNATURE_OVERRIDE", "true");
    }

    /**
     * Test setting false for ALLOW_V1_SIGNATURE_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowV1SignatureOverrideFalse() throws Exception {
        testAllowOverrideNoError("ALLOW_V1_SIGNATURE_OVERRIDE", "false");
    }

    /**
     * Test setting TRUE for ALLOW_V1_SIGNATURE_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowV1SignatureOverrideTrueUpperCase() throws Exception {
        testAllowOverrideNoError("ALLOW_V1_SIGNATURE_OVERRIDE", "TRUE");
    }

    /**
     * Test setting FALSE for ALLOW_V1_SIGNATURE_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowV1SignatureOverrideFalseUpperCase() throws Exception {
        testAllowOverrideNoError("ALLOW_V1_SIGNATURE_OVERRIDE", "FALSE");
    }

    /**
     * Test setting an illegal value for ALLOW_V2_SIGNATURE_OVERRIDE.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalAllowV2SignatureOverride() throws Exception {
        testIllegalAllowOverride("ALLOW_V2_SIGNATURE_OVERRIDE");
    }

    /**
     * Test setting true for ALLOW_V2_SIGNATURE_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowV2SignatureOverrideTrue() throws Exception {
        testAllowOverrideNoError("ALLOW_V2_SIGNATURE_OVERRIDE", "true");
    }

    /**
     * Test setting false for ALLOW_V2_SIGNATURE_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowV2SignatureOverrideFalse() throws Exception {
        testAllowOverrideNoError("ALLOW_V2_SIGNATURE_OVERRIDE", "false");
    }

    /**
     * Test setting TRUE for ALLOW_V2_SIGNATURE_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowV2SignatureOverrideTrueUpperCase() throws Exception {
        testAllowOverrideNoError("ALLOW_V2_SIGNATURE_OVERRIDE", "TRUE");
    }

    /**
     * Test setting FALSE for ALLOW_V2_SIGNATURE_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowV2SignatureOverrideFalseUpperCase() throws Exception {
        testAllowOverrideNoError("ALLOW_V2_SIGNATURE_OVERRIDE", "FALSE");
    }

    /**
     * Test setting an illegal value for ALLOW_V3_SIGNATURE_OVERRIDE.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalAllowV3SignatureOverride() throws Exception {
        testIllegalAllowOverride("ALLOW_V3_SIGNATURE_OVERRIDE");
    }

    /**
     * Test setting true for ALLOW_V3_SIGNATURE_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowV3SignatureOverrideTrue() throws Exception {
        testAllowOverrideNoError("ALLOW_V3_SIGNATURE_OVERRIDE", "true");
    }

    /**
     * Test setting false for ALLOW_V3_SIGNATURE_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowV3SignatureOverrideFalse() throws Exception {
        testAllowOverrideNoError("ALLOW_V3_SIGNATURE_OVERRIDE", "false");
    }

    /**
     * Test setting TRUE for ALLOW_V3_SIGNATURE_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowV3SignatureOverrideTrueUpperCase() throws Exception {
        testAllowOverrideNoError("ALLOW_V3_SIGNATURE_OVERRIDE", "TRUE");
    }

    /**
     * Test setting FALSE for ALLOW_V3_SIGNATURE_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowV3SignatureOverrideFalseUpperCase() throws Exception {
        testAllowOverrideNoError("ALLOW_V3_SIGNATURE_OVERRIDE", "FALSE");
    }

    /**
     * Test setting an illegal value for ALLOW_MIN_SDK_VERSION_OVERRIDE.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalAllowMinSDKVersionOverride() throws Exception {
        testIllegalAllowOverride("ALLOW_MIN_SDK_VERSION_OVERRIDE");
    }

    /**
     * Test setting true for ALLOW_MIN_SDK_VERSION_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowMinSDKVersionOverrideTrue() throws Exception {
        testAllowOverrideNoError("ALLOW_MIN_SDK_VERSION_OVERRIDE", "true");
    }

    /**
     * Test setting false for ALLOW_MIN_SDK_VERSION_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowMinSDKVersionOverrideFalse() throws Exception {
        testAllowOverrideNoError("ALLOW_MIN_SDK_VERSION_OVERRIDE", "false");
    }

    /**
     * Test setting TRUE for ALLOW_MIN_SDK_VERSION_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowMinSDKVersionTrueUpperCase() throws Exception {
        testAllowOverrideNoError("ALLOW_MIN_SDK_VERSION_OVERRIDE", "TRUE");
    }

    /**
     * Test setting FALSE for ALLOW_MIN_SDK_VERSION_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowMinSDKVersionOverrideFalseUpperCase() throws Exception {
        testAllowOverrideNoError("ALLOW_MIN_SDK_VERSION_OVERRIDE", "FALSE");
    }

    /**
     * Test setting an illegal value for ALLOW_MAX_SDK_VERSION_OVERRIDE.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalAllowMaxSDKVersionOverride() throws Exception {
        testIllegalAllowOverride("ALLOW_MAX_SDK_VERSION_OVERRIDE");
    }

    /**
     * Test setting true for ALLOW_MAX_SDK_VERSION_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowMaxSDKVersionOverrideTrue() throws Exception {
        testAllowOverrideNoError("ALLOW_MAX_SDK_VERSION_OVERRIDE", "true");
    }

    /**
     * Test setting false for ALLOW_MAX_SDK_VERSION_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowMaxSDKVersionOverrideFalse() throws Exception {
        testAllowOverrideNoError("ALLOW_MAX_SDK_VERSION_OVERRIDE", "false");
    }

    /**
     * Test setting TRUE for ALLOW_MAX_SDK_VERSION_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowMaxSDKVersionTrueUpperCase() throws Exception {
        testAllowOverrideNoError("ALLOW_MAX_SDK_VERSION_OVERRIDE", "TRUE");
    }

    /**
     * Test setting FALSE for ALLOW_MAX_SDK_VERSION_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowMaxSDKVersionOverrideFalseUpperCase() throws Exception {
        testAllowOverrideNoError("ALLOW_MAX_SDK_VERSION_OVERRIDE", "FALSE");
    }

    /**
     * Test setting an illegal value for ALLOW_DEBUGGABLE_APK_PERMITTED_OVERRIDE.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalAllowDebuggableApkPermittedOverride() throws Exception {
        testIllegalAllowOverride("ALLOW_DEBUGGABLE_APK_PERMITTED_OVERRIDE");
    }

    /**
     * Test setting true for ALLOW_DEBUGGABLE_APK_PERMITTED_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowDebuggableApkPermittedOverrideTrue() throws Exception {
        testAllowOverrideNoError("ALLOW_DEBUGGABLE_APK_PERMITTED_OVERRIDE", "true");
    }

    /**
     * Test setting false for ALLOW_DEBUGGABLE_APK_PERMITTED_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowDebuggableApkPermittedOverrideFalse() throws Exception {
        testAllowOverrideNoError("ALLOW_DEBUGGABLE_APK_PERMITTED_OVERRIDE", "false");
    }

    /**
     * Test setting TRUE for ALLOW_DEBUGGABLE_APK_PERMITTED_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowDebuggableApkPermittedTrueUpperCase() throws Exception {
        testAllowOverrideNoError("ALLOW_DEBUGGABLE_APK_PERMITTED_OVERRIDE", "TRUE");
    }

    /**
     * Test setting FALSE for ALLOW_DEBUGGABLE_APK_PERMITTED_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowDebuggableApkPermittedFalseUpperCase() throws Exception {
        testAllowOverrideNoError("ALLOW_DEBUGGABLE_APK_PERMITTED_OVERRIDE", "FALSE");
    }

    /**
     * Test setting an illegal value for ALLOW_V1_SIGNATURE_NAME_OVERRIDE.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalAllowV1SignatureNameOverride() throws Exception {
        testIllegalAllowOverride("ALLOW_V1_SIGNATURE_NAME_OVERRIDE");
    }

    /**
     * Test setting true for ALLOW_V1_SIGNATURE_NAME_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowV1SignatureNameOverrideTrue() throws Exception {
        testAllowOverrideNoError("ALLOW_V1_SIGNATURE_NAME_OVERRIDE", "true");
    }

    /**
     * Test setting false for ALLOW_V1_SIGNATURE_NAME_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowV1SignatureNameOverrideFalse() throws Exception {
        testAllowOverrideNoError("ALLOW_V1_SIGNATURE_NAME_OVERRIDE", "false");
    }

    /**
     * Test setting TRUE for ALLOW_V1_SIGNATURE_NAME_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowV1SignatureNameTrueUpperCase() throws Exception {
        testAllowOverrideNoError("ALLOW_V1_SIGNATURE_NAME_OVERRIDE", "TRUE");
    }

    /**
     * Test setting FALSE for ALLOW_V1_SIGNATURE_NAME_OVERRIDE.
     *
     * @throws Exception 
     */
    @Test
    public void testAllowV1SignatureNameFalseUpperCase() throws Exception {
        testAllowOverrideNoError("ALLOW_V1_SIGNATURE_NAME_OVERRIDE", "FALSE");
    }

    private void testIllegalAllowOverride(final String property) {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty(property, "foo");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);
        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for " + property + ": foo"));
    }

    private void testAllowOverrideNoError(final String property, final String value) {
        final ApkSigner instance = new MockedApkSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty(property, value);
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);
        assertFalse("Does not contain error: " + errors.toString(),
                    errors.contains("Illegal value for " + property + ": " + value));
    }
    
    /**
     * Create a test lineage given the two test tokens, old and new.
     * 
     * @return SigningCertificateLineage
     * @throws Exception 
     */
    private SigningCertificateLineage createLineage() throws Exception {
        SigningCertificateLineage.SignerConfig oldSignerConfig =
                createSignerConfig(tokenRSA.getPrivateKey(0),
                                   (X509Certificate) tokenRSA.getCertificate(0));

        SigningCertificateLineage.SignerConfig newSignerConfig =
                createSignerConfig(tokenRSANew.getPrivateKey(0),
                                   (X509Certificate) tokenRSANew.getCertificate(0));

        return new SigningCertificateLineage.Builder(oldSignerConfig, newSignerConfig).build();
    }

    private SigningCertificateLineage.SignerConfig createSignerConfig(final PrivateKey privateKey,
                                                                      final X509Certificate cert) {
        return new SigningCertificateLineage.SignerConfig.Builder(privateKey, cert).build();
    }
}
