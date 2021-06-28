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

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
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
 * Unit tests for ApkRotateSigner.
 *  
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ApkRotateSignerUnitTest {

    private static MockedCryptoToken tokenRSA;
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
    }

    /**
     * Test that setting OTHER_SIGNERS pointing to exactly two signers does not
     * give an error.
     * 
     * @throws Exception
     */
    @Test
    public void testValidNextSigners() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OTHER_SIGNERS", "ApkSignerOld, ApkSignerNew");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Errors should not mention OTHER_SIGNERS: " + errors.toString(),
                    errors.toString().contains("OTHER_SIGNERS"));
    }

    /**
     * Test that not setting OTHER_SIGNERS gives an error.
     *
     * @throws Exception 
     */
    @Test
    public void testMissingNextSigners() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Must specify OTHER_SIGNERS."));
    }

    /**
     * Test that setting an empty OTHER_SIGNERS gives an error.
     *
     * @throws Exception 
     */
    @Test
    public void testEmptyNextSigners() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OTHER_SIGNERS", "");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Must specify OTHER_SIGNERS."));
    }

    /**
     * Test that setting an blank (whitespace) OTHER_SIGNERS gives an error.
     *
     * @throws Exception 
     */
    @Test
    public void testBlankNextSigners() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OTHER_SIGNERS", " ");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Must specify OTHER_SIGNERS."));
    }

    /**
     * Test that setting more two signer (old and new) in OTHER_SIGNERS gives an error.
     *
     * @throws Exception 
     */
    @Test
    public void testTooManyNextSigners() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OTHER_SIGNERS", "ApkSignerNew, ApkSignerNew2, YetAnotherApkSigner");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("OTHER_SIGNERS should contain two signers (old and new)."));
    }

    /**
     * Test that setting a value other than "true" or "false" for OLD_SET_INSTALLED_DATA
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalOldSetInstalledData() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_INSTALLED_DATA", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_INSTALLED_DATA. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "true" for OLD_SET_INSTALLED_DATA is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueOldSetInstalledData() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_INSTALLED_DATA", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_INSTALLED_DATA. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for OLD_SET_INSTALLED_DATA is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseOldSetInstalledData() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_INSTALLED_DATA", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_INSTALLED_DATA. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for OLD_SET_INSTALLED_DATA is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseOldSetInstalledData() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_INSTALLED_DATA", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_INSTALLED_DATA. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for OLD_SET_INSTALLED_DATA is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseOldSetInstalledData() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_INSTALLED_DATA", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_INSTALLED_DATA. Only true, false, or empty is allowed."));
    }

    /**
     * Test that setting a value other than "true" or "false" for OLD_SET_SHARED_UID
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalOldSetSharedUid() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_SHARED_UID", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_SHARED_UID. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "true" for OLD_SET_SHARED_UID is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueOldSetSharedUid() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_SHARED_UID", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_SHARED_UID. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for OLD_SET_SHARED_UID is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseOldSetSharedUid() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_SHARED_UID", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_SHARED_UID. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for OLD_SET_SHARED_UID is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseOldSetSharedUid() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_SHARED_UID", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_SHARED_UID. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for OLD_SET_SHARED_UID is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseOldSetSharedUid() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_SHARED_UID", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_SHARED_UID. Only true, false, or empty is allowed."));
    }

    /**
     * Test that setting a value other than "true" or "false" for OLD_SET_PERMISSION
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalOldSetPermission() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_PERMISSION", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_PERMISSION. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "true" for OLD_SET_PERMISSION is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueOldSetPermission() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_PERMISSION", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_PERMISSION. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for OLD_SET_PERMISSION is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseOldSetPermission() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_PERMISSION", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_PERMISSION. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for OLD_SET_PERMISSION is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseOldSetPermission() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_PERMISSION", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_PERMISSION. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for OLD_SET_PERMISSION is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseOldSetPermission() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_PERMISSION", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_PERMISSION. Only true, false, or empty is allowed."));
    }

    /**
     * Test that setting a value other than "true" or "false" for OLD_SET_ROLLBACK
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalOldSetRollback() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_ROLLBACK", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_ROLLBACK. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "true" for OLD_SET_ROLLBACK is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueOldSetRollback() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_ROLLBACK", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_ROLLBACK. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for OLD_SET_ROLLBACK is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseOldSetRollback() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_ROLLBACK", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_ROLLBACK. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for OLD_SET_ROLLBACK is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseOldSetRollback() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_ROLLBACK", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_ROLLBACK. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for OLD_SET_ROLLBACK is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseOldSetRollback() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_ROLLBACK", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_ROLLBACK. Only true, false, or empty is allowed."));
    }

/**
     * Test that setting a value other than "true" or "false" for OLD_SET_AUTH
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalOldSetAuth() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_AUTH", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_AUTH. Only true, false, or empty is allowed."));
    }
    
    /**
     * Test that specifying "true" for OLD_SET_AUTH is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueOldSetAuth() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_AUTH", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_AUTH. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for OLD_SET_AUTH is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseOldSetAuth() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_AUTH", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_AUTH. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for OLD_SET_AUTH is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseOldSetAuth() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_AUTH", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_AUTH. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for OLD_SET_AUTH is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseOldSetAuth() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OLD_SET_AUTH", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property OLD_SET_AUTH. Only true, false, or empty is allowed."));
    }

    /**
     * Test that setting a value other than "true" or "false" for NEW_SET_INSTALLED_DATA
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalNewSetInstalledData() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_INSTALLED_DATA", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_INSTALLED_DATA. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "true" for NEW_SET_INSTALLED_DATA is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueNewSetInstalledData() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_INSTALLED_DATA", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_INSTALLED_DATA. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for NEW_SET_INSTALLED_DATA is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseNewSetInstalledData() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_INSTALLED_DATA", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_INSTALLED_DATA. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for NEW_SET_INSTALLED_DATA is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseNewSetInstalledData() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_INSTALLED_DATA", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_INSTALLED_DATA. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for NEW_SET_INSTALLED_DATA is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseNewSetInstalledData() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_INSTALLED_DATA", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_INSTALLED_DATA. Only true, false, or empty is allowed."));
    }

    /**
     * Test that setting a value other than "true" or "false" for NEW_SET_SHARED_UID
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalNewSetSharedUid() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_SHARED_UID", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_SHARED_UID. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "true" for NEW_SET_SHARED_UID is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueNewSetSharedUid() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_SHARED_UID", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_SHARED_UID. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for NEW_SET_SHARED_UID is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseNewSetSharedUid() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_SHARED_UID", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_SHARED_UID. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for NEW_SET_SHARED_UID is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseNewSetSharedUid() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_SHARED_UID", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_SHARED_UID. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for NEW_SET_SHARED_UID is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseNewSetSharedUid() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_SHARED_UID", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_SHARED_UID. Only true, false, or empty is allowed."));
    }

    /**
     * Test that setting a value other than "true" or "false" for NEW_SET_PERMISSION
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalNewSetPermission() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_PERMISSION", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_PERMISSION. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "true" for NEW_SET_PERMISSION is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueNewSetPermission() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_PERMISSION", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_PERMISSION. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for NEW_SET_PERMISSION is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseNewSetPermission() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_PERMISSION", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_PERMISSION. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for NEW_SET_PERMISSION is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseNewSetPermission() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_PERMISSION", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_PERMISSION. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for NEW_SET_PERMISSION is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseNewSetPermission() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_PERMISSION", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_PERMISSION. Only true, false, or empty is allowed."));
    }

    /**
     * Test that setting a value other than "true" or "false" for NEW_SET_ROLLBACK
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalNewSetRollback() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_ROLLBACK", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_ROLLBACK. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "true" for NEW_SET_ROLLBACK is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueNewSetRollback() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_ROLLBACK", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_ROLLBACK. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for NEW_SET_ROLLBACK is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseNewSetRollback() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_ROLLBACK", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_ROLLBACK. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for NEW_SET_ROLLBACK is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseNewSetRollback() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_ROLLBACK", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_ROLLBACK. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for NEW_SET_ROLLBACK is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseNewSetRollback() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_ROLLBACK", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_ROLLBACK. Only true, false, or empty is allowed."));
    }

    /**
     * Test that setting a value other than "true" or "false" for NEW_SET_AUTH
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalNewSetAuth() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_AUTH", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_AUTH. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "true" for NEW_SET_AUTH is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueNewSetAuth() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_AUTH", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_AUTH. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for NEW_SET_AUTH is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseNewSetAuth() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_AUTH", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_AUTH. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for NEW_SET_AUTH is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseNewSetAuth() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_AUTH", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_AUTH. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for NEW_SET_AUTH is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseNewSetAuth() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("NEW_SET_AUTH", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property NEW_SET_AUTH. Only true, false, or empty is allowed."));
    }

    /**
     * Test illegal value for MIN_SDK_VERSION.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalMinSDKVersion() throws Exception {
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
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
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
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
        final ApkRotateSigner instance = new MockedApkRotateSigner(DEFAULT_KEY, tokenRSA);
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("MIN_SDK_VERSION", "-42");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(null);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property MIN_SDK_VERSION: -42"));
    }

}
