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
package org.signserver.module.apk.signer;

import java.util.List;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.server.SignServerContext;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.MockedServicesImpl;

/**
 * Unit tests for the ApkLineageSigner.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ApkLineageSignerUnitTest {

    private static MockedServicesImpl services;

    @BeforeClass
    public static void setupUpClass() throws Exception {
        final GlobalConfigurationSessionMock globalMock =
                new GlobalConfigurationSessionMock();
        services = new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, globalMock);
    }
    
    /**
     * Test that setting OTHER_SIGNERS pointing to exactly one signer does not
     * give an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testValidOtherSigners() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OTHER_SIGNERS", "ApkSigner");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Errors should not mention OTHER_SIGNERS: " + errors.toString(),
                    errors.toString().contains("OTHER_SIGNERS"));
    }

    /**
     * Test that not setting OTHER_SIGNERS gives an error.
     *
     * @throws Exception 
     */
    @Test
    public void testMissingOtherSigners() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Must specify OTHER_SIGNERS."));
    }

    /**
     * Test that setting an empty OTHER_SIGNERS gives an error.
     *
     * @throws Exception 
     */
    @Test
    public void testEmptyOtherSigners() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OTHER_SIGNERS", "");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Must specify OTHER_SIGNERS."));
    }

    /**
     * Test that setting an blank (whitespace) OTHER_SIGNERS gives an error.
     *
     * @throws Exception 
     */
    @Test
    public void testBlankOtherSigners() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OTHER_SIGNERS", " ");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Must specify OTHER_SIGNERS."));
    }

    /**
     * Test that setting more one signer in OTHER_SIGNERS gives an error.
     *
     * @throws Exception 
     */
    @Test
    public void testTooManyOtherSigners() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("OTHER_SIGNERS", "ApkSigner, YetAnotherApkSigner");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("OTHER_SIGNERS should contain one signer."));
    }

    /**
     * Test that setting a value other than "true" or "false" for SET_INSTALLED_DATA
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalSetInstalledData() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_INSTALLED_DATA", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_INSTALLED_DATA. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "true" for SET_INSTALLED_DATA is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueSetInstalledData() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_INSTALLED_DATA", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_INSTALLED_DATA. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for SET_INSTALLED_DATA is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseSetInstalledData() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_INSTALLED_DATA", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_INSTALLED_DATA. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for SET_INSTALLED_DATA is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseSetInstalledData() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_INSTALLED_DATA", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_INSTALLED_DATA. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for SET_INSTALLED_DATA is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseSetInstalledData() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_INSTALLED_DATA", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_INSTALLED_DATA. Only true, false, or empty is allowed."));
    }

    /**
     * Test that setting a value other than "true" or "false" for SET_SHARED_UID
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalSetSharedUid() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_SHARED_UID", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_SHARED_UID. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "true" for SET_SHARED_UID is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueSetSharedUid() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_SHARED_UID", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_SHARED_UID. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for SET_SHARED_UID is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseSetSharedUid() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_SHARED_UID", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_SHARED_UID. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for SET_SHARED_UID is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseSetSharedUid() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_SHARED_UID", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_SHARED_UID. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for SET_SHARED_UID is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseSharedUid() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_SHARED_UID", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_SHARED_UID. Only true, false, or empty is allowed."));
    }

    /**
     * Test that setting a value other than "true" or "false" for SET_PERMISSION
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalSetPermission() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_PERMISSION", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_PERMISSION. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "true" for SET_PERMISSION is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueSetPermission() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_PERMISSION", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_PERMISSION. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for SET_PERMISSION is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseSetPermission() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_PERMISSION", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_PERMISSION. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for SET_PERMISSION is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseSetPermission() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_PERMISSION", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_PERMISSION. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for SET_PERMISSION is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseSetPermission() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_PERMISSION", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_PERMISSIONs. Only true, false, or empty is allowed."));
    }

    /**
     * Test that setting a value other than "true" or "false" for SET_ROLLBACK
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalSetRollback() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_ROLLBACK", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_ROLLBACK. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "true" for SET_ROLLBACK is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueSetRollback() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_ROLLBACK", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_ROLLBACK. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for SET_ROLLBACK is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseSetRollback() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_ROLLBACK", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_ROLLBACK. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for SET_ROLLBACK is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseSetRollback() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_ROLLBACK", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_ROLLBACK. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for SET_ROLLBACK is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseSetRollback() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_ROLLBACK", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_ROLLBACK. Only true, false, or empty is allowed."));
    }

    /**
     * Test that setting a value other than "true" or "false" for SET_AUTH
     * results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalSetAuth() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_AUTH", "_illegal_");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertTrue("Contains error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_AUTH. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "true" for SET_AUTH is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueSetAuth() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_AUTH", "true");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_AUTH. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "TRUE" for SET_AUTH is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrueUpperCaseSetAuth() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_AUTH", "TRUE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_AUTH. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "false" for SET_AUTH is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseSetAuth() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_AUTH", "false");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_AUTH. Only true, false, or empty is allowed."));
    }

    /**
     * Test that specifying "FALSE" for SET_AUTH is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testFalseUpperCaseSetAuth() throws Exception {
        final ApkLineageSigner instance = new ApkLineageSigner();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("SET_AUTH", "FALSE");
        instance.init(42, config, new SignServerContext(), null);

        final List<String> errors = instance.getFatalErrors(services);

        assertFalse("Does not contain error: " + errors.toString(),
                   errors.contains("Illegal value for property SET_AUTH. Only true, false, or empty is allowed."));
    }

}
