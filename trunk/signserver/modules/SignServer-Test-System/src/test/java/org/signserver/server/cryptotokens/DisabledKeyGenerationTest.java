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
package org.signserver.server.cryptotokens;

import java.nio.charset.StandardCharsets;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static junit.framework.TestCase.fail;
import org.apache.log4j.Logger;
import org.junit.Assume;
import org.junit.Test;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;

/**
 * Test for the key generation disabling feature in WorkerSessionBean and that
 * is configured in conf/signserverd_deploy.properties.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class DisabledKeyGenerationTest {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DisabledKeyGenerationTest.class);
    
    private final ModulesTestCase helper = new ModulesTestCase();
    
    /**
     * Assuming test-config.properties is confgured with 
     * test.disablekeygen.disabled=false (default), this test checks that the
     * key generation throws an exception.
     * 
     * Note that this test also assumes that conf/signserver_deploy.properties
     * is configured with cryptotoken.disablekeygeneration=true.
     * 
     * As this could make other tests fail (i.e. those using key generation),
     * one probably need to disable this test and run it separately.
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testWorkerSessionKeyGeneration() throws Exception {
        LOG.info("This test assumes test.disablekeygen.disabled=false and that conf/signserver_deploy.properties is configured with cryptotoken.disablekeygeneration=true.");
        Assume.assumeFalse("true".equalsIgnoreCase(helper.getConfig().getProperty("test.disablekeygen.disabled")));

        try {
            helper.addDummySigner1(true);
            helper.getWorkerSession().generateSignerKey(new WorkerIdentifier(helper.getSignerIdDummy1()), "RSA", "2048", "newkey", "foo123".toCharArray());
            fail("Should have thrown CryptoTokenOfflineException(\"Key generation has been disabled\")");
        } catch (CryptoTokenOfflineException ex) {
            assertEquals("Key generation has been disabled", ex.getMessage());
        } finally {
            helper.removeWorker(helper.getSignerIdDummy1());
        }
    }
    
    /**
     * Same test as for WorkerSession but using CLI.
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testAdminCLIKeyGeneration() throws Exception {
        LOG.info("This test assumes test.disablekeygen.disabled=false and that conf/signserver_deploy.properties is configured with cryptotoken.disablekeygeneration=true.");
        Assume.assumeFalse("true".equalsIgnoreCase(helper.getConfig().getProperty("test.disablekeygen.disabled")));

        try {
            helper.addDummySigner1(true);
            CLITestHelper cli = helper.getAdminCLI();
            
            int ret = cli.execute("generatekey", String.valueOf(helper.getSignerIdDummy1()), "-keyalg", "RSA", "-keyspec", "2048", "-alias", "newkey");
            String error = cli.getErr().toString(StandardCharsets.UTF_8.name());
            assertTrue("Error: " + error, error.contains("Key generation has been disabled"));
        } catch (UnexpectedCommandFailureException ex) {
            assertEquals("Key generation has been disabled", ex.getCause().getMessage());
        } finally {
            helper.removeWorker(helper.getSignerIdDummy1());
        }
    }

}
