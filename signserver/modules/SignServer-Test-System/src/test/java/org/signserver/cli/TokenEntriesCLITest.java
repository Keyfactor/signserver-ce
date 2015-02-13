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
package org.signserver.cli;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import static junit.framework.TestCase.assertEquals;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.SignServerUtil;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.cryptotokens.KeystoreInConfigCryptoToken;
import org.signserver.server.cryptotokens.P12CryptoToken;
import org.signserver.testutils.CLITestHelper;
import static org.signserver.testutils.CLITestHelper.assertPrinted;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests for the query token entries command.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TokenEntriesCLITest extends ModulesTestCase {
    private final CLITestHelper cli = getAdminCLI();
    
    protected final IWorkerSession workerSession = getWorkerSession();
    protected final IGlobalConfigurationSession globalSession = getGlobalSession();

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
    }

    /**
     * Tests that there is an error if the token argument is missing.
     * @throws Exception 
     */
    @Test
    public void testNoArguments() throws Exception {
        // make sure an error message is printed if not setting the mandatory -token argument
        assertEquals("", CommandLineInterface.RETURN_INVALID_ARGUMENTS, cli.execute("querytokenentries"));
        assertPrinted("Should output error", cli.getOut(), "Missing required option: token");
    }

    /**
     * Tests querying one entry.
     * @throws Exception 
     */
    @Test
    public void testQueryOneKey() throws Exception {
        final int tokenId = 40301;
        final String testKeyAlias1 = "testKeyAlias1";
        final File ks = createEmptyKeystore();
        try {
            globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + tokenId + ".CLASSPATH", "org.signserver.server.signers.CryptoWorker");
            globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + tokenId + ".SIGNERTOKEN.CLASSPATH", P12CryptoToken.class.getName());
            workerSession.setWorkerProperty(tokenId, "NAME", "TestP12CryptoToken" + tokenId);
            workerSession.setWorkerProperty(tokenId, "KEYSTOREPATH", ks.getAbsolutePath());
            workerSession.setWorkerProperty(tokenId, "KEYSTOREPASSWORD", "foo123");
            workerSession.reloadConfiguration(tokenId);
            workerSession.generateSignerKey(tokenId, "RSA", "512", testKeyAlias1, "foo123".toCharArray());
            
            assertEquals(CommandLineInterface.RETURN_SUCCESS,
                     cli.execute("querytokenentries", "-token", String.valueOf(tokenId), "-from", "0", "-limit", "1", "-criteria", "alias LIKE %KeyAlias%"));
            assertPrinted("Should contain entries", cli.getOut(), "0: testKeyAlias1");
            
        } finally {
            FileUtils.deleteQuietly(ks);
            removeWorker(tokenId);
        }
    }

    /**
     * Tests that it is possible to query all entries in a token with 13
     * entries, knowing that the CLI command makes the query in batches of 10
     * entries.
     * @throws Exception 
     */
    @Test
    public void testQueryMoreThan10Keys() throws Exception {
        final int tokenId = 40302;
        final List<String> aliases = new ArrayList<String> ();
        for (int i = 0; i < 13; i++) {
            aliases.add("testKey-" + i);
        }
        final File ks = createEmptyKeystore();
        try {
            globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + tokenId + ".CLASSPATH", "org.signserver.server.signers.CryptoWorker");
            globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + tokenId + ".SIGNERTOKEN.CLASSPATH", KeystoreInConfigCryptoToken.class.getName());
            workerSession.setWorkerProperty(tokenId, "NAME", "TestP12CryptoToken" + tokenId);
            workerSession.setWorkerProperty(tokenId, "KEYSTOREPATH", ks.getAbsolutePath());
            workerSession.setWorkerProperty(tokenId, "KEYSTOREPASSWORD", "foo123");
            workerSession.reloadConfiguration(tokenId);
            
            for (String alias : aliases) {
                workerSession.generateSignerKey(tokenId, "RSA", "512", alias, "foo123".toCharArray());
            }

            assertEquals(CommandLineInterface.RETURN_SUCCESS,
                     cli.execute("querytokenentries", "-token", String.valueOf(tokenId)));
            String output = cli.getOut().toString("UTF-8");
            for (String alias : aliases) {
                assertTrue("should contain: " + alias + " but was " + output, output.contains(alias));
            }
        } finally {
            FileUtils.deleteQuietly(ks);
            removeWorker(tokenId);
        }
    }
    
    private File createEmptyKeystore() throws Exception {
        SignServerUtil.installBCProvider();
        File result = File.createTempFile("TokenEntriesCLITest", ".p12");
        FileOutputStream out = null;
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(null, null);
            out = new FileOutputStream(result);
            ks.store(out, "foo123".toCharArray());
        } finally {
            IOUtils.closeQuietly(out);
        }
        return result;
    }
}
