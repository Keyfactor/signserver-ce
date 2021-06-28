/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.dnssec.signer;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Properties;
import static junit.framework.TestCase.assertTrue;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import static org.junit.Assert.assertEquals;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.signserver.client.cli.ClientCLI;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
import static org.signserver.module.dnssec.signer.ZoneFileServerSideSignerComplianceTest.DNSSEC_ENABLED;
import org.signserver.server.cryptotokens.PKCS11CryptoToken;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ComplianceTestUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * P11 Compliance test running dnssec-verify to verify signatures created by the
 * ZoneFileServerSideSigner. 
 * 
 * These tests can be disabled by setting the test.dnssec.enabled test
 * configuration parameter to false for test environments where the
 * dnssec-verify CLI tool is not available.
 *
 * @author Vinay Singh
 * @version $Id$
 */
@FixMethodOrder
@RunWith(Parameterized.class)
public class ZoneFileServerSideSignerP11ComplianceTest {
    
    /**
     * Logger for this class
     */
    private static final Logger LOG = Logger.getLogger(ZoneFileServerSideSignerP11ComplianceTest.class);
    private static final String DNSSEC_ENABLED = "test.dnssec.enabled";
    private static final String DNSSEC_VERIFY_PATH = "test.dnssec-verify.path";    

    private static final int CRYPTO_TOKEN = 13100;
    private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenZoneFileServerSideSignerP11";
    private static final int WORKER_ID = 17901;
    private static final String WORKER_NAME = "TestZoneFileServerSideP11Signer";    

    private final ModulesTestCase helper = new ModulesTestCase();
    private static final CLITestHelper cli = new CLITestHelper(ClientCLI.class);
    
    private final String sharedLibraryName;
    private final String slot;
    private final String pin;
    private final String existingKey1;    
    
    private static boolean enabled;
    private static String dnssecVerifyCommand;
    private final File inputZoneFile;

    @BeforeClass
    public static void setUpClass() throws IOException {
        final Properties config = new ModulesTestCase().getConfig();
        enabled = !Boolean.FALSE.toString().trim().equalsIgnoreCase(config.getProperty(DNSSEC_ENABLED));
        final String dnssecVerifyPath = config.getProperty(DNSSEC_VERIFY_PATH);

        dnssecVerifyCommand =
                StringUtils.isNotBlank(dnssecVerifyPath) ? dnssecVerifyPath : "dnssec-verify";
    }

    @Before
    public void setUpTest() {
        Assume.assumeTrue("dnssec enabled", enabled);
    }
    
    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> generateData() throws FileNotFoundException {
        final LinkedList<Object[]> data = new LinkedList<>();
        File folder = new File(PathUtil.getAppHome(), "dnssec-test-files");
        if (folder.exists()) {
            for (File file : folder.listFiles()) {
                data.add(new Object[]{file.getName(), file});
            }
        } else {
            LOG.error("Folder with zone files does not exist so not running any tests: " + folder.getAbsolutePath());
        }
        return data;
    }

    public ZoneFileServerSideSignerP11ComplianceTest(final String title, final File inputFile) throws FileNotFoundException {        
        this.inputZoneFile = inputFile;
        sharedLibraryName = helper.getConfig().getProperty("test.p11.sharedLibraryName");
        slot = helper.getConfig().getProperty("test.p11.slot");
        pin = helper.getConfig().getProperty("test.p11.pin");
        existingKey1 = helper.getConfig().getProperty("test.p11.existingkey1");
    }
    
    private void setupCryptoTokenProperties(final int tokenId, final boolean cache) throws Exception {
        // Setup token
        helper.getWorkerSession().setWorkerProperty(tokenId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        helper.getWorkerSession().setWorkerProperty(tokenId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        helper.getWorkerSession().setWorkerProperty(tokenId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        helper.getWorkerSession().setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        helper.getWorkerSession().setWorkerProperty(tokenId, "SHAREDLIBRARYNAME", sharedLibraryName);
        helper.getWorkerSession().setWorkerProperty(tokenId, "SLOT", slot);
        helper.getWorkerSession().setWorkerProperty(tokenId, "PIN", pin);
        helper.getWorkerSession().setWorkerProperty(tokenId, "DEFAULTKEY", existingKey1); // Test key
        helper.getWorkerSession().setWorkerProperty(tokenId, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }

    private void setupWorkerProperties(final int workerId, final String zoneName) throws Exception {      
        String zskPrefix = zoneName + "_Z_";
        String ksk1 = zoneName+"_K_1";
        String ksk2 = zoneName+"_K_2";
        String activeKSKs = ksk1+","+ksk2;
        LOG.info("zoneName "+ zoneName);
        LOG.info("zskPrefix " + zskPrefix);
        LOG.info("activeKSKs " + activeKSKs);

        // Setup worker        
        helper.getWorkerSession().setWorkerProperty(workerId, "NAME", WORKER_NAME);
        helper.getWorkerSession().setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.dnssec.signer.ZoneFileServerSideSigner");
        helper.getWorkerSession().setWorkerProperty(workerId, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        helper.getWorkerSession().setWorkerProperty(workerId, "DISABLEKEYUSAGECOUNTER", "TRUE");
        helper.getWorkerSession().setWorkerProperty(workerId, "ZSK_KEY_ALIAS_PREFIX", zskPrefix);
        helper.getWorkerSession().setWorkerProperty(workerId, "ACTIVE_KSKS", activeKSKs);
        helper.getWorkerSession().setWorkerProperty(workerId, "ZONE_NAME", zoneName+".");
        helper.getWorkerSession().setWorkerProperty(workerId, "NSEC3_SALT", "6dcd4ce23d88e2ee");
        helper.getWorkerSession().setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
    }

    /**
     * Tests that the command "dnssec-verify -V" prints a reasonable message. And
     * log the version string, so that it's visible in the stdout from the test.
     *
     * @throws Exception
     */    
    private void testDNSSECVersion() throws Exception {
        final ComplianceTestUtils.ProcResult res
                = ComplianceTestUtils.execute(dnssecVerifyCommand, "-V");
        final String error = res.getErrorMessage();
        assertTrue("Contains version message", error.startsWith("dnssec-verify"));
        LOG.info("DNSSSEC version output: " + error);
    }

    @Test
    public void signAndVerify() throws Exception {        
        String inputZoneFileName = inputZoneFile.getName();
        final File signedFile = File.createTempFile(inputZoneFile.getName(), "-signed.dss");
        int indexOfSufix = inputZoneFileName.indexOf(".zone");
        String zoneName =
                inputZoneFileName.substring(0, indexOfSufix).split("-")[0];
        final ComplianceTestUtils.ProcResult res;
        String zsk1 = null, zsk2 = null, ksk1 = null, ksk2 = null;

        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, false);            
            setupWorkerProperties(WORKER_ID, zoneName);
            helper.getWorkerSession().reloadConfiguration(CRYPTO_TOKEN);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);

            // Create ZSKs
            zsk1 = zoneName + "_Z_1";
            zsk2 = zoneName + "_Z_2";
            helper.getWorkerSession().generateSignerKey(new WorkerIdentifier(WORKER_ID), "RSA", "2048", zsk1, null);
            helper.getWorkerSession().generateSignerKey(new WorkerIdentifier(WORKER_ID), "RSA", "2048", zsk2, null);

            // Create KSKs
            ksk1 = zoneName+"_K_1";
            ksk2 = zoneName+"_K_2";
            helper.getWorkerSession().generateSignerKey(new WorkerIdentifier(WORKER_ID), "RSA", "2048", ksk1, null);
            helper.getWorkerSession().generateSignerKey(new WorkerIdentifier(WORKER_ID), "RSA", "2048", ksk2, null);

            assertEquals("Status code", ClientCLI.RETURN_SUCCESS,
                    cli.execute("signdocument", "-workerid",
                            Integer.toString(WORKER_ID), "-infile", inputZoneFile.getAbsolutePath(),
                            "-outfile", signedFile.getAbsolutePath(), "-metadata", "ZSK_SEQUENCE_NUMBER=1"));

            // check dnssec-verify version
            testDNSSECVersion();            
        
            // verify signed zone file
            res = ComplianceTestUtils.execute(dnssecVerifyCommand, "-v", "9",
                    "-o", zoneName,
                    signedFile.getAbsolutePath());
            final String output = ComplianceTestUtils.toString(res.getOutput());
            final String error = res.getErrorMessage();

            LOG.info("Result:\n" + output);
            LOG.info("Errors:\n" + error);
            assertEquals("result", 0, res.getExitValue());
            /* check output on both stderr and stdout, as newer versions of
             * bind9-utils seems to output messages on stdout
             */
            assertTrue("Expecting successful verification: " + output + error,
                       error.contains("Zone fully signed") ||
                       output.contains("Zone fully signed"));
        } finally {
            helper.removeWorker(WORKER_ID);
            helper.getWorkerSession().removeKey(new WorkerIdentifier(CRYPTO_TOKEN), zsk1);
            helper.getWorkerSession().removeKey(new WorkerIdentifier(CRYPTO_TOKEN), zsk2);
            helper.getWorkerSession().removeKey(new WorkerIdentifier(CRYPTO_TOKEN), ksk1);
            helper.getWorkerSession().removeKey(new WorkerIdentifier(CRYPTO_TOKEN), ksk2);
            helper.removeWorker(CRYPTO_TOKEN);            
        }
    }
    
}
