/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.webtest.test;

import com.google.common.collect.ImmutableMap;
import java.util.Arrays;
import org.apache.log4j.Logger;
import org.junit.AfterClass;
import static org.junit.Assert.assertTrue;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.webtest.util.AllWorkersHelper;
import org.signserver.webtest.util.WebTestBase;
import static org.signserver.webtest.util.WebTestBase.getWebDriver;
import org.signserver.webtest.util.WebTestHelper;
import org.signserver.webtest.util.WorkerHelper;

/**
 * DSSQA-111 checks that key generation is disabled in admin web when configured
 * to do so.
 *
 * @author Vinay Singh
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DssQa111_DisabledKeyGeneration extends WebTestBase {
    
    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(DssQa111_DisabledKeyGeneration.class);
    private static final String CLASS_NAME = DssQa111_DisabledKeyGeneration.class.getSimpleName();    
    private static final String WORKER = "xmlsigner";
    private final String workerName = WORKER + "_" + getUniqueId();
    
    private final ModulesTestCase helper = new ModulesTestCase();
    
    private static String cryptoToken;

    @BeforeClass
    public static void init() {
        setUp(CLASS_NAME);
        cryptoToken = WebTestHelper.addCryptoTokenP12();
    }

    @AfterClass
    public static void exit() {       
        AllWorkersHelper.removeWorkers(Arrays.asList(WORKER, cryptoToken));
        getWebDriver().quit();
    }

    /**
     * Adds XMLSigner.
     */
    @Test
    public void a_addXMLSigner() {
        AllWorkersHelper.addFromTemplate(WORKER + ".properties", ImmutableMap.of(
                "WORKERGENID1.NAME", workerName,
                "WORKERGENID1.CRYPTOTOKEN", cryptoToken
        ));
        AllWorkersHelper.assertWorkerExists(workerName);
        AllWorkersHelper.assertWorkerStatus(workerName, "ACTIVE");
    }
    
    /**
     * Checks that key generation is disabled under crypto worker.
     */
    @Test
    public void b_checkKeyGenerationDisabled_CryptoWorker() {
        LOG.info("This test assumes test.disablekeygen.disabled=false and that conf/signserver_deploy.properties is configured with cryptotoken.disablekeygeneration=true.");
        Assume.assumeFalse("true".equalsIgnoreCase(helper.getConfig().getProperty("test.disablekeygen.disabled")));

        WebTestHelper.openAdminWeb();
        AllWorkersHelper.openWorker(cryptoToken);
        WorkerHelper.clickCryptoTokenTab();
        // click 'Generate key…' link
        webDriver.findElement(By.xpath("//a[text()='Generate key…']")).click();
        assertTrue("Error message should be displayed", WebTestHelper.elementExists(By.xpath("//span[text()='Key generation is disabled.']")));

        WorkerHelper.clickStatusSummaryTab();
        // click 'Renew key…' link
        webDriver.findElement(By.xpath("//input[@value='Renew key…']")).click();
        assertTrue("Error message should be displayed", WebTestHelper.elementExists(By.xpath("//span[text()='Key generation is disabled.']")));
    }
    
    /**
     * Checks that key generation is disabled under signer.
     */
    @Test
    public void b_checkKeyGenerationDisabled_Signer() {
        LOG.info("This test assumes test.disablekeygen.disabled=false and that conf/signserver_deploy.properties is configured with cryptotoken.disablekeygeneration=true.");
        Assume.assumeFalse("true".equalsIgnoreCase(helper.getConfig().getProperty("test.disablekeygen.disabled")));

        WebTestHelper.openAdminWeb();
        AllWorkersHelper.openWorker(workerName);        
        // click 'Renew key…' link
        webDriver.findElement(By.xpath("//input[@value='Renew key…']")).click();
        assertTrue("Error message should be displayed", WebTestHelper.elementExists(By.xpath("//span[text()='Key generation is disabled.']")));
    }
    
}
