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

import java.util.Arrays;
import org.apache.log4j.Logger;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;
import org.signserver.webtest.util.AllWorkersHelper;
import org.signserver.webtest.util.CryptoWorkerHelper;
import org.signserver.webtest.util.WebTestBase;
import static org.signserver.webtest.util.WebTestBase.getUniqueId;
import static org.signserver.webtest.util.WebTestBase.getWebDriver;
import org.signserver.webtest.util.WebTestHelper;
import org.signserver.webtest.util.WorkerHelper;

/**
 * DSSQA-81 KeyStoreInConfig crypto worker setup.
 *
 * @author Vinay Singh
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DssQa81_KeystoreInConfigCryptoTokenSetUp extends WebTestBase{
    
    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(DssQa81_KeystoreInConfigCryptoTokenSetUp.class);
    private static final String CLASS_NAME = DssQa81_KeystoreInConfigCryptoTokenSetUp.class.getSimpleName();
    
    private static final String MASKED_VALUE = "●●●●●●";
    
    private static String CRYPTO_WORKER_NAME;
    
    @BeforeClass
    public static void init() {
        setUp(CLASS_NAME);
        CRYPTO_WORKER_NAME = "TestCryptoTokenKeystoreInConfig" + "_" + getUniqueId();
    }

    @AfterClass
    public static void exit() {
        AllWorkersHelper.removeWorkers(Arrays.asList(CRYPTO_WORKER_NAME));        
        getWebDriver().quit();
    }
    
    /**
     * Adds a KeystoreInConfig crypto worker through 'By Properties' option.
     */
    @Test
    public void a_addKeystoreInConfigCryptoWorker() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();
        WebTestHelper.clickAddLink();
        AllWorkersHelper.clickMethodButton("By Properties");
        
        WebElement nameElement = webDriver.findElement(By.xpath("//td[label[text()='Name*:']]/following-sibling::td/input[@type='text']"));
        WebTestHelper.setText(nameElement, CRYPTO_WORKER_NAME);

        WebElement implClassElement = webDriver.findElement(By.xpath("//td[label[text()='Implementation Class*:']]/following-sibling::td/input[@type='text']"));
        WebTestHelper.setText(implClassElement, "org.signserver.server.signers.CryptoWorker");

        WebElement signerTokenElement = webDriver.findElement(By.xpath("//td[label[text()='Signer Token:']]/following-sibling::td/input[@type='text']"));
        WebTestHelper.setText(signerTokenElement, "org.signserver.server.cryptotokens.KeystoreInConfigCryptoToken");
        
        Select drpCountry = new Select(webDriver.findElement(By.xpath("//td[label[text()='Type:']]/following-sibling::td/select")));
        drpCountry.selectByVisibleText("CRYPTO_WORKER");
        
        CryptoWorkerHelper.addAdditionalPropertyUnderAddOrLoadConfigurationByPropertiesMethod("KEYSTORETYPE", "INTERNAL");
        
        // click 'Next'
        webDriver.findElement(By.xpath("//input[@type='submit' and @value='Next']")).click();
        // click 'Apply'
        webDriver.findElement(By.xpath("//input[@type='submit' and @value='Apply']")).click();
        
        // Check that the worker was successfully added
        AllWorkersHelper.assertWorkerStatus(CRYPTO_WORKER_NAME, "OFFLINE");
    }
    
    /**
     * Adds KEYSTOREPASSWORD property and checks worker status.
     */
    @Test
    public void b_addKeyStorePwdAndAssertStatus() {
        AllWorkersHelper.clickWorkersTab();
        AllWorkersHelper.openWorker(CRYPTO_WORKER_NAME);
        WorkerHelper.clickConfigurationTab();
        WorkerHelper.addProperty("KEYSTOREPASSWORD", "foo123");
        WorkerHelper.assertPropertyExists("KEYSTOREPASSWORD", MASKED_VALUE);

        WorkerHelper.clickStatusSummaryTab();
        WorkerHelper.assertStatusSummaryContains("Worker status : Offline");
        WorkerHelper.assertStatusSummaryContains("Worker status : Offline");
        WorkerHelper.assertStatusSummaryContains("Crypto Token is disconnected");
    }
    
    /**
     * Generates key under crypto worker and checks worker status.
     */
    @Test
    public void c_generateKeyAndAssertStatus() {
        CryptoWorkerHelper.generateKey(CRYPTO_WORKER_NAME, "key1", "RSA", "1024");
        WorkerHelper.clickStatusSummaryTab();
        WorkerHelper.assertStatusSummaryContains("Worker status : Active");
        WorkerHelper.assertStatusSummaryContains("Worker status : Active");

    }

}
