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

import java.io.FileNotFoundException;
import java.util.Arrays;
import org.apache.log4j.Logger;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.webtest.util.AllWorkersHelper;
import org.signserver.webtest.util.CryptoWorkerHelper;
import org.signserver.webtest.util.WebTestBase;
import static org.signserver.webtest.util.WebTestBase.getWebDriver;
import org.signserver.webtest.util.WebTestHelper;

/**
 * DSSQA-54 PKCS11 crypto worker setup.
 *
 * @author Vinay Singh
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DssQa54_PKCS11CryptoWorkerSetup extends WebTestBase {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(DssQa54_PKCS11CryptoWorkerSetup.class);
    private static final String CLASS_NAME = DssQa54_PKCS11CryptoWorkerSetup.class.getSimpleName();

    private final ModulesTestCase helper = new ModulesTestCase();
    
    private static String CRYPTO_WORKER_NAME;
    private static final String TEST_KEY = "KEY";

    private final String sharedLibraryName;
    private final String slot;
    private final String pin;
    private final String existingKey1;

    @BeforeClass
    public static void init() {
        setUp(CLASS_NAME);
        CRYPTO_WORKER_NAME = "TESTP11" + "_" + getUniqueId();
    }

    @AfterClass
    public static void exit() {
        AllWorkersHelper.removeWorkers(Arrays.asList(CRYPTO_WORKER_NAME));        
        getWebDriver().quit();
    }

    public DssQa54_PKCS11CryptoWorkerSetup() throws FileNotFoundException {        
        sharedLibraryName = helper.getConfig().getProperty("test.p11.sharedLibraryName");
        slot = helper.getConfig().getProperty("test.p11.slot");
        pin = helper.getConfig().getProperty("test.p11.pin");
        existingKey1 = helper.getConfig().getProperty("test.p11.existingkey1");
    }

    /**
     * Adds PKCS11 crypto worker through 'By Properties' option.
     */
    @Test
    public void a_addP11CryptoWorker() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();
        WebTestHelper.clickAddLink();
        AllWorkersHelper.clickMethodButton("By Properties");

        WebElement nameElement = webDriver.findElement(By.xpath("//td[label[text()='Name*:']]/following-sibling::td/input[@type='text']"));
        WebTestHelper.setText(nameElement, CRYPTO_WORKER_NAME);

        WebElement implClassElement = webDriver.findElement(By.xpath("//td[label[text()='Implementation Class*:']]/following-sibling::td/input[@type='text']"));
        WebTestHelper.setText(implClassElement, "org.signserver.server.signers.CryptoWorker");

        WebElement signerTokenElement = webDriver.findElement(By.xpath("//td[label[text()='Signer Token:']]/following-sibling::td/input[@type='text']"));
        WebTestHelper.setText(signerTokenElement, "org.signserver.server.cryptotokens.PKCS11CryptoToken");

        CryptoWorkerHelper.addAdditionalPropertyUnderAddOrLoadConfigurationByPropertiesMethod("SHAREDLIBRARYNAME", sharedLibraryName);
        CryptoWorkerHelper.addAdditionalPropertyUnderAddOrLoadConfigurationByPropertiesMethod("SLOTLABELTYPE", "SLOT_NUMBER");
        CryptoWorkerHelper.addAdditionalPropertyUnderAddOrLoadConfigurationByPropertiesMethod("SLOTLABELVALUE", slot);
        CryptoWorkerHelper.addAdditionalPropertyUnderAddOrLoadConfigurationByPropertiesMethod("PIN", pin);
        CryptoWorkerHelper.addAdditionalPropertyUnderAddOrLoadConfigurationByPropertiesMethod("DEFAULTKEY", TEST_KEY);

        // click 'Next'
        webDriver.findElement(By.xpath("//input[@type='submit' and @value='Next']")).click();
        // click 'Apply'
        webDriver.findElement(By.xpath("//input[@type='submit' and @value='Apply']")).click();
        
        // Check that the worker was successfully added
        AllWorkersHelper.assertWorkerExists(CRYPTO_WORKER_NAME);
    }
    
    /**
     * Generates default key under crypto worker.
     *
     * @throws java.lang.InterruptedException
     */
    @Test
    public void b_generateKey() throws InterruptedException {
        // Looks like generating 2048 bit key takes more time compared to 1024 so slowing down selenium test a bit after generating key       
        CryptoWorkerHelper.generateKey(CRYPTO_WORKER_NAME, TEST_KEY, "RSA", "2048");
        Thread.sleep(5000);
    }
    
    /**
     * Checks that crypto worker is ACTIVE.
     */
    @Test
    public void c_checkStatus() {
        // Check that the worker was successfully activated
        AllWorkersHelper.assertWorkerStatus(CRYPTO_WORKER_NAME, "ACTIVE");
    }

}
