/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.webtest.util;

import com.google.common.collect.ImmutableMap;
import java.util.Map;
import org.apache.log4j.Logger;
import static org.junit.Assert.assertTrue;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.signserver.testutils.ModulesTestCase;
import static org.signserver.webtest.util.WebTestBase.webDriver;

/**
 * CryptoWorkerHelper contains helper methods for the crypto worker pages.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class CryptoWorkerHelper {
    
    /**
     * Logger for this class
     */
    private static final Logger LOG = Logger.getLogger(CryptoWorkerHelper.class);

    /**
     * Generates key given parameters.
     *
     * @param cryptoWorkerName
     * @param keyAlias
     * @param keyAlg
     * @param keySpec
     */
    public static void generateKey(String cryptoWorkerName, String keyAlias, String keyAlg, String keySpec) {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.openWorker(cryptoWorkerName);
        WorkerHelper.clickCryptoTokenTab();
        
        // click 'Generate key…' link
        webDriver.findElement(By.xpath("//a[text()='Generate key…']")).click();

        // set key alias
        WebElement keyAliasElement = webDriver.findElement(By.xpath("//input[contains(@id, 'alias') and @type='text']"));
        WebTestHelper.setText(keyAliasElement, keyAlias);

        // set to enter key alg manually
        WebElement selectKeyAlgManuallyElement =
                webDriver.findElement(By.xpath("//input[contains(@id, 'enterAlgManually') and @type='submit']"));
        selectKeyAlgManuallyElement.click();
        
        // set key alg
        WebElement keyAlgElement = webDriver.findElement(By.xpath("//input[contains(@id, 'keyAlg') and @type='text']"));
        WebTestHelper.setText(keyAlgElement, keyAlg);

        // set to enter key spec manually
        WebElement selectKeySpecManuallyElement =
                webDriver.findElement(By.xpath("//input[contains(@id, 'enterKeySpecManually') and @type='submit']"));
        selectKeySpecManuallyElement.click();

        // set key spec
        WebElement keySpecElement = webDriver.findElement(By.xpath("//input[contains(@id, 'keySpec') and @type='text']"));
        WebTestHelper.setText(keySpecElement, keySpec);

        // click 'Generate' button
        webDriver.findElement(By.xpath("//input[@value='Generate' and @type='submit']")).click();
    }
    
    /**
     * Adds P11 crypto worker given parameters.
     *
     * @param propertyFile
     * @param cryptoWorkerName
     * @param keyAlias
     */
    public static void addCryptoWorkerP11(String propertyFile, String cryptoWorkerName, String keyAlias) {
        String sharedLibraryName;
        String slot;
        String pin;
        String existingKey1;
        ModulesTestCase helper = new ModulesTestCase();

        sharedLibraryName = helper.getConfig().getProperty("test.p11.sharedLibraryName");
        slot = helper.getConfig().getProperty("test.p11.slot");
        pin = helper.getConfig().getProperty("test.p11.pin");
        existingKey1 = helper.getConfig().getProperty("test.p11.existingkey1");

        String defaultKeyAlias = keyAlias != null ? keyAlias : existingKey1;

        Map<String, String> properties = ImmutableMap.<String, String>builder()
                .put("WORKERGENID1.NAME", cryptoWorkerName)
                .put("WORKERGENID1.SHAREDLIBRARYNAME", sharedLibraryName)
                .put("WORKERGENID1.SLOTLABELTYPE", "SLOT_NUMBER")
                .put("WORKERGENID1.SLOTLABELVALUE", slot)
                .put("WORKERGENID1.PIN", pin)
                .put("WORKERGENID1.DEFAULTKEY", defaultKeyAlias).build();

        AllWorkersHelper.addFromTemplate(propertyFile, properties);
    }
    
    /**
     * Verifies symmetric key attributes on crypto token entry screen.
     *
     * @param cryptoWorkerName
     * @param keyAlias
     * @param keyAlg
     * @param keySpec
     */
    public static void assertSymmetricKeyDetails(String cryptoWorkerName, String keyAlias, String keyAlg, String keySpec) {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.openWorker(cryptoWorkerName);
        WorkerHelper.clickCryptoTokenTab();

        webDriver.findElement(By.xpath("//a[text()='" + keyAlias + "']")).click();

        assertTrue("Heading missing?", WebTestHelper.elementExists(By.xpath("//th[text()='Name']")));
        assertTrue("Heading missing?", WebTestHelper.elementExists(By.xpath("//th[text()='Name']/following-sibling::th[text()='Value']")));
        
        assertTrue("Key attribute-name missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Alias']]")));
        assertTrue("Key attribute-value missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Alias']]/following-sibling::td[pre[text()='" + keyAlias + "']]")));
        
        assertTrue("Key attribute-name missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Type']]")));
        assertTrue("Key attribute-value missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Type']]/following-sibling::td[pre[text()='SECRETKEY_ENTRY']]")));
        
        assertTrue("Key attribute-name missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Creation date']]")));
        assertTrue("Key attribute-value missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Creation date']]/following-sibling::td[pre[text()='n/a']]")));
        
        assertTrue("Key attribute-name missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Certificate']]")));
        assertTrue("Key attribute-value missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Certificate']]/following-sibling::td[pre[text()='n/a']]")));
        
        assertTrue("Key attribute-name missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Key specification']]")));
        assertTrue("Key attribute-value missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Key specification']]/following-sibling::td[pre[text()='" + keySpec + "']]")));
        
        assertTrue("Key attribute-name missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Key algorithm']]")));
        assertTrue("Key attribute-value missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Key algorithm']]/following-sibling::td[pre[text()='" + keyAlg + "']]")));        
    }
    
    /**
     * Verifies wrapped key attributes on crypto token entry screen.
     *
     * @param cryptoWorkerName
     * @param keyAlias
     * @param keyAlg
     * @param keySpec
     * @param wrappingKey
     */
    public static void assertWrappedKeyDetails(String cryptoWorkerName, String keyAlias, String keyAlg, String keySpec, String wrappingKey) {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.openWorker(cryptoWorkerName);
        WorkerHelper.clickCryptoTokenTab();

        webDriver.findElement(By.xpath("//a[text()='" + keyAlias + "']")).click();

        assertTrue("Heading missing?", WebTestHelper.elementExists(By.xpath("//th[text()='Name']")));
        assertTrue("Heading missing?", WebTestHelper.elementExists(By.xpath("//th[text()='Name']/following-sibling::th[text()='Value']")));

        assertTrue("Key attribute-name missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Alias']]")));
        assertTrue("Key attribute-value missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Alias']]/following-sibling::td[pre[text()='" + keyAlias + "']]")));

        assertTrue("Key attribute-name missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Type']]")));
        assertTrue("Key attribute-value missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Type']]/following-sibling::td[pre[text()='PRIVATEKEY_ENTRY']]")));

        assertTrue("Key attribute-name missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Creation date']]")));
        assertTrue("Key attribute-value missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Creation date']]/following-sibling::td[pre[text()='n/a']]")));

        assertTrue("Key attribute-name missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Certificate']]")));
        String certFieldValue = "CN=Dummy cert for " + keyAlias;
        assertTrue("Key attribute-value missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Certificate']]/following-sibling::td[pre[text()= '" + certFieldValue + "']]")));
        assertTrue("Certificate details-link missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Certificate']]/following-sibling::td[pre[text()= '" + certFieldValue + "']]/following-sibling::td/a[contains(text(), 'View')]")));

        assertTrue("Key attribute-name missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Key specification']]")));
        assertTrue("Key attribute-value missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Key specification']]/following-sibling::td[pre[text()='" + keySpec + "']]")));

        assertTrue("Key attribute-name missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Key algorithm']]")));
        assertTrue("Key attribute-value missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Key algorithm']]/following-sibling::td[pre[text()='" + keyAlg + "']]")));

        assertTrue("Key attribute-name missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Wrapping Key']]")));
        assertTrue("Key attribute-value missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Wrapping Key']]/following-sibling::td[pre[text()='" + wrappingKey + "']]")));

        assertTrue("Key attribute-name missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Wrapping Cipher']]")));
        assertTrue("Key attribute-value missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Wrapping Cipher']]/following-sibling::td[pre[text()='CKM_AES_CBC_PAD']]")));

        assertTrue("Key attribute-name missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Signings']]")));
        assertTrue("Key attribute-value missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Signings']]/following-sibling::td[pre[text()='0']]")));

        assertTrue("Key attribute-name missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Public exponent']]")));
        assertTrue("Key attribute-value missing?", WebTestHelper.elementExists(By.xpath("//td[b[text()='Public exponent']]/following-sibling::td[pre[text()='65537']]")));

        assertTrue("Back button missing?", WebTestHelper.elementExists(By.xpath("//div[@id='worker_content']/form/a[text()='Back']")));
    }
    
    /**
     * Performs test key operation on given key.
     *
     * @param cryptoWorkerName
     * @param keyAlias
     */
    public static void testKey(String cryptoWorkerName, String keyAlias) {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.openWorker(cryptoWorkerName);
        WorkerHelper.clickCryptoTokenTab();

        webDriver.findElement(By.xpath("//td[a[text()='" + keyAlias + "']]/preceding-sibling::td/input[@type='checkbox']")).click();
        webDriver.findElement(By.xpath("//input[@type='submit' and @value='Test…']")).click();
        webDriver.findElement(By.xpath("//input[@type='submit' and @value='Test']")).click();

        assertTrue("Heading missing?", WebTestHelper.elementExists(By.xpath("//th[text()='Alias']")));
        assertTrue("Heading missing?", WebTestHelper.elementExists(By.xpath("//th[text()='Alias']/following-sibling::th[text()='Result']")));

        assertTrue("Data missing?", WebTestHelper.elementExists(By.xpath("//span[text()='" + keyAlias + "']")));
        String resultMessage = keyAlias + ", SUCCESS";
        assertTrue("Result missing?", WebTestHelper.elementExists(By.xpath("//span[contains(text(), '" + resultMessage + "')]")));
    }
    
    /**
     * Adds additional property when configuration is added through 'By
     * Properties' method.
     *
     * @param propName
     * @param propValue
     */
    public static void addAdditionalPropertyUnderAddOrLoadConfigurationByPropertiesMethod(String propName, String propValue) {
        // click 'Add…' button
        webDriver.findElement(By.xpath("//td[label[text()='Additional Properties:']]/following-sibling::td/table/tfoot/tr/td/input[@type='submit' and @value='Add…']")).click();

        // find parent element under which name-value elements fall
        WebElement additionalPropertyElement = webDriver.findElement(By.xpath("//td[label[text()='Additional Properties:']]/following-sibling::td/following-sibling::td"));

        // set property name
        WebElement additionalPropName = additionalPropertyElement.findElement(By.xpath(".//td[label[text()='Name*:']]/following-sibling::td/input[@type='text']"));
        WebTestHelper.setText(additionalPropName, propName);

        // set property value
        WebElement additionalPropValue = additionalPropertyElement.findElement(By.xpath(".//td[label[text()='Value:']]/following-sibling::td/textarea"));
        WebTestHelper.setText(additionalPropValue, propValue);

        // add property clicking 'Add' button
        additionalPropertyElement.findElement(By.xpath(".//tr//td/input[@type='submit' and @value='Add']")).click();
    }

}
