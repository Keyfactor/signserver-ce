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
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.signserver.webtest.util.AllWorkersHelper;
import org.signserver.webtest.util.WebTestBase;
import static org.signserver.webtest.util.WebTestBase.getUniqueId;
import static org.signserver.webtest.util.WebTestBase.getWebDriver;
import org.signserver.webtest.util.WebTestHelper;
import org.signserver.webtest.util.WorkerHelper;

/**
 * DSSQA-110 usage of worker authorization rules configured with client certificate
 * serial number & common name.
 *
 * @author Vinay Singh
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DssQa110_ClientCertAuthRules extends WebTestBase{
    
    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(DssQa110_ClientCertAuthRules.class);
    private static final String CLASS_NAME = DssQa110_ClientCertAuthRules.class.getSimpleName();    
    private static final String WORKER = "xmlsigner";
    private final String workerName = WORKER + "_" + getUniqueId();    
    private static final String DATA = "<xml/>";

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
                "WORKERGENID1.CRYPTOTOKEN", cryptoToken,
                "WORKERGENID1.AUTHTYPE", "CLIENTCERT"
        ));
        AllWorkersHelper.assertWorkerExists(workerName);
        AllWorkersHelper.assertWorkerStatus(workerName, "ACTIVE");
    }
    
    /**
     * Signing should fail if no authorization rule exists and worker is
     * configured with CLIENTCERT authentication.
     */
    @Test
    public void b_XMLSigningFailureWithNoClientCertRule() {
        AllWorkersHelper.genericSignByDirectInput(workerName, "<xml/>");

        assertTrue("signing should fail", WebTestHelper.elementExists(By.xpath("//div/h1[contains(text(), 'Error 400')]")));
        WebElement error = webDriver.findElement(By.xpath("//div/h1[contains(text(), 'Error 400')]/following-sibling::p"));
        LOG.info("error message " + error.getText());
        assertTrue("authorization error should be displayed", error.getText().contains("Client is not authorized:"));
    }
    
    /**
     * Adds client certificate rule with certificate serial number.
     */
    @Test
    public void c_AddAuthRulewithCertificateSerialNo() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.openWorker(workerName);
        WorkerHelper.clickAuthorizationTab();
        WorkerHelper.addClientCertAuthRuleByLoadCurrentChoosingDefaultOption_CertificateSerialNo();
    }
    
    /**
     * Performs signing now after adding client certificate rule in previous step.
     */
    @Test
    public void d_XMLSigning() {
        AllWorkersHelper.genericSignByDirectInput(workerName, DATA);
        // check for successful signing output            
        assertTrue("Signing was not successful?", WebTestHelper.elementExists(By.xpath("//*[name()='SignatureValue']")));
    }
    
    /**
     * Removes earlier added client certificate rule and signing should fail
     * again.
     */
    @Test
    public void e_RemoveAuthRuleAndSigning() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.openWorker(workerName);
        WorkerHelper.clickAuthorizationTab();
        
        // click 'Remove' link
        webDriver.findElement(By.xpath("//a[text()='Remove']")).click();
        // click 'Remove' on worker authorization remove confirmation screen
        webDriver.findElement(By.xpath("//input[@value='Remove']")).click();
        
        // Try signing now, it should fail
        AllWorkersHelper.genericSignByDirectInput(workerName, "<xml/>");

        assertTrue("signing should fail", WebTestHelper.elementExists(By.xpath("//div/h1[contains(text(), 'Error 400')]")));
        WebElement error = webDriver.findElement(By.xpath("//div/h1[contains(text(), 'Error 400')]/following-sibling::p"));
        LOG.info("error message " + error.getText());
        assertTrue("authorization error should be displayed", error.getText().contains("Client is not authorized:"));
    }
    
    /**
     * Adds client certificate rule with common name (CN).
     */
    @Test
    public void f_AddAuthRulewithCommonName() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.openWorker(workerName);
        WorkerHelper.clickAuthorizationTab();
        WorkerHelper.addClientCertAuthRuleByLoadCurrentChoosingOption_CommonName();

        assertTrue("certificate rule with common name should exist", WebTestHelper.elementExists(By.xpath("//td/div[text()='Admin One']")));
    }
    
    /**
     * Performs signing now after adding client certificate rule with CN in
     * previous step.
     */
    @Test
    public void g_XMLSigning() {
        AllWorkersHelper.genericSignByDirectInput(workerName, DATA);
        // check for successful signing output            
        assertTrue("Signing was not successful?", WebTestHelper.elementExists(By.xpath("//*[name()='SignatureValue']")));
    }
    
}
