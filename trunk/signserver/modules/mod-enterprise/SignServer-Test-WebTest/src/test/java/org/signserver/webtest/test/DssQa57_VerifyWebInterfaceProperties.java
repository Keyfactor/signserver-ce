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

import org.apache.log4j.Logger;
import org.junit.AfterClass;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.signserver.webtest.util.WebTestBase;
import static org.signserver.webtest.util.WebTestBase.getWebDriver;
import org.signserver.webtest.util.WebTestHelper;

/**
 * DSSQA-57 Verify Web interface properties after application installation.
 *
 * @author Vinay Singh
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DssQa57_VerifyWebInterfaceProperties extends WebTestBase {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(DssQa57_VerifyWebInterfaceProperties.class);
    private static final String CLASS_NAME = DssQa57_VerifyWebInterfaceProperties.class.getSimpleName();

    @BeforeClass
    public static void init() {
        setUp(CLASS_NAME);
    }

    @AfterClass
    public static void exit() {
        getWebDriver().quit();
    }

    @Test
    public void a_verifyWebInterfacePage() {
        WebTestHelper.openWebInterfacePage();

        // check logo at top-left corner
        assertTrue("Application logo should be dispayed at top-left", WebTestHelper.elementExists(By.xpath("//div[@id='top-left']/img[contains(@src, 'logo.png')]")));

        assertTrue("Node should be dispayed at top-right", WebTestHelper.elementExists(By.xpath("//div[@id='top-right']/table/tbody/tr/td/span[@class='top-right-c1' and contains(text(), 'Node:')]")));

        assertTrue("Heading is missing?", WebTestHelper.elementExists(By.xpath("//div[@id='container1']/h2[text()='Local Resources']")));

        assertTrue("Local resource missing?", WebTestHelper.elementExists(By.xpath("//div[@id='container1']/ul/li/a[text()='Client Web']")));
        assertTrue("Local resource missing?", WebTestHelper.elementExists(By.xpath("//div[@id='container1']/ul/li/a[text()='Health Check']")));
        assertTrue("Local resource missing?", WebTestHelper.elementExists(By.xpath("//div[@id='container1']/ul/li/a[text()='Administration Web']")));

        assertTrue("Heading is missing?", WebTestHelper.elementExists(By.xpath("//div[@id='container1']/h2[text()='Online Resources']")));
        assertTrue("Online resource missing?", WebTestHelper.elementExists(By.xpath("//div[@id='container1']/ul/li/a[text()='SignServer Web Site']")));
        assertTrue("Online resource missing?", WebTestHelper.elementExists(By.xpath("//div[@id='container1']/ul/li/a[text()='PrimeKey Documentation']")));
       
        assertTrue("Copyright should be displayed at footer", WebTestHelper.elementExists(By.xpath("//div[@id='bottom']/p[@class='bottomText' and contains(text(), 'Copyright')]")));
    }
    
    @Test
    public void b_verifyDemosLink() {
        webDriver.findElement(By.xpath("//div[@id='container1']/ul/li/a[text()='Client Web']")).click();
                
        assertTrue("Application logo should be dispayed at top-left", WebTestHelper.elementExists(By.xpath("//div[@id='top-left']/a/img[contains(@src, 'logo.png')]")));
        assertTrue("Node should be dispayed at top-right", WebTestHelper.elementExists(By.xpath("//div[@id='top-right']/table/tbody/tr/td/span[@class='top-right-c1' and contains(text(), 'Node:')]")));

        assertTrue("Menu option missing?", WebTestHelper.elementExists(By.xpath("//div[@id='top-menu']/ul/li/a[text()='File Upload']")));
        assertTrue("Menu option missing?", WebTestHelper.elementExists(By.xpath("//div[@id='top-menu']/ul/li/a[text()='Direct Input']")));
        assertTrue("Menu option missing?", WebTestHelper.elementExists(By.xpath("//div[@id='top-menu']/ul/li/a[text()='More...']")));
        assertTrue("Menu option missing?", WebTestHelper.elementExists(By.xpath("//div[@id='top-menu']/ul/li/a[text()='Documentation']")));
        
        assertTrue("Menu option missing?", WebTestHelper.elementExists(By.xpath("//details/summary[contains(text(), 'Process type')]")));
        assertTrue("Menu option missing?", WebTestHelper.elementExists(By.xpath("//details/summary[contains(text(), 'CMS-specific')]")));
        assertTrue("Menu option missing?", WebTestHelper.elementExists(By.xpath("//details/summary[contains(text(), 'PDF-specific')]")));
        assertTrue("Menu option missing?", WebTestHelper.elementExists(By.xpath("//details/summary[contains(text(), 'Generic meta data')]")));
        
        assertTrue("Process  type option missing?", WebTestHelper.elementExists(By.xpath("//details/p/select/option[contains(text(), 'Sign document')]")));
        assertTrue("Process  type option missing?", WebTestHelper.elementExists(By.xpath("//details/p/select/option[contains(text(), 'Validate document')]")));
        assertTrue("Process  type option missing?", WebTestHelper.elementExists(By.xpath("//details/p/select/option[contains(text(), 'Validate certificate')]")));
        assertTrue("Process  type option missing?", WebTestHelper.elementExists(By.xpath("//details/p[contains(text(), 'Request detached signature:')]")));
        assertTrue("Process  type option missing?", WebTestHelper.elementExists(By.xpath("//details/p[contains(text(), 'Password (if required for opening or signing PDF):')]")));
        assertTrue("Process  type option missing?", WebTestHelper.elementExists(By.xpath("//details/p[contains(text(), 'Include additional meta data with the request:')]")));
                
        assertTrue("Heading is missing?", WebTestHelper.elementExists(By.xpath("//div[@id='container1']/h1[text()='Generic Signing or Validation by File Upload']")));
        assertTrue("Copyright should be displayed at footer", WebTestHelper.elementExists(By.xpath("//div[@id='bottom']/p[@class='bottomText' and contains(text(), 'Copyright')]")));
                
    }
    
    @Test
    public void c_verifyDocumentationLink() {
        WebTestHelper.openWebInterfacePage();
        webDriver.findElement(By.xpath("//div[@id='container1']/ul/li/a[text()='Client Web']")).click();
        assertTrue("Application logo should be dispayed at top-left", WebTestHelper.elementExists(By.xpath("//div[@id='top-left']/a/img[contains(@src, 'logo.png')]")));
        assertTrue("Node should be dispayed at top-right", WebTestHelper.elementExists(By.xpath("//div[@id='top-right']/table/tbody/tr/td/span[@class='top-right-c1' and contains(text(), 'Node:')]")));

        webDriver.findElement(By.xpath("//div[@id='top-menu']/ul/li/a[text()='Documentation']")).click();
 
        assertTrue("Heading missing?", WebTestHelper.elementExists(By.xpath("//a[@class='ht-space-link']/h2[text()='SignServer Manual']")));
        
        assertTrue("Linked page missing?", WebTestHelper.elementExists(By.xpath("//a[@class='ht-nav-page-link' and text()='SignServer Introduction']")));
        assertTrue("Linked page missing?", WebTestHelper.elementExists(By.xpath("//a[@class='ht-nav-page-link' and text()='SignServer Installation']")));
        assertTrue("Linked page missing?", WebTestHelper.elementExists(By.xpath("//a[@class='ht-nav-page-link' and text()='SignServer Operations']")));
        assertTrue("Linked page missing?", WebTestHelper.elementExists(By.xpath("//a[@class='ht-nav-page-link' and text()='SignServer Integration']")));
        assertTrue("Linked page missing?", WebTestHelper.elementExists(By.xpath("//a[@class='ht-nav-page-link' and text()='SignServer Reference']")));
        assertTrue("Linked page missing?", WebTestHelper.elementExists(By.xpath("//a[@class='ht-nav-page-link' and text()='SignServer Integration']")));
        assertTrue("Linked page missing?", WebTestHelper.elementExists(By.xpath("//a[@class='ht-nav-page-link' and text()='SignServer Release Information']")));
        
        assertTrue("Heading missing?", WebTestHelper.elementExists(By.xpath("//div[@class='ht-sidebar-other']/h2[text()='Other Resources']")));
        assertTrue("Linked page missing?", WebTestHelper.elementExists(By.xpath("//a[@class='ht-nav-page-link' and text()='signserver.org']")));
        assertTrue("Linked page missing?", WebTestHelper.elementExists(By.xpath("//a[@class='ht-nav-page-link' and text()='ejbca.org']")));
        assertTrue("Linked page missing?", WebTestHelper.elementExists(By.xpath("//a[@class='ht-nav-page-link' and text()='primekey.com']")));

        assertTrue("Search text box missing?", WebTestHelper.elementExists(By.xpath("//div[@class='ht-search-input']/form/input[@class='search-input' and @placeholder='Search']")));
        assertTrue("Search-submit button missing?", WebTestHelper.elementExists(By.xpath("//div[@class='ht-search-input']/form/input[@type='submit']")));
    }
    
    @Test
    public void d_verifySignServerWebsiteLink() {
        WebTestHelper.openWebInterfacePage();
        webDriver.findElement(By.xpath("//div[@id='container1']/ul/li/a[text()='Client Web']")).click();
        webDriver.findElement(By.xpath("//div[@id='top-menu']/ul/li/a[text()='Documentation']")).click();        
        webDriver.findElement(By.xpath("//a[@class='ht-nav-page-link' and text()='signserver.org']")).click();
        assertTrue("SignServer website down?", WebTestHelper.elementExists(By.xpath("//title[text()='Home - SignServer']")));
    }
    
    @Test
    public void e_verifyEJBCAWebsiteLink() {
        WebTestHelper.openWebInterfacePage();
        webDriver.findElement(By.xpath("//div[@id='container1']/ul/li/a[text()='Client Web']")).click();
        webDriver.findElement(By.xpath("//div[@id='top-menu']/ul/li/a[text()='Documentation']")).click();   
        webDriver.findElement(By.xpath("//a[@class='ht-nav-page-link' and text()='ejbca.org']")).click();
        assertTrue("EJBCA website down?", WebTestHelper.elementExists(By.xpath("//title[text()='EJBCA - The Open Source CA']")));
    }
    
    @Test
    public void f_verifyPrimeKeyWebsiteLink() {
        WebTestHelper.openWebInterfacePage();
        webDriver.findElement(By.xpath("//div[@id='container1']/ul/li/a[text()='Client Web']")).click();
        webDriver.findElement(By.xpath("//div[@id='top-menu']/ul/li/a[text()='Documentation']")).click();   
        webDriver.findElement(By.xpath("//a[@class='ht-nav-page-link' and text()='primekey.com']")).click();
        assertTrue("PrimeKey website down?", WebTestHelper.elementExists(By.xpath("//title[text()='PrimeKey: Creating trust for the connected society']")));
    }

}
