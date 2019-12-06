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
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.signserver.webtest.util.AllWorkersHelper;
import org.signserver.webtest.util.AuditLogHelper;
import org.signserver.webtest.util.WebTestBase;
import static org.signserver.webtest.util.WebTestBase.getWebDriver;
import org.signserver.webtest.util.WebTestHelper;

/**
 * DSSQA-44 Verify all Admin web properties after fresh installation.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class DssQa44_VerifyAdminWebProperties extends WebTestBase {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(DssQa44_VerifyAdminWebProperties.class);
    private static final String CLASS_NAME = DssQa44_VerifyAdminWebProperties.class.getSimpleName();

    @BeforeClass
    public static void init() {
        setUp(CLASS_NAME);
    }

    @AfterClass
    public static void exit() {
        getWebDriver().quit();
    }

    @Test
    public void a_verifyTop() {
        WebTestHelper.openAdminWeb();

        // check logo at top-left corner
        assertTrue("Application logo should be dispayed at top-left", WebTestHelper.elementExists(By.xpath("//div[@id='top-left']//a/img[contains(@src, 'logo.png')]")));

        // check items at top-right corner
        assertTrue("'Logged-in user' info should be displayed at top-right", WebTestHelper.elementExists(By.xpath("//div[@id='top-right']/table/tbody/tr/td/span[text()='User:']")));
        assertTrue("'Node' should be displayed at top-right", WebTestHelper.elementExists(By.xpath("//div[@id='top-right']/table/tbody/tr/td/span[text()='Node:']")));
        assertTrue("'Server-time' should be displayed at top-right", WebTestHelper.elementExists(By.xpath("//div[@id='top-right']/table/tbody/tr/td/span[text()='Server Time:']")));
        assertTrue("'Application version' should be displayed at top-right", WebTestHelper.elementExists(By.xpath("//div[@id='top-right']/table/tbody/tr/td/span[text()='Version:']")));

        assertTrue("'Workers' should be displayed under top-menu", WebTestHelper.elementExists(By.xpath("//div[@id='top-menu']/ul/li/a[text()='Workers']")));
        assertTrue("'Global Configuration' should be displayed under top-menu", WebTestHelper.elementExists(By.xpath("//div[@id='top-menu']/ul/li/a[text()='Global Configuration']")));
        assertTrue("Administrators' should be displayed at top-right", WebTestHelper.elementExists(By.xpath("//div[@id='top-menu']/ul/li/a[text()='Administrators']")));
        assertTrue("'Audit Log' should be displayed at top-right", WebTestHelper.elementExists(By.xpath("//div[@id='top-menu']/ul/li/a[text()='Audit Log']")));
        assertTrue("'Archive' should be displayed at top-right", WebTestHelper.elementExists(By.xpath("//div[@id='top-menu']/ul/li/a[text()='Archive']")));
        assertTrue("'Documentation' should be displayed at top-right", WebTestHelper.elementExists(By.xpath("//div[@id='top-menu']/ul/li/a[text()='Documentation']")));
    }

    @Test
    public void b_verifyWorkersTabItems() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();

        // check heading
        assertTrue("'Documentation' should be displayed at top-right", WebTestHelper.elementExists(By.xpath("//div[@id='content']/h1[text()='All Workers']")));

        // check all functions
        assertTrue("worker function is missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/p/input[@value='Activate…']")));
        assertTrue("worker function is missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/p/input[@value='Deactivate…']")));
        assertTrue("worker function is missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/p/input[@value='Renew key…']")));
        assertTrue("worker function is missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/p/input[@value='Test key…']")));
        assertTrue("worker function is missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/p/input[@value='Generate CSR…']")));
        assertTrue("worker function is missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/p/input[@value='Install Certificates…']")));
        assertTrue("worker function is missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/p/input[@value='Renew signer…']")));
        assertTrue("worker function is missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/p/input[@value='Remove…']")));
        assertTrue("worker function is missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/p/input[@value='Reload from database…']")));
        assertTrue("worker function is missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/p/input[@value='Export…']")));

        // check Add... link
        assertTrue("Logged-in user info should be displayed at top-right", WebTestHelper.elementExists(By.xpath("//div[@id='content']/a[text()='Add…']")));

    }
    
    @Test
    public void c_verifyGlobalConfigurationTab() {
        AllWorkersHelper.clickGlobalConfigurationTab();
        assertTrue("worker function is missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/a[text()='Add…']")));
        assertTrue("worker function is missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/input[@value='Remove selected…']")));
    }
    
    @Test
    public void d_verifyAdministratorstab() {
        AllWorkersHelper.clickAdministratorsTab();
        // check if any administrator exists already otherwise add current logged-in user as administrator having Admin, Author, Archive Auditor roles
        if (webDriver.findElements(By.xpath("//div[@id='content']/form/table/tbody/tr/td/input[@type='submit' and @value='Edit']")).isEmpty()) {
            webDriver.findElement(By.xpath("//div[@id='content']/form/p/a[text()='Add…']")).click();
            webDriver.findElement(By.xpath("//input[@value='Load Current']")).click();
            webDriver.findElement(By.xpath("//input[@id='form:roleAuditor' and @type='checkbox']")).click();
            webDriver.findElement(By.xpath("//input[@id='form:roleArchiveAuditor' and @type='checkbox']")).click();
            webDriver.findElement(By.xpath("//input[@value='Add' and @type='submit']")).click();
            
            assertTrue("'Edit' button should be visible now", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/table/tbody/tr/td/input[@type='submit' and @value='Edit']")));
            assertTrue("'Remove' button should be visible now", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/table/tbody/tr/td/input[@type='submit' and @value='Remove']")));
        }

        assertTrue("Auth rule detail missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/table/thead/tr/th[text()='Certificate Serial Number']")));
        assertTrue("Auth rule detail missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/table/thead/tr/th[text()='Issuer DN']")));
        assertTrue("Auth rule detail missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/table/thead/tr/th[text()='Roles']")));
        assertTrue("Auth rule actions missing??", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/table/thead/tr/th[text()='Actions']")));
        
        assertTrue("Heading missing??", WebTestHelper.elementExists(By.xpath("//h2[text()='Allow Any Administrator']")));
        assertTrue("Paragraph missing??", WebTestHelper.elementExists(By.xpath("//p[contains(text(),'Note: this will override administrators added in the list above')]")));
        
        WebElement currentSetting = webDriver.findElement(By.xpath("//td[text()='Current Setting:']/following-sibling::td/b"));
        String currentSettingText = currentSetting.getText();
        assertTrue(currentSettingText.equals("Only listed") || currentSettingText.equals("Allow any"));
        assertTrue("current setting missing?", WebTestHelper.elementExists(By.xpath("//input[starts-with(@value, 'Switch to')]")));
        
        // Below code could not work, some problem due to double codes in "Allow any" and "Only listed"
//        if (currentSetting.getText().equals("Only listed")) {
//            assertTrue("current setting missing?", WebTestHelper.elementExists(By.xpath("//input[@value='Switch to \"Allow any\"']")));
//        } else {
//            assertTrue(currentSetting.getText().equals("Allow any"));
//            assertTrue("current setting missing??", WebTestHelper.elementExists(By.xpath("//input[@value='Switch to \"Only listed\"']")));
//        }

        assertTrue("Heading missing??", WebTestHelper.elementExists(By.xpath("//h2[text()='Peer Systems']")));
        assertTrue("checkbox missing??", WebTestHelper.elementExists(By.xpath("//input[contains(@id, 'allowIncoming') and @type='checkbox']")));
        assertTrue("Label missing??", WebTestHelper.elementExists(By.xpath("//label[text()='Allow incoming connections']")));
        assertTrue("button missing??", WebTestHelper.elementExists(By.xpath("//td[label[text()='Allow incoming connections']]/following-sibling::td/input[@value='Save']")));
    }
    
    public void e_verifyAuditLogTab() {
        AuditLogHelper.clickAuditLogTab();
        assertTrue("Heading missing??", WebTestHelper.elementExists(By.xpath("//h1[text()='Current Conditions']")));
        assertTrue("Heading missing??", WebTestHelper.elementExists(By.xpath("//h1[text()='Search Results']")));
    }
    
    public void f_verifyArchiveTab() {
        AllWorkersHelper.clickArchiveTab();
        assertTrue("Heading missing??", WebTestHelper.elementExists(By.xpath("//h1[text()='Current Conditions']")));
        assertTrue("Heading missing??", WebTestHelper.elementExists(By.xpath("//h1[text()='Search Results']")));
    }
    
    public void g_verifyDocumentationLink() {
        AllWorkersHelper.clickDocumentationTab();
        assertTrue("Heading missing??", WebTestHelper.elementExists(By.xpath("//span[text()='Administrators Page']")));
        assertTrue("Heading missing??", WebTestHelper.elementExists(By.xpath("//h1[text()='Search results']")));
    }

}
