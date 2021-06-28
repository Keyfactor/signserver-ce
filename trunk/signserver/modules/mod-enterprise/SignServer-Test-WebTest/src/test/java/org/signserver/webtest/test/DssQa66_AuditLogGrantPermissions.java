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

import java.io.File;
import java.io.IOException;
import static junit.framework.TestCase.assertEquals;
import org.apache.log4j.Logger;
import org.junit.AfterClass;
import org.junit.Assert;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.signserver.testutils.ComplianceTestUtils;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.webtest.util.AllWorkersHelper;
import org.signserver.webtest.util.AuditLogHelper;
import org.signserver.webtest.util.WebTestBase;
import static org.signserver.webtest.util.WebTestBase.getWebDriver;
import org.signserver.webtest.util.WebTestHelper;

/**
 * DSSQA-66 Audit Log: Grant Permissions.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class DssQa66_AuditLogGrantPermissions extends WebTestBase {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(DssQa66_AuditLogGrantPermissions.class);
    private static final String CLASS_NAME = DssQa66_AuditLogGrantPermissions.class.getSimpleName();

    private static ModulesTestCase testCase = new ModulesTestCase();
    private static String adminCLI;

    @BeforeClass
    public static void init() throws Exception {
        setUp(CLASS_NAME);

        // allow all wsadmins initially
        adminCLI = testCase.getSignServerHome().getAbsolutePath() + File.separator + "bin" + File.separator + "signserver";
        ComplianceTestUtils.ProcResult res = ComplianceTestUtils.execute(adminCLI, "wsadmins", "-allowany");
        Assert.assertEquals("result: " + res.getErrorMessage(), 0, res.getExitValue());
    }

    @AfterClass
    public static void exit() throws IOException {
        getWebDriver().quit();
        
        // again allow access for all admins
        ComplianceTestUtils.execute(adminCLI, "wsadmins", "-allowany");
    }

    /**
     * Grants permission to current logged-in user and verifies that it works as
     * expected.
     */
    @Test
    public void a_GrantPermisssionsAndVerify() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickAdministratorsTab();

        // Add new admin
        webDriver.findElement(By.xpath("//div[@id='content']/form/p/a[text()='Add…']")).click();
        webDriver.findElement(By.xpath("//input[@value='Load Current']")).click();

        WebElement adminCheckBox = webDriver.findElement(By.xpath("//input[@id='form:roleAdmin' and @type='checkbox']"));
        assertTrue("Admin checkbox is not selected", adminCheckBox.isSelected());

        assertTrue("Cancel link missing??", WebTestHelper.elementExists(By.xpath("//a[text()='Cancel']")));

        webDriver.findElement(By.xpath("//input[@id='form:roleAuditor' and @type='checkbox']")).click();
        webDriver.findElement(By.xpath("//input[@id='form:roleArchiveAuditor' and @type='checkbox']")).click();
        webDriver.findElement(By.xpath("//input[@id='form:rolePeerSystem' and @type='checkbox']")).click();
        webDriver.findElement(By.xpath("//input[@value='Add' and @type='submit']")).click();

        // Back to Administrators screen
        assertTrue("'Edit' button should be visible now", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/table/tbody/tr/td/input[@type='submit' and @value='Edit']")));
        assertTrue("'Remove' button should be visible now", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/table/tbody/tr/td/input[@type='submit' and @value='Remove']")));

        assertTrue("Auth rule detail heading missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/table/thead/tr/th[text()='Certificate Serial Number']")));
        assertTrue("Auth rule detail heading missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/table/thead/tr/th[text()='Issuer DN']")));
        assertTrue("Auth rule detail heading missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/table/thead/tr/th[text()='Roles']")));
        assertTrue("Auth rule actions missing??", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/table/thead/tr/th[text()='Actions']")));
        
        assertTrue("Auth rule detail missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/table/tbody/tr/td[text()='723507815f93333']")));
        String issuerDN = "C=SE, O=SignServer, OU=Testing, CN=DSS Root CA 10";
        assertTrue("Auth rule detail missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/table/tbody/tr/td[text()='" + issuerDN + "']")));
        String roles = "Admin, Auditor, Archive Auditor, Peer System";
        assertTrue("Auth rule detail missing?", WebTestHelper.elementExists(By.xpath("//div[@id='content']/form/table/tbody/tr/td[text()='" + roles + "']")));

        assertTrue("Heading missing??", WebTestHelper.elementExists(By.xpath("//h2[text()='Allow Any Administrator']")));
        assertTrue("Paragraph missing??", WebTestHelper.elementExists(By.xpath("//p[contains(text(),'Note: this will override administrators added in the list above')]")));

        assertTrue("Heading missing??", WebTestHelper.elementExists(By.xpath("//h2[text()='Peer Systems']")));
        assertTrue("checkbox missing??", WebTestHelper.elementExists(By.xpath("//input[contains(@id, 'allowIncoming') and @type='checkbox']")));
        assertTrue("Label missing??", WebTestHelper.elementExists(By.xpath("//label[text()='Allow incoming connections']")));
        assertTrue("button missing??", WebTestHelper.elementExists(By.xpath("//td[label[text()='Allow incoming connections']]/following-sibling::td/input[@value='Save']")));

        WebElement currentSetting = webDriver.findElement(By.xpath("//td[text()='Current Setting:']/following-sibling::td/b"));
        String currentSettingText = currentSetting.getText();
        assertEquals("Allow any", currentSettingText);

        //  change setting from 'Allow any' to 'Only listed' 
        assertTrue("setting switch button missing?", WebTestHelper.elementExists(By.xpath("//input[starts-with(@value, 'Switch to')]")));
        webDriver.findElement(By.xpath("//input[starts-with(@value, 'Switch to')]")).click();

        assertTrue("Heading missing??", WebTestHelper.elementExists(By.xpath("//h1[text()='Allow Only Listed']")));
        assertTrue("Heading missing??", WebTestHelper.elementExists(By.xpath("//h2[contains(text(),'Are you sure you want to change to allow only listed administrators?')]")));
        assertTrue("paragraph missing??", WebTestHelper.elementExists(By.xpath("//p[contains(text(),'First make sure that you are listed as an administrator otherwise you will be logged out without the ability to login except from command line interface.')]")));
        assertTrue("Cancel link missing??", WebTestHelper.elementExists(By.xpath("//a[text()='Cancel']")));
        webDriver.findElement(By.xpath("//input[@value = 'Apply']")).click();

        WebElement updatedSetting = webDriver.findElement(By.xpath("//td[text()='Current Setting:']/following-sibling::td/b"));
        String updatedSettingText = updatedSetting.getText();
        assertEquals("Only listed", updatedSettingText);

        AllWorkersHelper.clickWorkersTab();
        assertFalse("This heading should not be present??", WebTestHelper.elementExists(By.xpath("//h1[text()='Authorization Error']")));
        assertFalse("This paragraph should not present??", WebTestHelper.elementExists(By.xpath("//p[contains(text(),'Administrator not authorized to resource.')]")));
        
        // check access on Audit log tab
        AuditLogHelper.clickAuditLogTab();
        assertTrue("Heading missing??", WebTestHelper.elementExists(By.xpath("//h1[text()='Current Conditions']")));
        assertTrue("Heading missing??", WebTestHelper.elementExists(By.xpath("//h1[text()='Search Results']")));
    }

}
