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

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import org.junit.Assert;
import static org.junit.Assert.assertEquals;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebElement;

/**
 * WorkersHelper contains helper methods for the 'Workers' page.
 * 
 * @version $Id$
 */
public class AllWorkersHelper {

    private AllWorkersHelper() {
        throw new AssertionError("Cannot instantiate class");
    }

    /* 'All Workers' methods */

    /**
     * Clicks the 'Workers' tab.
     */
    public static void clickWorkersTab() {
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Workers' and contains(@href, 'workers.xhtml')]")).click();
    }
    
    /**
     * Clicks the 'Global Configuration' tab.
     */
    public static void clickGlobalConfigurationTab() {
        WebTestBase.getWebDriver().findElement(By.xpath("//div[@id='top-menu']/ul/li/a[text()='Global Configuration']")).click();
    }
    
    /**
     * Clicks the 'Administrators' tab.
     */
    public static void clickAdministratorsTab() {
        WebTestBase.getWebDriver().findElement(By.xpath("//div[@id='top-menu']/ul/li/a[text()='Administrators']")).click();
    }
    
    /**
     * Clicks the 'Archive' tab.
     */
    public static void clickArchiveTab() {
        WebTestBase.getWebDriver().findElement(By.xpath("//div[@id='top-menu']/ul/li/a[text()='Archive']")).click();
    }
    
    /**
     * Clicks the 'Documentation' tab.
     */
    public static void clickDocumentationTab() {
        WebTestBase.getWebDriver().findElement(By.xpath("//div[@id='top-menu']/ul/li/a[text()='Documentation']")).click();
    }

    /**
     * Clicks on a worker in the list 'All Workers' to open its worker page.
     * 
     * @param workerName the name of the worker
     */
    public static void openWorker(String workerName) {
        WebTestBase.getWebDriver().findElement(By.xpath("//a[starts-with(text(), '" + workerName + "')]")).click();
    }

    /**
     * Selects a worker in the list 'All Workers'.
     * 
     * A non-existent worker is ignored.
     * 
     * @param workerName the name of the worker
     */
    public static void selectWorker(String workerName) {
        try {
            WebElement checkbox = WebTestBase.getWebDriver().findElement(By.xpath("//td[table//table//a[starts-with(text(), '" + workerName + "')]]/preceding-sibling::td/input"));
            if (!checkbox.isSelected()) {
                checkbox.click();
            }
        } catch (NoSuchElementException e) {
            // Worker did not exist, do nothing
        }
    }

    /**
     * Deselects a worker in the list 'All Workers'.
     * 
     * A non-existent worker is ignored.
     * 
     * @param workerName the name of the worker
     */
    public static void deselectWorker(String workerName) {
        try {
            WebElement checkbox = WebTestBase.getWebDriver().findElement(By.xpath("//td[table//table//a[starts-with(text(), '" + workerName + "')]]/preceding-sibling::td/input"));
            if (checkbox.isSelected()) {
                checkbox.click();
            }
        } catch (NoSuchElementException e) {
            // Worker did not exist, do nothing
        }
    }
    
    /**
     * Checks 'Select All' checkbox.
     *
     */
    public static void checkSelectAllCheckbox() {
        WebElement selectAllcheckboxElement = WebTestBase.getWebDriver().findElement(By.xpath("//input[@class = 'jsHidden' and @type='checkbox' and contains(@onclick, 'toggleCheckboxes')]"));
        if (!selectAllcheckboxElement.isSelected()) {
            selectAllcheckboxElement.click();
        }
    }
    
     /**
     * Unchecks 'Select All' checkbox.
     *
     */
    public static void uncheckSelectAllCheckbox() {
        WebElement selectAllcheckboxElement = WebTestBase.getWebDriver().findElement(By.xpath("//input[@class = 'jsHidden' and @type='checkbox' and contains(@onclick, 'toggleCheckboxes')]"));
        if (selectAllcheckboxElement.isSelected()) {
            selectAllcheckboxElement.click();
        }
    }
    
    /**
     * Checks if 'Select All' checkbox is selected or not.
     *
     * @return
     */
    public static boolean isSelectAllCheckboxChecked() {
        WebElement selectAllcheckboxElement = WebTestBase.getWebDriver().findElement(By.xpath("//input[@class = 'jsHidden' and @type='checkbox' and contains(@onclick, 'toggleCheckboxes')]"));
        return selectAllcheckboxElement.isSelected();
    }
    
    /**
     * Checks if 'Select All' checkbox exists on GUI.
     *
     * @return
     */
    public static boolean isSelectAllCheckboxExists() {
        return WebTestHelper.elementExists(By.xpath("//input[@class = 'jsHidden' and @type='checkbox' and contains(@onclick, 'toggleCheckboxes')]"));
    }
    
    /**
     * Asserts that state of other checkboxes match with 'Select All' checkbox
     * when checked on below screens.
     * 1) Activate.
     * 2) Deactivate.
     * 3) Renew key.
     * 4) Test key.
     * 5) Generate CSR.
     * 6) Install Certificates.
     * 7) Renew Signer.
     * 8) Remove.
     * 9) Reload from database.
     * 10) Export.
     *
     * @param WORKERS
     */
    public static void workersSelectionMatchesWhenSelectAllCheckboxChecked(List<String> WORKERS) {
        int noOfSelectedCheckBox = 0;
        for (String workerName : WORKERS) {
            //  selectWorker(workerName);
            WebElement checkbox = WebTestBase.getWebDriver().findElement(By.xpath("//td[a[starts-with(text(), '" + workerName + "')]]/preceding-sibling::td/preceding-sibling::td/input"));
            if (checkbox.isSelected()) {
                // checkbox.click();
                noOfSelectedCheckBox++;
            }
        }
        assertEquals("No of checked checkboxes should match with no of workers", WORKERS.size(), noOfSelectedCheckBox);
    }
    
    /**
     * Asserts that state of other checkboxes match with 'Select All' checkbox
     * when checked on 'All Workers' screen.
     *
     * @param WORKERS
     */
    public static void workersSelectionMatchesWhenSelectAllCheckboxCheckedOnAllWorkersScreen(List<String> WORKERS) {
        int noOfSelectedCheckBox = 0;
        for (String workerName : WORKERS) {
            //  selectWorker(workerName);
            WebElement checkbox = WebTestBase.getWebDriver().findElement(By.xpath("//td[table//table//a[starts-with(text(), '" + workerName + "')]]/preceding-sibling::td/input"));
            if (checkbox.isSelected()) {
                // checkbox.click();
                noOfSelectedCheckBox++;
            }
        }
        assertEquals("No of checked checkboxes should match with no of workers", WORKERS.size(), noOfSelectedCheckBox);
    }
    
    /**
     * Asserts that state of other checkboxes match with 'Select All' checkbox
     * when unchecked on below screens.
     * 1) Activate.
     * 2) Deactivate.
     * 3) Renew key.
     * 4) Test key.
     * 5) Generate CSR.
     * 6) Install Certificates.
     * 7) Renew Signer.
     * 8) Remove.
     * 9) Reload from database.
     * 10) Export.
     *
     * @param WORKERS
     */
    public static void workersSelectionMatchesWhenSelectAllCheckboxUnchecked(List<String> WORKERS) {
        int noOfDeSelectedCheckBox = 0;
        for (String workerName : WORKERS) {
            //  selectWorker(workerName);
            WebElement checkbox = WebTestBase.getWebDriver().findElement(By.xpath("//td[a[starts-with(text(), '" + workerName + "')]]/preceding-sibling::td/preceding-sibling::td/input"));
            if (!checkbox.isSelected()) {
                noOfDeSelectedCheckBox++;
            }
        }
        assertEquals("No of unchecked checkboxes should match with no of workers", WORKERS.size(), noOfDeSelectedCheckBox);
    }
    
    /**
     * Asserts that state of other checkboxes match with 'Select All' checkbox
     * when unchecked on 'All Workers' screen.
     *
     * @param WORKERS
     */
    public static void workersSelectionMatchesWhenSelectAllCheckboxUncheckedOnAllWorkersScreen(List<String> WORKERS) {
        int noOfDeSelectedCheckBox = 0;
        for (String workerName : WORKERS) {
            //  selectWorker(workerName);
            WebElement checkbox = WebTestBase.getWebDriver().findElement(By.xpath("//td[table//table//a[starts-with(text(), '" + workerName + "')]]/preceding-sibling::td/input"));
            if (!checkbox.isSelected()) {
                noOfDeSelectedCheckBox++;
            }
        }
        assertEquals("No of unchecked checkboxes should match with no of workers", WORKERS.size(), noOfDeSelectedCheckBox);
    }

    /**
     * Checks that a worker exists in the list 'All Workers', fails otherwise.
     * 
     * @param workerName the name of the worker
     */
    public static void assertWorkerExists(String workerName) {
        WebTestHelper.openAdminWeb();
        clickWorkersTab();
        Assert.assertTrue("The worker did not exist in the list 'All Workers'",
                WebTestHelper.elementExists(By.xpath("//a[starts-with(text(), '" + workerName + "')]")));
    }

    /**
     * Checks that a worker in the list 'All Workers' has a given status,
     * fails otherwise.
     * 
     * @param workerName the name of the worker
     * @param status the expected status, e.g. 'ACTIVE', 'OFFLINE'
     */
    public static void assertWorkerStatus(String workerName, String status) {
        WebTestHelper.openAdminWeb();
        clickWorkersTab();
        Assert.assertTrue("The worker did not have the status '" + status + "'",
                WebTestHelper.elementExists(By.xpath("//tr[td/a[starts-with(text(), '" + workerName + "')]]/following-sibling::tr/td[text()='" + status + "']")));
    }

    /* Add worker methods */

    /**
     * Clicks the correct 'Choose Method' button.
     * 
     * @param addMethod the method to use, e.g. "From Template", "From File" or "By Properties"
     */
    public static void clickMethodButton(String addMethod) {
        WebTestBase.getWebDriver().findElement(By.xpath("//input[@value='" + addMethod + "']")).click();
    }

    /**
     * Clicks the 'Apply' button.
     */
    public static void clickApplyButton() {
        WebTestBase.getWebDriver().findElement(By.xpath("//input[@value='Apply']")).click();
    }

    /**
     * Selects a template from the 'Load From Template' dropdown and clicks 'Next'.
     * 
     * @param template the name of the template to select
     */
    public static void selectTemplate(String template) {
        WebElement dropdown = WebTestBase.getWebDriver().findElement(By.xpath("//h2[text()='Load From Template']//following-sibling::select"));
        WebTestHelper.dropdownSelect(dropdown, template);
        WebTestBase.getWebDriver().findElement(By.xpath("//input[@value='Next']")).click();
    }

    /**
     * Comments out all occurrences of a property with a given name in the
     * 'Configuration' textarea while adding a worker.
     * 
     * @param property the name of the property
     */
    public static void commentProperty(String property) {
        ((JavascriptExecutor) WebTestBase.getWebDriver()).executeScript(
                "document.getElementById(\"configForm:configuration\").value = document.getElementById(\"configForm:configuration\").value.replace(/^" + property + "/gm, \"#" + property + "\");");
    }

    /**
     * Adds a new line to the 'Configuration' textarea while adding a worker on
     * the form "property=value".
     * 
     * @param property the name of the property
     * @param value the value of the property
     */
    public static void addProperty(String property, String value) {
        ((JavascriptExecutor) WebTestBase.getWebDriver()).executeScript(
                "document.getElementById(\"configForm:configuration\").value = document.getElementById(\"configForm:configuration\").value + \"\\n" + property + "=" + value + "\"");
    }

    /**
     * Sets a property in the 'Configuration' textarea while adding a worker.
     * 
     * Any existing properties in the textarea with the same name are commented out,
     * so this method can safely be used both for editing existing properties and
     * adding new properties.
     * 
     * @param property the name of the property
     * @param value the value of the property
     */
    public static void setProperty(String property, String value) {
        commentProperty(property);
        addProperty(property, value);
    }

    /**
     * Adds a worker using the method 'From Template'.
     * 
     * @param template the name of the template to use
     * @param properties the properties to be set (or null if no properties)
     */
    public static void addFromTemplate(String template, Map<String, String> properties) {
        WebTestHelper.openAdminWeb();
        clickWorkersTab();
        WebTestHelper.clickAddLink();
        clickMethodButton("From Template");
        selectTemplate(template);
        if (properties != null) {
            for (Entry<String, String> entry : properties.entrySet()) {
                setProperty(entry.getKey(), entry.getValue());
            }
        }
        clickApplyButton();
    }

    /* Activate worker methods */

    /**
     * Clicks the 'Activate' button.
     * 
     * Can be used for both the 'Activate...' and 'Activate' buttons.
     */
    public static void clickActivateButton() {
        WebTestBase.getWebDriver().findElement(By.xpath("//input[contains(@value, 'Activate')]")).click();
    }

    /**
     * Enters an authentication code in the field 'Authentication Code' on
     * 'Activate' page.
     * 
     * @param authenticationCode the authentication code for activation
     */
    public static void enterAuthenticationCode(String authenticationCode) {
        WebElement passwordField = WebTestBase.getWebDriver().findElement(By.xpath("//input[contains(@id, 'password')]"));
        passwordField.clear();
        passwordField.sendKeys(authenticationCode);
    }

    /* Remove worker methods */

    /**
     * Clicks the 'Remove' button.
     * 
     * Can be used for both the 'Remove...' and 'Remove' buttons.
     */
    public static void clickRemoveButton() {
        WebTestBase.getWebDriver().findElement(By.xpath("//input[contains(@value, 'Remove')]")).click();
    }
    
    /**
     * Clicks the 'Renew key…' button.
     *
     */
    public static void clickRenewKeyButton() {
        WebTestBase.getWebDriver().findElement(By.xpath("//input[@value = 'Renew key…']")).click();
    }
    
    /**
     * Clicks the 'Generate CSR…' button.
     */
    public static void clickGenerateCSRButton() {
        WebTestBase.getWebDriver().findElement(By.xpath("//input[@value = 'Generate CSR…']")).click();
    }
    
    /**
     * Clicks the 'Deactivate…' or 'Deactivate…' button.
     */
    public static void clickDeactivateButton() {
        WebTestBase.getWebDriver().findElement(By.xpath("//input[contains(@value, 'Deactivate')]")).click();
    }
    
    /**
     * Clicks the 'Test key…' or 'Test key' button.
     */
    public static void clickTestKeysButton() {
        WebTestBase.getWebDriver().findElement(By.xpath("//input[contains(@value, 'Test key')]")).click();
    }
    
    /**
     * Clicks the 'Install Certificates…' or 'Install Certificates' button.
     */
    public static void clickInstallCertificatesButton() {
        WebTestBase.getWebDriver().findElement(By.xpath("//input[contains(@value, 'Install Certificates')]")).click();
    }
    
    /**
     * Clicks the 'Renew signer…' or 'Renew signer' button.
     */
    public static void clickRenewSignerButton() {
        WebTestBase.getWebDriver().findElement(By.xpath("//input[contains(@value, 'Renew signer')]")).click();
    }
    
    /**
     * Clicks the 'Reload from database…' or 'Reload from database' button.
     */
    public static void clickReloadFromDatabaseButton() {
        WebTestBase.getWebDriver().findElement(By.xpath("//input[contains(@value, 'Reload from database')]")).click();
    }

    /**
     * Removes all workers in a list of worker names.
     * 
     * Non-existent workers are ignored.
     * 
     * @param workerNames the names of the workers to be removed
    */
    public static void removeWorkers(List<String> workerNames) {
        WebTestHelper.openAdminWeb();
        clickWorkersTab();
        for (String workerName : workerNames) {
            selectWorker(workerName);
        }
        clickRemoveButton();
        try {
            clickRemoveButton();
        } catch (NoSuchElementException e) {
            // Do nothing, no workers selected
        }
    }
    
    /**
     * Renew keys for given workers.
     *
     * @param workerNames
     */
    public static void renewKeys(List<String> workerNames) {
        WebTestHelper.openAdminWeb();
        clickWorkersTab();

        for (String workerName : workerNames) {
            selectWorker(workerName);
        }
        clickRenewKeyButton();

        List<WebElement> keyAlgTextBoxes = WebTestBase.getWebDriver().findElements(By.xpath("//input[contains(@id, 'keyAlg')]"));
        for (WebElement keyAlgTextBox : keyAlgTextBoxes) {
            WebTestHelper.setText(keyAlgTextBox, "RSA");
        }

        List<WebElement> keySpecTextBoxes = WebTestBase.getWebDriver().findElements(By.xpath("//input[contains(@id, 'keySpec')]"));
        for (WebElement keySpecTextBox : keySpecTextBoxes) {
            WebTestHelper.setText(keySpecTextBox, "2048");
        }

        WebTestBase.getWebDriver().findElement(By.xpath("//input[@value='Generate']")).click();
    }
    
    /**
     * Generates CSR for given workers.
     *
     * @param workerNames
     */
    public static void generateCSRs(List<String> workerNames) {
        WebTestHelper.openAdminWeb();
        clickWorkersTab();

        for (String workerName : workerNames) {
            selectWorker(workerName);
        }
        clickGenerateCSRButton();
        
        // Set signature algorithm
        List<WebElement> sigAlgTextBoxes = WebTestBase.getWebDriver().findElements(By.xpath("//input[contains(@id, 'sigAlg')]"));
        for (WebElement sigAlgTextBox : sigAlgTextBoxes) {
            WebTestHelper.setText(sigAlgTextBox, "SHA256withRSA");
        }
        
        // Set DN
        for (String workerName : workerNames) {
            WebElement dnTextBox = WebTestBase.getWebDriver().findElement(By.xpath("//td[a[starts-with(text(), '" + workerName + "')]]/following-sibling::td/following-sibling::td/following-sibling::td/input[contains(@id, 'dn')]"));
            String dnValue = "CN=" + workerName + ",OU=QA,O=SignServerTesting,C=SE";
            WebTestHelper.setText(dnTextBox, dnValue);
        }
        
        // click 'Generate'
        WebTestBase.getWebDriver().findElement(By.xpath("//input[@value='Generate']")).click();       

        // click 'Download' buttons
        WebTestBase.getWebDriver().findElement(By.xpath("//input[@value='Download']"));
        List<WebElement> downloadButtons = WebTestBase.getWebDriver().findElements(By.xpath("//input[@value='Download']"));
        assertEquals(workerNames.size(), downloadButtons.size());

        for (WebElement downloadButton : downloadButtons) {
            downloadButton.click();
        }
    }

    /* Export worker methods */

    /**
     * Clicks the 'Export...' button.
     */
    public static void clickExportButton() {
        WebTestBase.getWebDriver().findElement(By.xpath("//input[contains(@value, 'Export')]")).click();
    }

    /**
     * Checks that the text 'Configuration exported successfully' is displayed.
     */
    public static void assertExportSuccessful() {
        Assert.assertTrue("The export was not successful",
                WebTestHelper.elementExists(By.xpath("//span[text()='Configuration exported successfully']")));
    }
    
    /**
     * Sign generic document by direct input
     * @param workerName
     * @param data
     */
    public static void genericSignByDirectInput(String workerName, String data) {
       // WebTestBase.getWebDriver().findElement(By.xpath("//input[contains(@value, 'Export')]")).click();
       WebTestHelper.openClientWebPage();
       WebTestBase.getWebDriver().findElement(By.xpath("//div[@id='top-menu']/ul/li/a[text()='Direct Input']")).click();
       
       WebElement element = WebTestBase.getWebDriver().findElement(By.xpath("//div[@id='container1']/form/p[1]/input[@name='workerName']"));
       WebTestHelper.setText(element, workerName);
       
       // enter data to be signed
       WebElement dataElement = WebTestBase.getWebDriver().findElement(By.xpath("//div[@id='container1']/form/p[2]/textarea[1][@name='data']"));
       WebTestHelper.setText(dataElement, data);
       
       // submit file
        WebElement submitButton = WebTestBase.getWebDriver().findElement(By.xpath("//*[@id=\"submitButton\"]")); 
        submitButton.click();
    }
    
    /**
     * Sign generic document by file upload.
     *
     * @param workerName
     * @param testFile
     */
    public static void genericSignByFileUpload(String workerName, String testFile) {        
        WebTestHelper.openClientWebPage();

        WebElement element = WebTestBase.getWebDriver().findElement(By.xpath("//div[@id='container1']/form/p[1]/input[@name='workerName']"));
        WebTestHelper.setText(element, workerName);
        
        // upload file
        WebElement fileUploadElement = WebTestBase.getWebDriver().findElement(By.xpath("//*[@id='fileInput']"));        
        // enter the file path onto the file-selection input field
        fileUploadElement.sendKeys(testFile);
        
        // submit file
        WebElement submitButton = WebTestBase.getWebDriver().findElement(By.xpath("//*[@id=\"submitButton\"]")); 
        submitButton.click();
    }
    
    /**
     * check if file exists in test download directory.
     *
     * @param fileName
     * @return
     */
    public static boolean fileExists(String fileName) {
        File testDir = new File(WebTestBase.getTestDir(), fileName);
        return testDir.exists();
    }
    
    /**
     * deletes a file in test download directory.
     *
     * @param fileName
     */
    public static void deleteFile(String fileName) {
        File fileToDelete = new File(WebTestBase.getTestDir(), fileName);
        fileToDelete.delete();
    }
    
    /**
     * extract generated id from all workers page for given workerName.
     *
     * @param workerName
     * @return
     */
    public static String extractGeneratedWorkerId(String workerName) {
        clickWorkersTab();
        WebElement element = WebTestBase.getWebDriver().findElement(By.xpath("//tr[td/a[starts-with(text(), '" + workerName + "')]]"));
        String workerNameWithId = element.getText();
        String workerId = workerNameWithId.substring(workerName.length() + 2, workerNameWithId.length() - 1);
        return workerId;
    }
}
