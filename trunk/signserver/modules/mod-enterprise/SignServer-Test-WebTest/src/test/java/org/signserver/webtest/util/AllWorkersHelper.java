/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.webtest.util;

import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import org.junit.Assert;
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
}
