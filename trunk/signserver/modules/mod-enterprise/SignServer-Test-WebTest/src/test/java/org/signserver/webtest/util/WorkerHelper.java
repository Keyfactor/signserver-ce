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

import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;

/**
 * WorkerHelper contains helper methods for the worker pages.
 * 
 * @version $Id$
 */
public class WorkerHelper {

    private WorkerHelper() {
        throw new AssertionError("Cannot instantiate class");
    }

    /* Status Summary methods */

    /**
     * Clicks the 'Status Summary' tab.
     */
    public static void clickStatusSummaryTab() {
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Status Summary']")).click();
    }

    /**
     * Checks that the status on 'Status Summary' page contains a given string.
     * 
     * @param toCheck the substring to check for
     */
    public static void assertStatusSummaryContains(String toCheck) {
        Assert.assertTrue("'Status Summary' did not contain the string: " + toCheck,
                WebTestBase.getWebDriver().findElement(By.xpath("//div[@id='worker_content']/pre")).getText().contains(toCheck));
    }

    /* Configuration methods */

    /**
     * Clicks the 'Configuration' tab.
     */
    public static void clickConfigurationTab() {
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Configuration']")).click();
    }

    /**
     * Clicks the 'Edit' link for a given property.
     * 
     * @param property the property to edit
     */
    public static void clickPropertyEditLink(String property) {
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Edit' and contains(@href, '" + property + "')]")).click();
    }

    /**
     * Clicks the 'Add...' link on the worker Configuration page, fills in 'Name:'
     * and 'Value:', then clicks the 'Submit' button.
     * 
     * @param name
     * @param value 
     */
    public static void addProperty(String name, String value) {
        WebTestHelper.clickAddLink();
        WebTestHelper.setText(WebTestBase.getWebDriver().findElement(By.id("form:name")), name);
        WebTestHelper.setText(WebTestBase.getWebDriver().findElement(By.id("form:value")), value);
        WebTestHelper.clickSubmitButton();
    }

    /**
     * Fills in the fields on the edit page for a masked property and clicks the
     * 'Submit' button.
     * 
     * @param name the string to put as "Name:" (or null to leave as default)
     * @param value the string to put as "Value:" (or null to leave as default)
     * @param valueConfirm the string to put as "Value (confirm):" (or null to leave as default)
     */
    public static void editMaskedProperty(String name, String value, String valueConfirm) {
        if (name != null) {
            WebTestHelper.setText(WebTestBase.getWebDriver().findElement(By.id("form:name")), name);
        }
        if (value != null) {
            WebTestHelper.setText(WebTestBase.getWebDriver().findElement(By.id("form:value_secret")), value);
        }
        if (valueConfirm != null) {
            WebTestHelper.setText(WebTestBase.getWebDriver().findElement(By.id("form:value_confirmation")), valueConfirm);
        }
        WebTestHelper.clickSubmitButton();
    }

    /**
     * Checks that a property exists in the 'Properties' table on the 'Configuration' tab.
     * 
     * @param property the property to check for
     * @param value the value to check for (can be null if no value check should be made)
     */
    public static void assertPropertyExists(String property, String value) {
        try {
            WebTestBase.getWebDriver().findElement(By.xpath("//td[text()='" + property + "']"));
            if (value != null) {
                WebTestBase.getWebDriver().findElement(By.xpath("//td[text()='" + property + "']/following-sibling::td[1][text()='" + value + "']"));
            }
        } catch (NoSuchElementException e) {
            Assert.fail("Property " + property + (value != null ? ":" + value : "") + " did not exist.");
        }
    }

    /**
     * Checks the property currently being edited is a masked property.
     * 
     * This means that it should have one 'Name' field and two 'Value' fields.
     */
    public static void assertEditMaskedProperty() {
        try {
            WebTestBase.getWebDriver().findElement(By.id("form:name"));
            WebTestBase.getWebDriver().findElement(By.id("form:value_secret"));
            WebTestBase.getWebDriver().findElement(By.id("form:value_confirmation"));
        } catch (NoSuchElementException e) {
            Assert.fail("The property currently being edited was not masked.");
        }
    }

    /* Activate worker methods */

    /**
     * Activates a single worker by opening its worker page and activating it.
     *
     * @param workerName the name of the worker
     * @param authenticationCode the authentication code for activation
     */
    public static void activateWorker(String workerName, String authenticationCode) {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();
        AllWorkersHelper.openWorker(workerName);
        AllWorkersHelper.clickActivateButton();
        AllWorkersHelper.enterAuthenticationCode(authenticationCode);
        AllWorkersHelper.clickActivateButton();
    }
}
