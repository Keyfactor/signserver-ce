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

import java.util.Arrays;
import java.util.List;
import org.junit.Assert;
import org.openqa.selenium.By;

/**
 * AuditLogHelper contains helper methods for the 'Audit Log' page.
 * 
 * @version $Id$
 */
public class AuditLogHelper {

    private static long filterTime;

    private AuditLogHelper() {
        throw new AssertionError("Cannot instantiate class");
    }

    /**
     * Resets the filter time.
     * 
     * Call this method before performing an action which should be verified in
     * the Audit Log.
     */
    public static void resetFilterTime() {
        filterTime = System.currentTimeMillis();
    }

    /**
     * Clicks the 'Audit Log' tab and filters entries by the filter time.
     * 
     * This results in the Audit Log only displaying events which occurred after
     * the last call to resetFilterTime.
     */
    public static void clickAuditLogTab() {
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Audit Log' and contains(@href, 'auditlog.xhtml')]")).click();
        addCondition("Time (timeStamp)", "Greater or equals", String.valueOf(filterTime));
    }

    /**
     * Clicks the top 'Reload' button.
     */
    public static void clickReloadButton() {
        WebTestBase.getWebDriver().findElement(By.xpath("(//input[@value='Reload'])[1]")).click();
    }

    /**
     * Adds a condition and reloads the Audit Log.
     * 
     * @param column the 'Column' value for the condition
     * @param condition the 'Condition' value for the condition
     * @param value  the 'Value' value for the condition
     */
    public static void addCondition(String column, String condition, String value) {
        WebTestHelper.dropdownSelect(WebTestBase.getWebDriver().findElement(By.xpath("//table//select")), column);
        WebTestHelper.clickAddButton();
        WebTestHelper.dropdownSelect(WebTestBase.getWebDriver().findElement(By.xpath("//table//select")), condition);
        WebTestHelper.setText(WebTestBase.getWebDriver().findElement(By.xpath("//table//input[@type='text']")), value);
        WebTestHelper.clickAddButton();
        clickReloadButton();
    }

    /**
     * Checks that an entry exists in the Audit Log.
     * 
     * The 'View' link for the Details column is clicked for each matching event
     * with the correct outcome. Then all strings in the details list will be
     * compared to the event's details, i.e. it has to contain all strings in the
     * details list.
     * 
     * @param event the name of the event
     * @param outcome the outcome
     * @param details the details to check (or null if no check should be made)
     */
    public static void assertEntryExists(String event, String outcome, final List<String> details) {
        String xpath = "//tr[td[text()='" + event + "'] and td[text()='" + outcome + "']]//a[text()='View']";
        int numberOfViewLinks = WebTestBase.getWebDriver().findElements(By.xpath(xpath)).size();
        // Click each 'View' link matching the event/outcome combination and compare it's details
        for (int i = 1; i <= numberOfViewLinks; i++) {
            boolean match = true;
            if (details != null) {
                // Check if the current entry is a match
                WebTestBase.getWebDriver().findElement(By.xpath("(" + xpath + ")[" + i + "]")).click();
                String entryDetails = WebTestBase.getWebDriver().findElement(
                        By.xpath("//td[text()='Details:']/following-sibling::td/pre")).getText();
                for (String detail : details) {
                    if (!entryDetails.contains(detail)) {
                        match = false;
                        break;
                    }
                }
                WebTestBase.getWebDriver().navigate().back();
            }
            // This entry matched the parameters
            if (match) {
                return;
            }
        }
        // No entry matched the parameters
        Assert.fail("No Audit Log entry matched the combination " + event + ", " + outcome
                + (details != null ? ", " + Arrays.toString(details.toArray()) : ""));
    }
}
