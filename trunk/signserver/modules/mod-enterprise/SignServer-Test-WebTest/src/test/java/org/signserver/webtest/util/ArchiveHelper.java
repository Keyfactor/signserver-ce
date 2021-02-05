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

import java.util.ArrayList;
import java.util.List;
import static org.junit.Assert.assertEquals;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;

/**
 * ArchiveHelper contains helper methods for the 'Archive' page.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class ArchiveHelper {
    
    private static long filterTime;

    private ArchiveHelper() {
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
     * Clicks the 'Archive' tab and filters entries by the filter time.
     * 
     * This results in the Audit Log only displaying events which occurred after
     * the last call to resetFilterTime.
     */
    public static void clickArchiveTab() {
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Archive' and contains(@href, 'archive.xhtml')]")).click();
        addCondition("Time (time)", "Greater or equals", String.valueOf(filterTime));
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
     * Asserts that state of other checkboxes match with 'Select All' checkbox
     * when checked on 'Archive' screen and noOfExpectedEntries are selected.
     *
     * @param noOfExpectedEntries
     */
    public static void workersSelectionMatchesWhenSelectAllCheckboxChecked(int noOfExpectedEntries) {
        int noOfSelectedCheckBox = 0;
        List<WebElement> checkBoxes = WebTestBase.getWebDriver().findElements(By.xpath("//input[@class='allSelectable' and @type='checkbox']"));
        for (WebElement checkbox : checkBoxes) {
            if (checkbox.isSelected()) {
                noOfSelectedCheckBox++;
            }
        }

        assertEquals("No of checked checkboxes should match with no of expectedEntries", noOfExpectedEntries, noOfSelectedCheckBox);
    }

    /**
     * Asserts that state of other checkboxes match with 'Select All' checkbox
     * when unchecked on 'Archive' screen and noOfExpectedEntries are
     * deSelected.
     *
     * @param noOfExpectedEntries
     */
    public static void workersSelectionMatchesWhenSelectAllCheckboxUnchecked(int noOfExpectedEntries) {
        int noOfDeSelectedCheckBox = 0;
        List<WebElement> checkBoxes = WebTestBase.getWebDriver().findElements(By.xpath("//input[@class='allSelectable' and @type='checkbox']"));
        for (WebElement checkbox : checkBoxes) {
            if (!checkbox.isSelected()) {
                noOfDeSelectedCheckBox++;
            }
        }

        assertEquals("No of unchecked checkboxes should match with no of expectedEntries", noOfExpectedEntries, noOfDeSelectedCheckBox);
    }
    
    /**
     * Extracts and returns archiveIds of selected entries on Archive screen.
     *
     * @return
     */
    public static List<String> getArchiveIdsOfEntries() {
        List<String> selectedArchiveIds = new ArrayList<>();
        List<WebElement> archiveIdElments = WebTestBase.getWebDriver().findElements(By.xpath("//td[input[@class='allSelectable' and @type='checkbox']]/following-sibling"));
        for (WebElement archiveIdElement : archiveIdElments) {
            selectedArchiveIds.add(archiveIdElement.getText());
        }
        return selectedArchiveIds;
    }
    
}
