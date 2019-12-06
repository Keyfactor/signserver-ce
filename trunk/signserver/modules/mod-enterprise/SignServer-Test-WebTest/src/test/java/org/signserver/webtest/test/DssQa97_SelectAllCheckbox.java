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
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import org.apache.log4j.Logger;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.signserver.webtest.util.AllWorkersHelper;
import org.signserver.webtest.util.ArchiveHelper;
import org.signserver.webtest.util.WebTestBase;
import static org.signserver.webtest.util.WebTestBase.getUniqueId;
import static org.signserver.webtest.util.WebTestBase.getWebDriver;
import org.signserver.webtest.util.WebTestHelper;
import org.signserver.webtest.util.WorkerHelper;

/**
 * DSSQA-97 "Select All" check box and removal of multiple properties.
 *
 * @author Vinay Singh
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DssQa97_SelectAllCheckbox extends WebTestBase {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(DssQa97_SelectAllCheckbox.class);
    private static final String CLASS_NAME = DssQa97_SelectAllCheckbox.class.getSimpleName();
    private static final List<String> WORKERS = new ArrayList<>(Arrays.asList(
                "cmssigner", "odfsigner", "ooxmlsigner", "pdfsigner",
                "timestamp", "xadessigner", "xmlsigner"
    ));

    private static final HashMap<String, String> WORKER_NAME_BY_WORKER_TEMPL = new HashMap<>();
    private static String cryptoToken;

    @BeforeClass
    public static void init() {
        setUp(CLASS_NAME);
        cryptoToken = WebTestHelper.addCryptoTokenP12();

        // prerequisite of having some workers
        for (String worker : WORKERS) {
            String workerName = worker + "_" + getUniqueId();
            WORKER_NAME_BY_WORKER_TEMPL.put(worker, workerName);
            AllWorkersHelper.addFromTemplate(worker + ".properties", ImmutableMap.of(
                    "WORKERGENID1.NAME", workerName,
                    "WORKERGENID1.CRYPTOTOKEN", cryptoToken
            ));
            AllWorkersHelper.assertWorkerExists(workerName);
            AllWorkersHelper.assertWorkerStatus(workerName, "ACTIVE");
        }

        WORKERS.add(cryptoToken);
    }

    @AfterClass
    public static void exit() {        
        AllWorkersHelper.removeWorkers(WORKERS);
        getWebDriver().quit();
    }

    /**
     * Toggles 'Select All' checkbox on 'All Workers' screen.
     *
     */
    @Test
    public void a_ToggleSelectAllCheckboxOnAllWorkersScreen() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();

        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxCheckedOnAllWorkersScreen(WORKERS);

        AllWorkersHelper.uncheckSelectAllCheckbox();
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUncheckedOnAllWorkersScreen(WORKERS);
    }
    
    /**
     * Toggles 'Select All' checkbox on 'Workers Activate' screen.
     *
     */
    @Test
    public void b_ToggleSelectAllCheckboxOnActivateScreen() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();
        
        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.clickActivateButton();

        assertFalse("Select All checkbox should not be checked on Activate screen", AllWorkersHelper.isSelectAllCheckboxChecked());        
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);
        
        // in this state, Select All checkbox is unchecked but workers checkboxes are checked so two times toggling/clicking required to deSelect all worker checkboxes
        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.uncheckSelectAllCheckbox();
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);
        
        // Toggle Select All checkbox multiple times and check if state of worker checkboxes matches
        for (int i = 0; i < 6; i++) {
            AllWorkersHelper.checkSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);
            AllWorkersHelper.uncheckSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        }

        // click 'Cancel' button
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Cancel']")).click();

        // Back to All workers screen now
        assertFalse("Select All checkbox should not be checked on all workers screen", AllWorkersHelper.isSelectAllCheckboxChecked());
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxCheckedOnAllWorkersScreen(WORKERS);
    }
    
    /**
     * Toggles 'Select All' checkbox on 'Workers Deactivate' screen.
     *
     */
    @Test
    public void c_ToggleSelectAllCheckboxOnDeactivateScreen() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();

        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.clickDeactivateButton();

        assertFalse("Select All checkbox should not be checked on Deactivate screen", AllWorkersHelper.isSelectAllCheckboxChecked());

        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);

        // in this state, Select All checkbox is unchecked but workers checkboxes are checked so two times toggling/clicking required to deSelect all worker checkboxes
        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.uncheckSelectAllCheckbox();
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        // Toggle Select All checkbox multiple times and check if state of worker checkboxes matches
        for (int i = 0; i < 6; i++) {
            AllWorkersHelper.checkSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);
            AllWorkersHelper.uncheckSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        }

        // click 'Cancel' button
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Cancel']")).click();

        // Back to All workers screen now
        assertFalse("Select All checkbox should not be checked on all workers screen", AllWorkersHelper.isSelectAllCheckboxChecked());
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxCheckedOnAllWorkersScreen(WORKERS);
    }
    
    /**
     * Toggles 'Select All' checkbox on 'Workers Renew key' screen.
     *
     */
    @Test
    public void d_ToggleSelectAllCheckboxOnRenewKeysScreen() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();

        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.clickRenewKeyButton();

        assertFalse("Select All checkbox should not be checked on Renew Keys screen", AllWorkersHelper.isSelectAllCheckboxChecked());

        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);

        // in this state, Select All checkbox is unchecked but workers checkboxes are checked so two times toggling/clicking required to deSelect all worker checkboxes
        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.uncheckSelectAllCheckbox();
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        // Toggle Select All checkbox multiple times and check if state of worker checkboxes matches
        for (int i = 0; i < 6; i++) {
            AllWorkersHelper.checkSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);
            AllWorkersHelper.uncheckSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        }

        // click 'Cancel' button
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Cancel']")).click();

        // Back to All workers screen now
        assertFalse("Select All checkbox should not be checked on all workers screen", AllWorkersHelper.isSelectAllCheckboxChecked());
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxCheckedOnAllWorkersScreen(WORKERS);
    }
    
    /**
     * Toggles 'Select All' checkbox on 'Workers Test Key' screen.
     *
     */
    @Test
    public void e_ToggleSelectAllCheckboxOnTestKeysScreen() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();

        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.clickTestKeysButton();

        assertFalse("Select All checkbox should not be checked on Test Keys screen", AllWorkersHelper.isSelectAllCheckboxChecked());

        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);

        // in this state, Select All checkbox is unchecked but workers checkboxes are checked so two times toggling/clicking required to deSelect all worker checkboxes
        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.uncheckSelectAllCheckbox();
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        // Toggle Select All checkbox multiple times and check if state of worker checkboxes matches
        for (int i = 0; i < 6; i++) {
            AllWorkersHelper.checkSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);
            AllWorkersHelper.uncheckSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        }

        // click 'Cancel' button
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Cancel']")).click();

        // Back to All workers screen now
        assertFalse("Select All checkbox should not be checked on all workers screen", AllWorkersHelper.isSelectAllCheckboxChecked());
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxCheckedOnAllWorkersScreen(WORKERS);
    }
    
    /**
     * Toggles 'Select All' checkbox on 'Workers Generate CSR' screen.
     *
     */
    @Test
    public void f_ToggleSelectAllCheckboxOnGenerateCSRsScreen() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();

        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.clickGenerateCSRButton();

        assertFalse("Select All checkbox should not be checked on Generate CSR screen", AllWorkersHelper.isSelectAllCheckboxChecked());

        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);

        // in this state, Select All checkbox is unchecked but workers checkboxes are checked so two times toggling/clicking required to deSelect all worker checkboxes
        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.uncheckSelectAllCheckbox();
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        // Toggle Select All checkbox multiple times and check if state of worker checkboxes matches
        for (int i = 0; i < 6; i++) {
            AllWorkersHelper.checkSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);
            AllWorkersHelper.uncheckSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        }

        // click 'Cancel' button
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Cancel']")).click();

        // Back to All workers screen now
        assertFalse("Select All checkbox should not be checked on all workers screen", AllWorkersHelper.isSelectAllCheckboxChecked());
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxCheckedOnAllWorkersScreen(WORKERS);
    }
    
    /**
     * Toggles 'Select All' checkbox on 'Workers Install Certificate' screen.
     *
     */
    @Test
    public void g_ToggleSelectAllCheckboxOnInstallCertificatesScreen() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();

        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.clickInstallCertificatesButton();

        assertFalse("Select All checkbox should not be checked on Install Certificates screen", AllWorkersHelper.isSelectAllCheckboxChecked());

        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);

        // in this state, Select All checkbox is unchecked but workers checkboxes are checked so two times toggling/clicking required to deSelect all worker checkboxes
        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.uncheckSelectAllCheckbox();
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        // Toggle Select All checkbox multiple times and check if state of worker checkboxes matches
        for (int i = 0; i < 6; i++) {
            AllWorkersHelper.checkSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);
            AllWorkersHelper.uncheckSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        }

        // click 'Cancel' button
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Cancel']")).click();

        // Back to All workers screen now
        assertFalse("Select All checkbox should not be checked on all workers screen", AllWorkersHelper.isSelectAllCheckboxChecked());
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxCheckedOnAllWorkersScreen(WORKERS);
    }
    
    /**
     * Toggles 'Select All' checkbox on 'Workers Renew Signer' screen.
     *
     */
    @Test
    public void h_ToggleSelectAllCheckboxOnRenewSignersScreen() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();

        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.clickRenewSignerButton();

        assertFalse("Select All checkbox should not be checked on Renew Signers screen", AllWorkersHelper.isSelectAllCheckboxChecked());

        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);

        // in this state, Select All checkbox is unchecked but workers checkboxes are checked so two times toggling/clicking required to deSelect all worker checkboxes
        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.uncheckSelectAllCheckbox();
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        // Toggle Select All checkbox multiple times and check if state of worker checkboxes matches
        for (int i = 0; i < 6; i++) {
            AllWorkersHelper.checkSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);
            AllWorkersHelper.uncheckSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        }

        // click 'Cancel' button
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Cancel']")).click();

        // Back to All workers screen now
        assertFalse("Select All checkbox should not be checked on all workers screen", AllWorkersHelper.isSelectAllCheckboxChecked());
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxCheckedOnAllWorkersScreen(WORKERS);
    }
    
    /**
     * Toggles 'Select All' checkbox on 'Remove Workers' screen.
     *
     */
    @Test
    public void i_ToggleSelectAllCheckboxOnRemoveWorkersScreen() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();

        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.clickRemoveButton();

        assertFalse("Select All checkbox should not be checked on Remove Workers screen", AllWorkersHelper.isSelectAllCheckboxChecked());

        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);

        // in this state, Select All checkbox is unchecked but workers checkboxes are checked so two times toggling/clicking required to deSelect all worker checkboxes
        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.uncheckSelectAllCheckbox();
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        // Toggle Select All checkbox multiple times and check if state of worker checkboxes matches
        for (int i = 0; i < 6; i++) {
            AllWorkersHelper.checkSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);
            AllWorkersHelper.uncheckSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        }

        // click 'Cancel' button
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Cancel']")).click();

        // Back to All workers screen now
        assertFalse("Select All checkbox should not be checked on all workers screen", AllWorkersHelper.isSelectAllCheckboxChecked());
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxCheckedOnAllWorkersScreen(WORKERS);
    }
    
    /**
     * Toggles 'Select All' checkbox on 'Reload from Database' screen.
     *
     */
    @Test
    public void j_ToggleSelectAllCheckboxOnReloadFromDatabaseScreen() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();

        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.clickReloadFromDatabaseButton();

        assertFalse("Select All checkbox should not be checked on Reload from database screen", AllWorkersHelper.isSelectAllCheckboxChecked());

        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);

        // in this state, Select All checkbox is unchecked but workers checkboxes are checked so two times toggling/clicking required to deSelect all worker checkboxes
        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.uncheckSelectAllCheckbox();
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        // Toggle Select All checkbox multiple times and check if state of worker checkboxes matches
        for (int i = 0; i < 6; i++) {
            AllWorkersHelper.checkSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);
            AllWorkersHelper.uncheckSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        }

        // click 'Cancel' button
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Cancel']")).click();

        // Back to All workers screen now
        assertFalse("Select All checkbox should not be checked on all workers screen", AllWorkersHelper.isSelectAllCheckboxChecked());
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxCheckedOnAllWorkersScreen(WORKERS);
    }
    
    /**
     * Toggles 'Select All' checkbox on 'Export Workers' screen.
     *
     */
    @Test
    public void k_ToggleSelectAllCheckboxOnExportWorkersScreen() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();

        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.clickExportButton();

        assertFalse("Select All checkbox should not be checked on Reload from database screen", AllWorkersHelper.isSelectAllCheckboxChecked());

        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);

        // in this state, Select All checkbox is unchecked but workers checkboxes are checked so two times toggling/clicking required to deSelect all worker checkboxes
        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.uncheckSelectAllCheckbox();
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        // Toggle Select All checkbox multiple times and check if state of worker checkboxes matches
        for (int i = 0; i < 6; i++) {
            AllWorkersHelper.checkSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(WORKERS);
            AllWorkersHelper.uncheckSelectAllCheckbox();
            AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(WORKERS);

        }

        // click 'Cancel' button
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Cancel']")).click();

        // Back to All workers screen now
        assertFalse("Select All checkbox should not be checked on all workers screen", AllWorkersHelper.isSelectAllCheckboxChecked());
        AllWorkersHelper.workersSelectionMatchesWhenSelectAllCheckboxCheckedOnAllWorkersScreen(WORKERS);
    }
    
    /**
     * Toggles 'Select All' checkbox on 'Global Configuration' screen.
     *
     */
    @Test
    public void l_ToggleSelectAllCheckboxOnGlobalConfigurationScreen() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickGlobalConfigurationTab();
        
        assertTrue("function is missing?", WebTestHelper.elementExists(By.xpath("//form/a[text()='Add…']")));
        assertTrue("function is missing?", WebTestHelper.elementExists(By.xpath("//form/input[@value='Remove selected…']")));
        assertTrue("Heading missing?", WebTestHelper.elementExists(By.xpath("//h1[text()='Properties']")));

        assertTrue("Select All checkbox is missing?", AllWorkersHelper.isSelectAllCheckboxExists());

        if (WebTestHelper.elementExists(By.xpath("//td/a[text()='Edit']"))) {
            assertTrue("Checkbox missing?", WebTestHelper.elementExists(By.xpath("//td[a[text()='Edit']]/preceding-sibling::td/preceding-sibling::td/preceding-sibling::td/input[@type='checkbox']")));
        }

        int noOfEntries = webDriver.findElements(By.xpath("//td/a[text()='Edit']")).size();
        int noOfCheckBoxesInTable = webDriver.findElements(By.xpath("//input[@class='allSelectable' and @type='checkbox']")).size();
        assertEquals("No of checkboxes should be equal to no of entries in table", noOfCheckBoxesInTable, noOfEntries);

        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.clickRemoveButton();

        assertTrue("Heading missing?", WebTestHelper.elementExists(By.xpath("//h1[text()='Remove Properties']")));
        assertTrue("Heading missing?", WebTestHelper.elementExists(By.xpath("//h2[contains(text(), 'Are you sure you want to remove the worker properties?')]")));

        // click 'Cancel' button
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Cancel']")).click();

        // back to 'Global Configuraion Properties' page
        List<WebElement> checkboxes = webDriver.findElements(By.xpath("//input[@class='allSelectable' and @type='checkbox']"));
        for (WebElement checkbox : checkboxes) {
            assertFalse("checkbox should not be selected", checkbox.isSelected());
        }
    }
    
    /**
     * Toggles 'Select All' checkbox on 'Worker Configuration' screen.
     *
     */
    @Test
    public void m_ToggleSelectAllCheckboxOnWorkerConfigurationScreen() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.openWorker("pdfsigner");
        WorkerHelper.clickConfigurationTab();
        
        assertTrue("function is missing?", WebTestHelper.elementExists(By.xpath("//form/a[text()='Add…']")));
        assertTrue("function is missing?", WebTestHelper.elementExists(By.xpath("//form/input[@value='Remove selected…']")));        
        assertTrue("Heading missing?", WebTestHelper.elementExists(By.xpath("//h2[text()='Properties']")));

        assertTrue("Select All checkbox is missing?", AllWorkersHelper.isSelectAllCheckboxExists());

        if (WebTestHelper.elementExists(By.xpath("//td/a[text()='Edit']"))) {
            assertTrue("Checkbox missing?", WebTestHelper.elementExists(By.xpath("//td[a[text()='Edit']]/preceding-sibling::td/preceding-sibling::td/preceding-sibling::td/input[@type='checkbox']")));
        }

        int noOfEntries = webDriver.findElements(By.xpath("//td/a[text()='Edit']")).size();
        int noOfCheckBoxesInTable = webDriver.findElements(By.xpath("//input[@class='allSelectable' and @type='checkbox']")).size();
        assertEquals("No of checkboxes should be equal to no of entries in table", noOfCheckBoxesInTable, noOfEntries);

        AllWorkersHelper.checkSelectAllCheckbox();
        AllWorkersHelper.clickRemoveButton();

        assertTrue("Heading missing?", WebTestHelper.elementExists(By.xpath("//h2[text()='Remove Properties']")));
        assertTrue("Heading missing?", WebTestHelper.elementExists(By.xpath("//b[contains(text(), 'Are you sure you want to remove the worker properties?')]")));

        // click 'Cancel' button
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Cancel']")).click();

        // back to 'Worker Configuration Properties' page
        List<WebElement> checkboxes = webDriver.findElements(By.xpath("//input[@class='allSelectable' and @type='checkbox']"));
        for (WebElement checkbox : checkboxes) {
            assertFalse("checkbox should not be selected", checkbox.isSelected());
        }
        
        AllWorkersHelper.checkSelectAllCheckbox();

        // Remove all properties except - "NAME", "TYPE", "IMPLEMENTATION_CLASS
        unCheckSelectedProperty(Arrays.asList("NAME", "TYPE", "IMPLEMENTATION_CLASS"));
        // click 'Remove Selected...' button
        AllWorkersHelper.clickRemoveButton();
        // click 'Remove' button
        AllWorkersHelper.clickRemoveButton();
        propertyExists(Arrays.asList("NAME", "TYPE", "IMPLEMENTATION_CLASS"));
    }
    
    /**
     * Toggles 'Select All' checkbox on 'Archive' screen.
     *
     * @throws java.io.IOException
     */
    @Test
    public void n_ToggleSelectAllCheckboxOnArchiveScreen() throws IOException {
        int noOfSignings = 10;

        try {
            WebTestHelper.openAdminWeb();

            // provide Archive screen viewing permission
            addCurrentLoggedInAdminAndprovideArchivePermission();
            // Configure CMSSigner for Archiving
            configureSignerForArchiving();
            // Perform a test signing 10 times so 10 Archived entries (response) is created
            for (int i = 0; i < noOfSignings; i++) {
                performSigning();
            }

            WebTestHelper.openAdminWeb();
            ArchiveHelper.clickArchiveTab();

            // Toggle Select All checkbox multiple times and check if state of entries checkboxes match
            for (int i = 0; i < 6; i++) {
                AllWorkersHelper.checkSelectAllCheckbox();
                ArchiveHelper.workersSelectionMatchesWhenSelectAllCheckboxChecked(noOfSignings);
                AllWorkersHelper.uncheckSelectAllCheckbox();
                ArchiveHelper.workersSelectionMatchesWhenSelectAllCheckboxUnchecked(noOfSignings);
            }

            AllWorkersHelper.checkSelectAllCheckbox();
            // Download selected entries as a zip file
            webDriver.findElement(By.xpath("//input[@value='Download Selected in ZIP']")).click();
            assertTrue("zip file does not exist in download directory", AllWorkersHelper.fileExists("archives.zip"));

            // unzip zip file and verify that selected entries are actually inside zip file
            File zipFile = new File(WebTestBase.getTestDir(), "archives.zip");
            WebTestHelper.unzipFile(zipFile.getAbsolutePath(), WebTestBase.getTestDir());

            // Get ArchiveIDs of selected entries
            List<String> selectedArchiveIds = ArchiveHelper.getArchiveIdsOfEntries();
            for (String selectedArchiveId : selectedArchiveIds) {
                assertTrue("file correspoding to selected entry" + selectedArchiveId + " does not exist inside zip file", AllWorkersHelper.fileExists(selectedArchiveId + ".response"));
            }
        } finally {
            removeCurrentLoggedInAdmin();
            WebTestHelper.deleteTestFiles();
        }

    }
    
    private void addCurrentLoggedInAdminAndprovideArchivePermission() {
        AllWorkersHelper.clickAdministratorsTab();

        webDriver.findElement(By.xpath("//div[@id='content']/form/p/a[text()='Add…']")).click();
        webDriver.findElement(By.xpath("//input[@value='Load Current']")).click();
        webDriver.findElement(By.xpath("//input[@id='form:roleArchiveAuditor' and @type='checkbox']")).click();
        webDriver.findElement(By.xpath("//input[@value='Add' and @type='submit']")).click();
    }
    
    private void removeCurrentLoggedInAdmin() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickAdministratorsTab();

        WebTestBase.getWebDriver().findElement(By.xpath("//td[text()='723507815f93333']/following-sibling::td/following-sibling::td/following-sibling::td/input[@type='submit' and @value='Remove']")).click();
        WebTestBase.getWebDriver().findElement(By.xpath("//input[contains(@value, 'Remove')]")).click();
    }
    
    private void configureSignerForArchiving() {
        AllWorkersHelper.clickWorkersTab();
        AllWorkersHelper.openWorker("cmssigner");
        WorkerHelper.clickConfigurationTab();
        WorkerHelper.addProperty("ARCHIVERS", "org.signserver.server.archive.base64dbarchiver.Base64DatabaseArchiver");        
    }
    
    private void performSigning() {
        String cmsSignerName = WORKER_NAME_BY_WORKER_TEMPL.get("cmssigner");
        AllWorkersHelper.genericSignByDirectInput(cmsSignerName, "data");
        // assertTrue("Signed file does not exist in download directory", AllWorkersHelper.fileExists("process"));
    }
    
    private void unCheckSelectedProperty(List<String> propList) {
        for (String propName : propList) {
            WebElement checkbox = webDriver.findElement(By.xpath("//td[text()='" + propName + "']/preceding-sibling::td/input[@type='checkbox']"));
            if (checkbox.isSelected()) {
                checkbox.click();
            }
        }
    }
    
    private void propertyExists(List<String> propList) {
        for (String propName : propList) {
            assertTrue("Property missing?", WebTestHelper.elementExists(By.xpath("//td[text()='" + propName + "']")));
        }
    }
    
}
