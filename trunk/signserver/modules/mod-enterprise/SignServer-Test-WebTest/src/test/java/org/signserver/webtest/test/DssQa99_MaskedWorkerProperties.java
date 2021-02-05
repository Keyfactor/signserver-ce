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

import java.util.Arrays;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.signserver.webtest.util.AllWorkersHelper;
import org.signserver.webtest.util.AuditLogHelper;
import org.signserver.webtest.util.WebTestBase;
import org.signserver.webtest.util.WebTestHelper;
import org.signserver.webtest.util.WorkerHelper;

/**
 * DSSQA-99 tests the functionality of masked worker properties.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DssQa99_MaskedWorkerProperties extends WebTestBase {

    private static final String CLASS_NAME = DssQa99_MaskedWorkerProperties.class.getSimpleName();
    private static final String MASKED_PROPERTY_1 = "KEYSTOREPASSWORD";
    private static final String MASKED_PROPERTY_2 = "KEYDATA";
    private static final String MASKED_VALUE = "●●●●●●";

    private static String workerName;

    @BeforeClass
    public static void init() {
        setUp(CLASS_NAME);
        workerName = WebTestHelper.addCryptoTokenP12();
    }

    @AfterClass
    public static void exit() {
        AllWorkersHelper.removeWorkers(Arrays.asList(workerName));
        getWebDriver().quit();
    }

    @Test
    public void a_maskedStatusSummary() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();
        AllWorkersHelper.openWorker(workerName);
        WorkerHelper.clickStatusSummaryTab();
        WorkerHelper.assertStatusSummaryContains(MASKED_PROPERTY_1 + "=" + MASKED_VALUE);
    }

    @Test
    public void b_maskedConfiguration() {
        WorkerHelper.clickConfigurationTab();
        WorkerHelper.assertPropertyExists(MASKED_PROPERTY_1, MASKED_VALUE);
    }

    @Test
    public void c_editMaskedPropertyMismatch() {
        WorkerHelper.clickPropertyEditLink(MASKED_PROPERTY_1);
        WorkerHelper.assertEditMaskedProperty();
        WorkerHelper.editMaskedProperty(null, "foo123", "bar123");
        ;
        try {
            getWebDriver().findElement(By.xpath("//span[text()='The values do not match']"));
        } catch (NoSuchElementException e) {
            Assert.fail("No error message for value mismatch: " + e.getMessage());
        }
    }

    @Test
    public void d_editMaskedProperty() {
        AuditLogHelper.resetFilterTime();

        WorkerHelper.editMaskedProperty(null, "bar123", "bar123");
        WorkerHelper.assertPropertyExists(MASKED_PROPERTY_1, MASKED_VALUE);
    }

    @Test
    public void e_verifyAuditLog() {
        AuditLogHelper.clickAuditLogTab();
        AuditLogHelper.assertEntryExists("RELOAD_WORKER_CONFIG", "SUCCESS", null);
        AuditLogHelper.assertEntryExists("SET_WORKER_CONFIG", "SUCCESS",
                Arrays.asList("changed:" + MASKED_PROPERTY_1 + "=_MASKED_"));
    }

    @Test
    public void f_addMaskedProperty() {
        AuditLogHelper.resetFilterTime();

        AllWorkersHelper.clickWorkersTab();
        AllWorkersHelper.openWorker(workerName);
        WorkerHelper.clickConfigurationTab();
        WorkerHelper.addProperty(MASKED_PROPERTY_2, "foovalue");
        WorkerHelper.assertPropertyExists(MASKED_PROPERTY_2, MASKED_VALUE);
    }

    @Test
    public void g_commentMaskedProperty() {
        WorkerHelper.clickPropertyEditLink(MASKED_PROPERTY_2);
        WorkerHelper.assertEditMaskedProperty();
        WorkerHelper.editMaskedProperty(MASKED_PROPERTY_2 + "_", null, null);
        WorkerHelper.assertPropertyExists(MASKED_PROPERTY_2 + "_", MASKED_VALUE);
    }

    @Test
    public void h_verifyAuditLog() {
        AuditLogHelper.clickAuditLogTab();
        AuditLogHelper.assertEntryExists("RELOAD_WORKER_CONFIG", "SUCCESS", null);
        AuditLogHelper.assertEntryExists("SET_WORKER_CONFIG", "SUCCESS",
                Arrays.asList("added:" + MASKED_PROPERTY_2 + "_"));
        AuditLogHelper.assertEntryExists("SET_WORKER_CONFIG", "SUCCESS",
                Arrays.asList("removed:" + MASKED_PROPERTY_2));
    }
}
