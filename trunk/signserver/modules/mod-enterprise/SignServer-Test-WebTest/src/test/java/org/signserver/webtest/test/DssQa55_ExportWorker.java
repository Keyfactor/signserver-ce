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
package org.signserver.webtest.test;

import com.google.common.collect.ImmutableMap;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.signserver.webtest.util.AllWorkersHelper;
import org.signserver.webtest.util.WebTestBase;
import org.signserver.webtest.util.WebTestHelper;
import org.signserver.webtest.util.WorkerHelper;

/**
 * DSSQA-55 tests worker properties export.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DssQa55_ExportWorker extends WebTestBase {

    private static final String CLASS_NAME = DssQa55_ExportWorker.class.getSimpleName();
    private static final String WORKER = "odfsigner";

    private static String workerName;

    @BeforeClass
    public static void init() {
        setUp(CLASS_NAME);

        // Add worker for test
        workerName = WORKER + "_" + getUniqueId();
        AllWorkersHelper.addFromTemplate(WORKER + ".properties", ImmutableMap.of(
                "WORKERGENID1.NAME", workerName
        ));
    }

    @AfterClass
    public static void exit() {
        WebTestHelper.deleteTestFiles();
        AllWorkersHelper.removeWorkers(Arrays.asList(WORKER));
        getWebDriver().quit();
    }

    @Test
    public void a_exportWithNothingSelected() {
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();
        AllWorkersHelper.clickExportButton();

        // The list of selected workers should not exist
        Assert.assertFalse(WebTestHelper.elementExists(By.xpath("//table[contains(@id, 'table1')]")));
    }

    @Test
    public void b_exportWithWorkerSelected() {
        WebTestHelper.clickCancelLink();
        AllWorkersHelper.selectWorker(workerName);
        AllWorkersHelper.clickExportButton();

        // The list of selected workers should exist (containing only the selected worker)
        Assert.assertEquals("There was not exactly one worker in the export table", 1,
                getWebDriver().findElements(By.xpath("//table[contains(@id, 'table1')]/tbody/tr")).size());
        Assert.assertTrue("The wrong worker was in the export table", WebTestHelper.elementExists(By.xpath("//a[text()='" + workerName + "']")));

        // Generate and download the properties file
        WebTestHelper.clickGenerateButton();
        AllWorkersHelper.assertExportSuccessful();
        WebTestHelper.clickDownloadButton();
    }

    @Test
    public void c_verifyExport() {
        // Read the exported properties
        List<String> exported = new ArrayList<>();
        for (String line : WebTestHelper.linesFromFile("dump-*", StandardCharsets.ISO_8859_1)) {
            if (!line.startsWith("#")) {
                // Ignore prefix and comments
                exported.add(line.substring(line.indexOf(".") + 1));
            }
        }

        // Compare the exported properties to the 'Status Summary' page
        WebTestHelper.openAdminWeb();
        AllWorkersHelper.clickWorkersTab();
        AllWorkersHelper.openWorker(workerName);
        for (String property : exported) {
            WorkerHelper.assertStatusSummaryContains(property);
        }
    }
}
