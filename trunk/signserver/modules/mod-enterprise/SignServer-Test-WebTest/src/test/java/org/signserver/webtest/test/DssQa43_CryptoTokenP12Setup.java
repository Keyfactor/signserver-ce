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
import java.util.Arrays;
import java.util.Map;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.webtest.util.AllWorkersHelper;
import org.signserver.webtest.util.WebTestBase;
import org.signserver.webtest.util.WebTestHelper;
import org.signserver.webtest.util.WorkerHelper;

/**
 * DSSQA-43 tests adding CryptoTokenP12 and activating it.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DssQa43_CryptoTokenP12Setup extends WebTestBase {

    private static final String CLASS_NAME = DssQa43_CryptoTokenP12Setup.class.getSimpleName();
    private static final String PROPERTIES_FILE = "keystore-crypto.properties";
    private static final String WORKER_PASSWORD = "foo123";

    private static Map<String, String> properties;
    private static String workerName;
    private static String keystorePath;

    @BeforeClass
    public static void init() {
        setUp(CLASS_NAME);

        // Set up fields for test
        workerName = "CryptoTokenP12_" + getUniqueId();
        keystorePath = getTestDir() + "/dss10_keystore.p12";
        properties = ImmutableMap.of(
                "WORKERGENID1.NAME", workerName,
                "WORKERGENID1.KEYSTOREPATH", keystorePath
        );

        // Copy dss10_keystore.p12 to the temporary directory
        WebTestHelper.copyFileTemporarily(getSignServerDir() + "/res/test/dss10/dss10_keystore.p12", keystorePath);
    }

    @AfterClass
    public static void exit() {
        AllWorkersHelper.removeWorkers(Arrays.asList(workerName));
        getWebDriver().quit();
    }

    @Test
    public void a_addFromTemplate() {
        AllWorkersHelper.addFromTemplate(PROPERTIES_FILE, properties);

        // Check that the worker was successfully added and has the status 'OFFLINE'
        AllWorkersHelper.assertWorkerExists(workerName);
        AllWorkersHelper.assertWorkerStatus(workerName, "OFFLINE");
    }

    @Test
    public void b_openWorkerAndActivate() {
        WorkerHelper.activateWorker(workerName, WORKER_PASSWORD);

        // Check that the worker was successfully activated
        AllWorkersHelper.assertWorkerStatus(workerName, "ACTIVE");
    }
}
