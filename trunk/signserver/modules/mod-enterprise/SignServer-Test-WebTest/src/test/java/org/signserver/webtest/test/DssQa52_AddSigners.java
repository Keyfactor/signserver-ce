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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.webtest.util.AllWorkersHelper;
import org.signserver.webtest.util.WebTestBase;
import org.signserver.webtest.util.WebTestHelper;

/**
 * DSSQA-52 tests adding signers.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DssQa52_AddSigners extends WebTestBase {

    private static final String CLASS_NAME = DssQa52_AddSigners.class.getSimpleName();
    private static final List<String> WORKERS = new ArrayList<>(Arrays.asList(
            "cmssigner", "odfsigner", "ooxmlsigner", "pdfsigner",
            "timestamp", "xadessigner", "xmlsigner"
    ));

    private static String cryptoToken;

    @BeforeClass
    public static void init() {
        setUp(CLASS_NAME);
        cryptoToken = WebTestHelper.addCryptoTokenP12();
    }

    @AfterClass
    public static void exit() {
        WORKERS.add(cryptoToken);
        AllWorkersHelper.removeWorkers(WORKERS);
        getWebDriver().quit();
    }

    @Test
    public void a_addWorkers() {
        for (String worker : WORKERS) {
            String workerName = worker + "_" + getUniqueId();
            AllWorkersHelper.addFromTemplate(worker + ".properties", ImmutableMap.of(
                    "WORKERGENID1.NAME", workerName,
                    "WORKERGENID1.CRYPTOTOKEN", cryptoToken
            ));
            AllWorkersHelper.assertWorkerExists(workerName);
            AllWorkersHelper.assertWorkerStatus(workerName, "ACTIVE");
        }
    }
}
