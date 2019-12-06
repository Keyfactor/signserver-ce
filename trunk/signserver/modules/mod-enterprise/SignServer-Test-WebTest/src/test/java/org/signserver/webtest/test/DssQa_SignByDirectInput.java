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
import java.util.HashMap;
import java.util.List;
import org.apache.log4j.Logger;
import org.junit.AfterClass;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.signserver.webtest.util.AllWorkersHelper;
import org.signserver.webtest.util.WebTestBase;
import static org.signserver.webtest.util.WebTestBase.getUniqueId;
import static org.signserver.webtest.util.WebTestBase.getWebDriver;
import org.signserver.webtest.util.WebTestHelper;

/**
 * Perform cms, plain, xadES and xml signing by direct data input.
 *
 * @author Vinay Singh
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DssQa_SignByDirectInput extends WebTestBase {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(DssQa_SignByDirectInput.class);
    private static final String CLASS_NAME = DssQa_SignByDirectInput.class.getSimpleName();
    private static final List<String> WORKERS = new ArrayList<>(Arrays.asList(
            "cmssigner", "plainsigner", "xadessigner", "xmlsigner"));
    private static final String DATA = "<xml/>";
    private static final HashMap<String, String> WORKER_NAME_BY_WORKER_TEMPL = new HashMap<>();

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

    /**
     * Adds following signers - "cmssigner", "plainsigner", "xadessigner" and "xmlsigner".
     */
    @Test
    public void a_addWorkers() {
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
    }

    /**
     * Performs CMS signing.
     */
    @Test
    public void b_CMSSigning() {
        try {
            String cmsSignerName = WORKER_NAME_BY_WORKER_TEMPL.get("cmssigner");
            AllWorkersHelper.genericSignByDirectInput(cmsSignerName, DATA);
            assertTrue("Signed file does not exist in download directory", AllWorkersHelper.fileExists("process"));
        } finally {
            WebTestHelper.deleteTestFiles();
        }
    }

    /**
     * Performs PLAIN signing.
     */
    @Test
    public void c_PlainSigning() {
        try {
            String plainSignerName = WORKER_NAME_BY_WORKER_TEMPL.get("plainsigner");
            AllWorkersHelper.genericSignByDirectInput(plainSignerName, DATA);
            assertTrue("Signed file does not exist in download directory", AllWorkersHelper.fileExists("process"));
        } finally {
            WebTestHelper.deleteTestFiles();
        }
    }

    /**
     * Performs XML signing.
     */
    @Test
    public void d_XMLSigning() {
        String xmlsignerName = WORKER_NAME_BY_WORKER_TEMPL.get("xmlsigner");
        AllWorkersHelper.genericSignByDirectInput(xmlsignerName, DATA);

        // check for successful signing output            
        assertTrue("Signing was not successful?", WebTestHelper.elementExists(By.xpath("//*[name()='SignatureValue']")));
    }

    /**
     * Performs xadES signing.
     */
    @Test
    public void e_xadESSigning() {
        String xadESSignerName = WORKER_NAME_BY_WORKER_TEMPL.get("xadessigner");
        AllWorkersHelper.genericSignByDirectInput(xadESSignerName, DATA);

        // check for successful signing output            
        assertTrue("Signing was not successful?", WebTestHelper.elementExists(By.xpath("//*[name()='xades:QualifyingProperties']")));
    }

}
