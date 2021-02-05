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
 * DSSQA-51 Generate CSRs for multiple signers.
 *
 * @author Vinay Singh
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DssQa51_GenerateCSRs extends WebTestBase{
    
    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(DssQa51_GenerateCSRs.class);
    private static final String CLASS_NAME = DssQa51_GenerateCSRs.class.getSimpleName();
    private static final List<String> WORKERS = new ArrayList<>(Arrays.asList(
            "cmssigner", "odfsigner", "ooxmlsigner", "pdfsigner",
            "timestamp", "xadessigner", "xmlsigner"
    ));

    private static final HashMap<String, String> WORKER_NAME_BY_WORKER_TEMPL = new HashMap<>();
    private static String cryptoToken;
    private static File keyStoreFile;

    @BeforeClass
    public static void init() {
        setUp(CLASS_NAME);
        
        keyStoreFile = new File(WebTestBase.getTestDir() + "/dss10_keystore.p12");
        // keystore file not available at the time of renewKey operation so using alternative method "addCryptoTokenP12WithKeyStoreFile"
        cryptoToken = WebTestHelper.addCryptoTokenP12WithKeyStoreFile(keyStoreFile);
        
        // perform prerequisit first (DSSQA-52)
        performPrerequisit();
    }

    @AfterClass
    public static void exit() {
        WORKERS.add(cryptoToken);
         AllWorkersHelper.removeWorkers(WORKERS);

        // Not sure why "xadessigner" was still left (with 3 properties- NAME, NEXTCERTKEY,TYPE) on workers page so second attempt to delete it
        if (WebTestHelper.elementExists(By.xpath("//a[starts-with(text(), 'xadessigner')]"))) {
            AllWorkersHelper.removeWorkers(Arrays.asList("xadessigner"));
        }

        keyStoreFile.delete();
        getWebDriver().quit();
    }
    
    /**
     * Renew keys for given workers.
     */
    @Test
    public void a_RenewKeys() {
        AllWorkersHelper.renewKeys(WORKERS);
    }
    
    /**
     * Generates CSR for given workers.
     *
     * @throws java.lang.InterruptedException
     */
    @Test
    public void b_generateCSR() throws InterruptedException {
        // Probably selenium test was much faster comapred to renewKeys() operation at server side so NEXTCERTSIGNKEY was not visible 
        // while generating CSR so using sleep() there to slow down the selenium test processing
        Thread.sleep(5000);
        AllWorkersHelper.generateCSRs(WORKERS);
    }
    
    /**
     * Asserts that generated CSR files exists in download directory.
     */
    @Test
    public void c_checkCSRfilesExist() {
        List<String> workerNames = new ArrayList<>(WORKER_NAME_BY_WORKER_TEMPL.values());
        // List<String> workerNames = (List) WORKER_NAME_BY_WORKER_TEMPL.values();

        for (String workerName : workerNames) {
            String suffix = workerName.startsWith("timestamp") ? "-ts00004.p10" : "-signer00004.p10";
            String csrFileName = workerName + suffix;
            assertTrue("CSR file does not exist in download directory", AllWorkersHelper.fileExists(csrFileName));
            AllWorkersHelper.deleteFile(csrFileName);
        }
    }
    
    private static void performPrerequisit() {
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
  
}
