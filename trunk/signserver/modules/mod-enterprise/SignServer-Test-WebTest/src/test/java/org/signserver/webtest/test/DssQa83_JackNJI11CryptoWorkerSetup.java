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
import org.apache.log4j.Logger;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.webtest.util.AllWorkersHelper;
import org.signserver.webtest.util.CryptoWorkerHelper;
import org.signserver.webtest.util.WebTestBase;
import static org.signserver.webtest.util.WebTestBase.getUniqueId;
import static org.signserver.webtest.util.WebTestBase.getWebDriver;

/**
 * DSSQA-83 JackNJI11 crypto worker setup.
 *
 * @author Vinay Singh
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DssQa83_JackNJI11CryptoWorkerSetup extends WebTestBase {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(DssQa83_JackNJI11CryptoWorkerSetup.class);
    private static final String CLASS_NAME = DssQa83_JackNJI11CryptoWorkerSetup.class.getSimpleName();
        
    private static String CRYPTO_WORKER_NAME;
    private static final String TEST_KEY = "testp11ngkey";
    private static final String PROPERTIES_FILE = "p11ng-crypto.properties";    

    @BeforeClass
    public static void init() {
        setUp(CLASS_NAME);        
        CRYPTO_WORKER_NAME = "TESTP11NG" + "_" + getUniqueId();
    }
    
    @AfterClass
    public static void exit() {
        AllWorkersHelper.removeWorkers(Arrays.asList(CRYPTO_WORKER_NAME));        
        getWebDriver().quit();
    }

    /**
     * Adds JackNJI11 crypto worker through 'From Template' option.
     */
    @Test
    public void a_addFromTemplate() {
        // Add crypto worker
        CryptoWorkerHelper.addCryptoWorkerP11(PROPERTIES_FILE, CRYPTO_WORKER_NAME, TEST_KEY);
        
        // Check that the worker was successfully added
        AllWorkersHelper.assertWorkerExists(CRYPTO_WORKER_NAME);
        
        // Don't check for status OFFLINE as crypto worker would be ACTIVE if DEFAULTKEY already existed
        // AllWorkersHelper.assertWorkerStatus(CRYPTO_WORKER_NAME, "OFFLINE");       
    }
    
    /**
     * Generates default key under crypto worker.
     */
    @Test
    public void b_generateKey() {
        CryptoWorkerHelper.generateKey(CRYPTO_WORKER_NAME, TEST_KEY, "RSA", "1024");
    }
    
    /**
     * Checks that crypto worker is ACTIVE.
     */
    @Test
    public void c_checkStatus() {
        // Check that the worker was successfully activated
        AllWorkersHelper.assertWorkerStatus(CRYPTO_WORKER_NAME, "ACTIVE");
    }

}
