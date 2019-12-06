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
 * DSSQA-89 JackNJI11KeyWrappingCryptoWorker setup .
 *
 * @author Vinay Singh
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DssQa89_JackNJI11KeyWrappingCryptoWorkerSetup extends WebTestBase{
    
    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(DssQa89_JackNJI11KeyWrappingCryptoWorkerSetup.class);
    private static final String CLASS_NAME = DssQa89_JackNJI11KeyWrappingCryptoWorkerSetup.class.getSimpleName();    

    private static String P11NG_CRYPTO_WORKER_NAME;
    private static String P11NG_KEYWRAPPING_CRYPTO_WORKER_NAME;
        
    private static final String TEST_KEY = "testdefaultkey";
    private static final String TEST_WRAPPING_KEY = "testsecretkey";
    private static final String TEST_WRAPPED_KEY = "signertestkey";
    private static final String P11NG_CRYPTO_PROPERTIES_FILE = "p11ng-crypto.properties";
    private static final String P11NG_KEYWRAPPING_CRYPTO_PROPERTIES_FILE = "p11ng-keywrapping-crypto.properties";   
    private static final String PRIVATE_KEY_ALG = "RSA";
    private static final String SECRET_KEY_ALG = "AES";
    private static final String PRIVATE_KEY_SPEC = "2048";
    private static final String SECRET_KEY_SPEC = "128";

    @BeforeClass
    public static void init() {
        setUp(CLASS_NAME);
        P11NG_CRYPTO_WORKER_NAME = "TESTP11NG" + "_" + getUniqueId();
        P11NG_KEYWRAPPING_CRYPTO_WORKER_NAME = "TESTP11NGKEYWRAPPING" + "_" + getUniqueId();
       
        // perform prerequisit first (DSSQA-83)
        performPrerequisit();
    }
    
    @AfterClass
    public static void exit() {
        AllWorkersHelper.removeWorkers(Arrays.asList(P11NG_CRYPTO_WORKER_NAME, P11NG_KEYWRAPPING_CRYPTO_WORKER_NAME));
        getWebDriver().quit();
    }
    
    /**
     * Generates wrapping key under P11NG crypto worker and verifies wrappng key
     * details.
     */
    @Test
    public void a_generateWrappingKey() {
        // Generate symmetric secret wrapping key
        CryptoWorkerHelper.generateKey(P11NG_CRYPTO_WORKER_NAME, TEST_WRAPPING_KEY, SECRET_KEY_ALG, SECRET_KEY_SPEC);
        
       // Check symmetric key details
        CryptoWorkerHelper.assertSymmetricKeyDetails(P11NG_CRYPTO_WORKER_NAME, TEST_WRAPPING_KEY, SECRET_KEY_ALG, SECRET_KEY_SPEC);
    }
    
    /**
     * Adds JackNJI11 key wrapping crypto worker through 'From Template' option.
     */
    @Test
    public void b_createKeyWrappingCryptoWorker() {
        Map<String, String> properties = ImmutableMap.<String, String>builder()
                .put("WORKERGENID1.NAME", P11NG_KEYWRAPPING_CRYPTO_WORKER_NAME)
                .put("WORKERGENID1.CRYPTOTOKEN", P11NG_CRYPTO_WORKER_NAME)                
                .put("WORKERGENID1.DEFAULTKEY", TEST_WRAPPING_KEY).build();

        AllWorkersHelper.addFromTemplate(P11NG_KEYWRAPPING_CRYPTO_PROPERTIES_FILE, properties);
        
        // Check that the worker was successfully added
        AllWorkersHelper.assertWorkerExists(P11NG_CRYPTO_WORKER_NAME);
        // Check that worker is ACTIVE
        AllWorkersHelper.assertWorkerStatus(P11NG_CRYPTO_WORKER_NAME, "ACTIVE"); 

    }
    
    /**
     * Performs following operations under key wrapping crypto worker.
     * 1) Generates signer wrapped key 
     * 2) Verifies wrapped key details
     * 3) Performs test key operation for wrapped key.
     */
    @Test
    public void c_createWrappedKey() {
        // Generate wrapped key
        CryptoWorkerHelper.generateKey(P11NG_KEYWRAPPING_CRYPTO_WORKER_NAME, TEST_WRAPPED_KEY, PRIVATE_KEY_ALG, PRIVATE_KEY_SPEC);

        // Check wrapped key details
        CryptoWorkerHelper.assertWrappedKeyDetails(P11NG_KEYWRAPPING_CRYPTO_WORKER_NAME, TEST_WRAPPED_KEY, PRIVATE_KEY_ALG, PRIVATE_KEY_SPEC, TEST_WRAPPING_KEY);
        
        // Test wrapped key
        CryptoWorkerHelper.testKey(P11NG_KEYWRAPPING_CRYPTO_WORKER_NAME, TEST_WRAPPED_KEY);
    }
       
    private static void performPrerequisit() {
        // Add crypto worker
        CryptoWorkerHelper.addCryptoWorkerP11(P11NG_CRYPTO_PROPERTIES_FILE, P11NG_CRYPTO_WORKER_NAME, TEST_KEY);
        
        // Check that the worker was successfully added
        AllWorkersHelper.assertWorkerExists(P11NG_CRYPTO_WORKER_NAME);

        // Generate default private key
        CryptoWorkerHelper.generateKey(P11NG_CRYPTO_WORKER_NAME, TEST_KEY, PRIVATE_KEY_ALG, PRIVATE_KEY_SPEC);
        
        // check that worker is ACTIVE
        // Result might be unexpected here if there are already multiple RSA-2048 keys in slot
        AllWorkersHelper.assertWorkerStatus(P11NG_CRYPTO_WORKER_NAME, "ACTIVE");
    }
    
}
