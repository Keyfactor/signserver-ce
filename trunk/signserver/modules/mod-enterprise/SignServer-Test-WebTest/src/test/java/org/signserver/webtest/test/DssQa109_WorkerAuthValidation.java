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
import org.apache.log4j.Logger;
import org.junit.AfterClass;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.signserver.webtest.util.AllWorkersHelper;
import org.signserver.webtest.util.WebTestBase;
import static org.signserver.webtest.util.WebTestBase.getUniqueId;
import static org.signserver.webtest.util.WebTestBase.getWebDriver;
import org.signserver.webtest.util.WebTestHelper;

/**
 * DSSQA-109 Shows the error message when authorization is denied.
 *
 * @author Vinay Singh
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DssQa109_WorkerAuthValidation extends WebTestBase{
    
    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(DssQa109_WorkerAuthValidation.class);
    private static final String CLASS_NAME = DssQa109_WorkerAuthValidation.class.getSimpleName();    
    private static final String WORKER = "xmlsigner";
    private final String workerName = WORKER + "_" + getUniqueId();    

    private static String cryptoToken;

    @BeforeClass
    public static void init() {
        setUp(CLASS_NAME);
        cryptoToken = WebTestHelper.addCryptoTokenP12();
    }

    @AfterClass
    public static void exit() {       
        AllWorkersHelper.removeWorkers(Arrays.asList(WORKER, cryptoToken));
        getWebDriver().quit();
    }

    /**
     * Adds XMLSigner.
     */
    @Test
    public void a_addXMLSigner() {
        AllWorkersHelper.addFromTemplate(WORKER + ".properties", ImmutableMap.of(
                "WORKERGENID1.NAME", workerName,
                "WORKERGENID1.CRYPTOTOKEN", cryptoToken,
                "WORKERGENID1.AUTHTYPE", "CLIENTCERT"
        ));
        AllWorkersHelper.assertWorkerExists(workerName);
        AllWorkersHelper.assertWorkerStatus(workerName, "ACTIVE");
    }
    
    /**
     * Performs XML signing.
     */
    @Test
    public void b_XMLSigning() {
        AllWorkersHelper.genericSignByDirectInput(workerName, "<xml/>");
    }
    
    /**
     * Checks that signing should fail complaining that client is not
     * authorized.
     */
    @Test
    public void c_validatedAuthError() {
        assertTrue("signing should fail", WebTestHelper.elementExists(By.xpath("//div/h1[contains(text(), 'Error 400')]")));
        WebElement error = webDriver.findElement(By.xpath("//div/h1[contains(text(), 'Error 400')]/following-sibling::p"));
        LOG.info("error message " + error.getText());
        assertTrue("authorization error should be displayed", error.getText().contains("Client is not authorized:"));
    }
}
