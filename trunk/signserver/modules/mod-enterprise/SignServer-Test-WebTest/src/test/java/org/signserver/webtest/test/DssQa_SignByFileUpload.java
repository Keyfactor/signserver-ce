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
import java.io.FileOutputStream;
import java.io.IOException;
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
import org.signserver.webtest.util.AllWorkersHelper;
import org.signserver.webtest.util.WebTestBase;
import static org.signserver.webtest.util.WebTestBase.getUniqueId;
import static org.signserver.webtest.util.WebTestBase.getWebDriver;
import org.signserver.webtest.util.WebTestHelper;

/**
 * Perform cms, plain, xadES and xml signing by file upload.
 *
 * @author Vinay Singh
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DssQa_SignByFileUpload extends WebTestBase{
    
    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(DssQa_SignByFileUpload.class);
    private static final String CLASS_NAME = DssQa_SignByFileUpload.class.getSimpleName();
    private static final List<String> WORKERS = new ArrayList<>(Arrays.asList(
            "cmssigner", "plainsigner", "xadessigner", "xmlsigner"));    
    private static final HashMap<String, String> WORKER_NAME_BY_WORKER_TEMPL = new HashMap<>();

    private static String cryptoToken;
    private static File doc;
    
    @BeforeClass
    public static void init() throws IOException {
        setUp(CLASS_NAME);
        cryptoToken = WebTestHelper.addCryptoTokenP12();
        
        doc = File.createTempFile("test.xml", null);
        try (FileOutputStream out = new FileOutputStream(doc)) {
            out.write("<tag/>".getBytes());
        }
    }

    @AfterClass
    public static void exit() {       
        WORKERS.add(cryptoToken);
        AllWorkersHelper.removeWorkers(WORKERS);
        getWebDriver().quit();
        doc.delete();
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
            AllWorkersHelper.genericSignByFileUpload(cmsSignerName, doc.getAbsolutePath());
            assertTrue("Signed file does not exist in download directory", AllWorkersHelper.fileExists(doc.getName() + ".p7s"));
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
            AllWorkersHelper.genericSignByFileUpload(plainSignerName, doc.getAbsolutePath());
            assertTrue("signature file does not exist in download directory", AllWorkersHelper.fileExists(doc.getName() + ".sig"));
        } finally {
            WebTestHelper.deleteTestFiles();
        }
    }
    
    /**
     * Performs XML signing.
     */
    @Test
    public void d_XMLSigning() {
        try {
            String xmlsignerName = WORKER_NAME_BY_WORKER_TEMPL.get("xmlsigner");
            AllWorkersHelper.genericSignByFileUpload(xmlsignerName, doc.getAbsolutePath());
            assertTrue("Signed file does not exist in download directory", AllWorkersHelper.fileExists(doc.getName()));
        } finally {
            WebTestHelper.deleteTestFiles();
        }
    }
    
    /**
     * Performs xadES signing.
     */
    @Test
    public void e_xadESSigning() {
        try {
            String xadESSignerName = WORKER_NAME_BY_WORKER_TEMPL.get("xadessigner");
            AllWorkersHelper.genericSignByFileUpload(xadESSignerName, doc.getAbsolutePath());
            assertTrue("Signed file does not exist in download directory", AllWorkersHelper.fileExists(doc.getName()));
        } finally {
            WebTestHelper.deleteTestFiles();
        }
    }
    
}
