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
import java.util.Arrays;
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
import org.signserver.webtest.util.WorkerHelper;

/**
 * DSSQA-60 PDF signing.
 *
 * @author Vinay Singh
 * @version $Id$
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DssQa60_PdfSigning extends WebTestBase {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(DssQa60_PdfSigning.class);
    private static final String CLASS_NAME = DssQa60_PdfSigning.class.getSimpleName();    
    private static final String WORKER = "pdfsigner";
    private final String workerName = WORKER + "_" + getUniqueId();
    String samplePdf = getSignServerDir() + "/res/test/pdf/sample.pdf";

    private static String cryptoToken;

    @BeforeClass
    public static void init() {
        setUp(CLASS_NAME);
        cryptoToken = WebTestHelper.addCryptoTokenP12();
    }

    @AfterClass
    public static void exit() {
        WebTestHelper.deleteTestFiles();
        AllWorkersHelper.removeWorkers(Arrays.asList(WORKER, cryptoToken));
        getWebDriver().quit();
    }

    /**
     * Adds PDF signer, checks that worker is ACTIVE and worker id matches on
     * "All workers" and "worker" screen.
     */
    @Test
    public void a_addPDFSigner() {
        AllWorkersHelper.addFromTemplate(WORKER + ".properties", ImmutableMap.of(
                "WORKERGENID1.NAME", workerName,
                "WORKERGENID1.CRYPTOTOKEN", cryptoToken
        ));
        AllWorkersHelper.assertWorkerExists(workerName);
        AllWorkersHelper.assertWorkerStatus(workerName, "ACTIVE");
        
        // check whether generated worker id on all workers page and worker status summary page matches
        String workerId = AllWorkersHelper.extractGeneratedWorkerId(workerName);
        AllWorkersHelper.openWorker(workerName);
        LOG.info("workername " + workerName);
        LOG.info("workerid " + workerId);
        String statusSummaryLine = "Status of Signer with ID " + workerId + " (" + workerName + ")";
        WorkerHelper.assertStatusSummaryContains(statusSummaryLine);
    }
    
    /**
     * Performs PDF signing.
     */
    @Test
    public void b_performPDFSigning() {        
        AllWorkersHelper.genericSignByFileUpload(workerName, samplePdf);
    }

    /**
     * Checks that signing was successful and signed file existed in download
     * directory.
     */
    @Test
    public void c_checkSignedFileExists() {
        // name of signed file would be same in this case and it should exist in download directory
        String samplePdfFileName = new File(samplePdf).getName();
        assertTrue("Signed pdf file does not exist in download directory. Please check "
                + "if setting in firefox to save the pdf file (instead of opening preview) is activated", AllWorkersHelper.fileExists(samplePdfFileName));
    }

}
