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
package org.signserver.server.log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.apache.log4j.Logger;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.WorkerConfig;
import org.signserver.testutils.ModulesTestCase;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.SignServerUtil;
import org.signserver.ejb.interfaces.WorkerSession;


/**
 * Tests for the System Logger. This class contains tests separated from SystemLoggingTest that are intended to run only on Linux,
 * as these tests fail on Windows.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SystemLoggingLinuxTest extends ModulesTestCase {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(SystemLoggingLinuxTest.class);

    private static final int WORKERID_STATUS_REPORT = 5803;

    private File logFile;
    private File sodStatusReport;

    private final WorkerSession workerSession = getWorkerSession();

    @Before
    public void setUp() throws Exception {
        logFile = new File(getSignServerHome(), "signserver.log");

        sodStatusReport = File.createTempFile("sodstatusreport", "");
        sodStatusReport.deleteOnExit();
        sodStatusReport.setWritable(false, false);

        if (!logFile.exists()) {
            final String error = "Test case requires signserver log file in " + logFile.getAbsolutePath() + " (or that being a symlink to the signserver log file)";
            LOG.error(error);
            throw new Exception(error);
        }

        SignServerUtil.installBCProviderIfNotAvailable();
    }

    /**
     * Tests running SignerStatusReportTimedService with interval 20 and searching log which
     * should contain "sodstatusreport (Permission denied)"
     * and should not contain "Error during retrying timeout for timer".
     */
    @Test
    public void test01RunSignerStatusReportTimedService() throws Exception {
        LOG.info(">test01RunSignerStatusReportTimedService");
        try {
            final int workerId = WORKERID_STATUS_REPORT;
            workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, "TIMED_SERVICE");
            workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.signerstatusreport.SignerStatusReportTimedService");
            workerSession.setWorkerProperty(workerId, "INTERVAL", "20");
            workerSession.setWorkerProperty(workerId, "ACTIVE", "TRUE");
            workerSession.setWorkerProperty(workerId, "OUTPUTFILE", sodStatusReport.getAbsolutePath());
            workerSession.reloadConfiguration(workerId);

            // Wait for the service to run and log the error
            Thread.sleep(60000);
            final String searchTextSodStatusReport = "sodstatusreport";
            final String searchTextPermissionDenied = "(Permission denied)";
            boolean foundSodStatusReport = logContains(logFile, searchTextSodStatusReport, searchTextPermissionDenied);
            assertTrue("Log should contain sodstatusreport (Permission denied)", foundSodStatusReport);

            final String searchTextError = "Error during retrying timeout for timer";
            boolean foundError = logContains(logFile, searchTextError, null);
            assertFalse("Log should not contain error text: " + searchTextError, foundError);
        } finally {
            removeWorker(WORKERID_STATUS_REPORT);
        }
    }

    private boolean logContains(final File file, final String searchFirstString, final String searchSecondString) throws Exception {
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                LOG.info(line);
                if (line.contains(searchFirstString)) {
                    if (searchSecondString == null) {
                        return true;

                    } else if (line.contains(searchSecondString)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
