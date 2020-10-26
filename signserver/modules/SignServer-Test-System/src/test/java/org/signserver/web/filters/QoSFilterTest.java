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
package org.signserver.web.filters;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.naming.NamingException;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionRemote;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.elems.Term;
import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.signserver.admin.common.query.AuditLogFields;
import org.signserver.admin.common.query.QueryUtil;
import org.signserver.common.CESeCoreModules;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ServiceLocator;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionRemote;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;

/**
 * System tests for the QoSFilter.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class QoSFilterTest {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(QoSFilterTest.class);

    private static final int WORKERID1 = 1000;
    private static final String WORKERNAME1 = "SleepWorkerTest";
    private static final int WORKERID2 = 1001;
    private static final String WORKERNAME2 = "SleepWorkerTest2";

    private static ModulesTestCase modulesTestCase = new ModulesTestCase();
    private static final CLITestHelper clientCLI = modulesTestCase.getClientCLI();
    private static final WorkerSessionRemote workerSession =
            modulesTestCase.getWorkerSession();
    private static final GlobalConfigurationSessionRemote globalSession =
            modulesTestCase.getGlobalSession();
    private SecurityEventsAuditorSessionRemote auditorSession = null;

    @Rule
    public final TemporaryFolder inDir = new TemporaryFolder();
    
    @Rule
    public final TemporaryFolder outDir = new TemporaryFolder();

    @BeforeClass
    public static void setupClass() throws Exception {
        modulesTestCase.addDummySigner("org.signserver.server.signers.SleepWorker", null,
                       WORKERID1, WORKERNAME1, null, null, null);
        workerSession.setWorkerProperty(WORKERID1, "SLEEP_TIME", "1000");
        workerSession.setWorkerProperty(WORKERID1, "WORKERLOGGER",
                                        "org.signserver.server.log.SecurityEventsWorkerLogger");
        workerSession.reloadConfiguration(WORKERID1);
        modulesTestCase.addDummySigner("org.signserver.server.signers.SleepWorker", null,
                       WORKERID2, WORKERNAME2, null, null, null);
        workerSession.setWorkerProperty(WORKERID2, "SLEEP_TIME", "1000");
        workerSession.setWorkerProperty(WORKERID2, "WORKERLOGGER",
                                        "org.signserver.server.log.SecurityEventsWorkerLogger");
        workerSession.reloadConfiguration(WORKERID2);
        // set priority mapping, include some unused signers to test that parsing
        // the set works as expected
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                  "QOS_PRIORITIES", "1:1,1000:5,1002:2");
    }

    @Before
    public void setUp() throws Exception {
        Assume.assumeFalse("Test does not run in NODB mode",
                           "nodb".equalsIgnoreCase(modulesTestCase.getDeployConfig().getProperty("database.name")));
        
    }

    /**
     * Test that a single request will not be queued by the QoSFilter.
     *
     * @throws Exception 
     */
    @Test
    public void test01SingleRequest() throws Exception {
        clientCLI.execute("signdocument", "-servlet",
                          "/signserver/worker/" + WORKERNAME1,
                          "-data", "foo");
        final List<Map<String, Object>> lastLogFields = queryLastLogFields(1);

        assertEquals("Priority not set by filter", "not set",
                     lastLogFields.get(0).get("QOS_PRIORITY"));
    }

    /**
     * Test that sending more more requests to the SleepWorker that the
     * hard-coded max concurrent requests will result in some requests getting
     * queued by the filter (and thus having the worker log field set
     * accordingly).
     *
     * @throws Exception 
     */
    @Test
    public void test02SomeRequestsQueuedAndPrioritized() throws Exception {
        createTestFiles(20);
        clientCLI.execute("signdocument", "-servlet",
                          "/signserver/worker/" + WORKERNAME1,
                          "-threads", "20",
                          "-indir", inDir.getRoot().getAbsolutePath(),
                          "-outdir", outDir.getRoot().getAbsolutePath());
        final List<Map<String, Object>> lastLogFields =
                queryLastLogFields(20);
        int queuedRequests = 0;

        for (final Map<String, Object> details : lastLogFields) {
            final String prio = (String) details.get("QOS_PRIORITY");

            if ("5".equals(prio)) {
                queuedRequests++;
            }
        }

        assertTrue("Some requests should have been queued at prio 5",
                   queuedRequests > 0);
    }

    /**
     * Test that sending more more requests to the SleepWorker that the
     * hard-coded max concurrent requests will result in some requests getting
     * queued by the filter (and thus having the worker log field set
     * accordingly). Using a signer with explicit priority mapping, should
     * get default (0) prio.
     *
     * @throws Exception 
     */
    @Test
    public void test03SomeRequestsQueuedAndPrioritizedDefaultPrio() throws Exception {
        createTestFiles(20);
        clientCLI.execute("signdocument", "-servlet",
                          "/signserver/worker/" + WORKERNAME2,
                          "-threads", "20",
                          "-indir", inDir.getRoot().getAbsolutePath(),
                          "-outdir", outDir.getRoot().getAbsolutePath());
        final List<Map<String, Object>> lastLogFields =
                queryLastLogFields(20);
        int queuedRequests = 0;

        for (final Map<String, Object> details : lastLogFields) {
            final String prio = (String) details.get("QOS_PRIORITY");

            if ("0".equals(prio)) {
                queuedRequests++;
            }
        }

        assertTrue("Some requests should have been queued at prio 0",
                   queuedRequests > 0);
    }

    /**
     * Test that setting max accepted requests to a higher value than
     * the number of concurrent threads run will not result in queueing requests.
     *
     * @throws Exception 
     */
    @Test
    public void test04HigherMaxRequests() throws Exception {
        try {
            globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                      "QOS_MAX_REQUESTS", "50");
            createTestFiles(20);
            clientCLI.execute("signdocument", "-servlet",
                              "/signserver/worker/" + WORKERNAME1,
                              "-threads", "20",
                              "-indir", inDir.getRoot().getAbsolutePath(),
                              "-outdir", outDir.getRoot().getAbsolutePath());
            final List<Map<String, Object>> lastLogFields =
                    queryLastLogFields(20);
            int nonQueuedRequests = 0;

            for (final Map<String, Object> details : lastLogFields) {
                final String prio = (String) details.get("QOS_PRIORITY");

                if ("not set".equals(prio)) {
                    nonQueuedRequests++;
                }
            }

            assertEquals("No requests should be queued", 20, nonQueuedRequests);
        } finally {
            globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                         "QOS_MAX_REQUESTS");
        }
    }

    /**
     * Test that setting a higher max priority level correctly works with
     * a worker configured to that level.
     *
     * @throws Exception 
     */
    @Test
    public void test05HigherMaxPriorityLevel() throws Exception {
        try {
            globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                      "QOS_MAX_PRIORITY", "50");
            globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                  "QOS_PRIORITIES", "1:1,1000:50,1002:2");
            createTestFiles(20);
            clientCLI.execute("signdocument", "-servlet",
                              "/signserver/worker/" + WORKERNAME1,
                              "-threads", "20",
                              "-indir", inDir.getRoot().getAbsolutePath(),
                              "-outdir", outDir.getRoot().getAbsolutePath());
            final List<Map<String, Object>> lastLogFields =
                    queryLastLogFields(20);
            int queuedRequests = 0;

            for (final Map<String, Object> details : lastLogFields) {
                final String prio = (String) details.get("QOS_PRIORITY");

                if ("50".equals(prio)) {
                    queuedRequests++;
                }
            }

            assertTrue("Some requests were queued at priority 50",
                       queuedRequests > 0);
        } finally {
            globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                         "QOS_MAX_PRIORITY");
            // reset priority level mapping
            globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                  "QOS_PRIORITIES", "1:1,1000:5,1002:2");
        }
    }
    
    @AfterClass
    public static void tearDownClass() throws Exception {
        modulesTestCase.removeWorker(WORKERID1);
        modulesTestCase.removeWorker(WORKERID2);
    }

    private void createTestFiles(final int numFiles) throws IOException {
        for (int i = 0; i < numFiles; i++) {
            final File file = inDir.newFile("file-" + i);
            FileUtils.writeStringToFile(file, "hello", StandardCharsets.UTF_8,
                                        false);
        }
    }
    
    /**
     * Query the last log field of events of type PROCESS.
     *
     * @param numRows number of last rows to include, will cause failure if
     *                this number of rows are not found
     * @return additional details map
     * @throws Exception 
     */
    private List<Map<String, Object>> queryLastLogFields(final int numRows)
            throws Exception {
        final List<Map<String, Object>> result = new LinkedList<>();
        Term t = QueryUtil.parseCriteria("eventType EQ PROCESS", AuditLogFields.ALLOWED_FIELDS, AuditLogFields.NO_ARG_OPS, Collections.<String>emptySet(), AuditLogFields.LONG_FIELDS, AuditLogFields.DATE_FIELDS);
        QueryCriteria qc = QueryCriteria.create().add(t).add(Criteria.orderDesc(AuditRecordData.FIELD_TIMESTAMP));

        Set<String> devices = getAuditorSession().getQuerySupportingLogDevices();
        if (devices.isEmpty()) {
            throw new Exception("No log devices available for querying");
        }
        final String device = devices.iterator().next();

        List<? extends AuditLogEntry> logs =
                workerSession.selectAuditLogs(0, numRows, qc, device);
        assertEquals("new log rows", numRows, logs.size());
        
        logs.forEach(row -> {
            result.add(row.getMapAdditionalDetails());
        });

        return result;
    }

    private SecurityEventsAuditorSessionRemote getAuditorSession() throws RemoteException {
        if (auditorSession == null) {
            try {
                auditorSession = ServiceLocator.getInstance().lookupRemote(
                        SecurityEventsAuditorSessionRemote.class, CESeCoreModules.CORE);
            } catch (NamingException e) {
                LOG.error("Error instantiating the SecurityEventsAuditorSession.", e);
                throw new RemoteException("Error instantiating the SecurityEventsAuditorSession", e);
            }
        }
        return auditorSession;
    }
}
