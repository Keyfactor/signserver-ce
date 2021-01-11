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

    private static final int WORKER1_ID = 1000;
    private static final String WORKER1_NAME = "SleepWorkerTest";
    private static final int WORKER2_ID = 1001;
    private static final String WORKER2_NAME = "SleepWorkerTest2";

    private static final ModulesTestCase MODULES_TC = new ModulesTestCase();
    private static final CLITestHelper CLIENT_CLI = MODULES_TC.getClientCLI();
    private static final WorkerSessionRemote WORKER_SESSION = MODULES_TC.getWorkerSession();
    private static final GlobalConfigurationSessionRemote GLOBAL_SESSION = MODULES_TC.getGlobalSession();
    private SecurityEventsAuditorSessionRemote auditorSession = null;

    static private final int CONFIG_CACHE_TIMEOUT = 10;

    @Rule
    public final TemporaryFolder inDir = new TemporaryFolder();

    @Rule
    public final TemporaryFolder outDir = new TemporaryFolder();

    @BeforeClass
    public static void setupClass() {
        MODULES_TC.addDummySigner("org.signserver.server.signers.SleepWorker", null,
                WORKER1_ID, WORKER1_NAME, null, null, null);
        WORKER_SESSION.setWorkerProperty(WORKER1_ID, "SLEEP_TIME", "1000");
        WORKER_SESSION.setWorkerProperty(WORKER1_ID, "WORKERLOGGER",
                                        "org.signserver.server.log.SecurityEventsWorkerLogger");
        WORKER_SESSION.reloadConfiguration(WORKER1_ID);
        MODULES_TC.addDummySigner("org.signserver.server.signers.SleepWorker", null,
                WORKER2_ID, WORKER2_NAME, null, null, null);
        WORKER_SESSION.setWorkerProperty(WORKER2_ID, "SLEEP_TIME", "1000");
        WORKER_SESSION.setWorkerProperty(WORKER2_ID, "WORKERLOGGER",
                                        "org.signserver.server.log.SecurityEventsWorkerLogger");
        WORKER_SESSION.reloadConfiguration(WORKER2_ID);
        // set priority mapping, include some unused signers to test that parsing the set works as expected
        GLOBAL_SESSION.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "QOS_PRIORITIES", "1:1,1000:5,1002:2");
        // unset enabled parameter to get default behaviour
        GLOBAL_SESSION.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "QOS_FILTER_ENABLED");
    }

    @Before
    public void setUp() throws Exception {
        Assume.assumeFalse("Test does not run in NODB mode",
                           "nodb".equalsIgnoreCase(MODULES_TC.getDeployConfig().getProperty("database.name")));
    }

    // Test that a single request will not be queued by the QoSFilter.
    @Test
    public void test01SingleRequest() throws Exception {
        GLOBAL_SESSION.setProperty(GlobalConfiguration.SCOPE_GLOBAL,"QOS_FILTER_ENABLED", "true");
        // wait until old cached filter config has expired (with some margin)
        Thread.sleep(CONFIG_CACHE_TIMEOUT * 1000 + 1000);

        try {
            CLIENT_CLI.execute("signdocument", "-servlet",
                              "/signserver/worker/" + WORKER1_NAME,
                              "-data", "foo");
            final List<Map<String, Object>> lastLogFields = queryLastLogFields(1);

            assertEquals("Priority not set by filter", "not set", lastLogFields.get(0).get("QOS_PRIORITY"));
        } finally {
            GLOBAL_SESSION.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                         "QOS_FILTER_ENABLED");
            // wait until old cached filter config has expired (with some margin)
            Thread.sleep(CONFIG_CACHE_TIMEOUT * 1000 + 1000);
        }
    }

    /**
     * Test that sending more more requests to the SleepWorker that the hard-coded max concurrent requests will result
     * in some requests getting queued by the filter (and thus having the worker log field set accordingly).
     */
    @Test
    public void test02SomeRequestsQueuedAndPrioritized() throws Exception {
        createTestFiles(20);
        GLOBAL_SESSION.setProperty(GlobalConfiguration.SCOPE_GLOBAL,"QOS_FILTER_ENABLED", "true");
        // wait until old cached filter config has expired (with some margin)
        Thread.sleep(CONFIG_CACHE_TIMEOUT * 1000 + 1000);

        try {
            CLIENT_CLI.execute("signdocument", "-servlet",
                              "/signserver/worker/" + WORKER1_NAME,
                              "-threads", "20",
                              "-indir", inDir.getRoot().getAbsolutePath(),
                              "-outdir", outDir.getRoot().getAbsolutePath());
            final List<Map<String, Object>> lastLogFields = queryLastLogFields(20);
            int queuedRequests = 0;

            for (final Map<String, Object> details : lastLogFields) {
                final String prio = (String) details.get("QOS_PRIORITY");

                if ("5".equals(prio)) {
                    queuedRequests++;
                }
            }

            assertTrue("Some requests should have been queued at prio 5", queuedRequests > 0);
        } finally {
            GLOBAL_SESSION.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,"QOS_FILTER_ENABLED");
            // wait until old cached filter config has expired (with some margin)
            Thread.sleep(CONFIG_CACHE_TIMEOUT * 1000 + 1000);
        }
    }

    /**
     * Test that sending more more requests to the SleepWorker that the hard-coded max concurrent requests will result
     * in some requests getting queued by the filter (and thus having the worker log field set accordingly). Using a
     * signer with explicit priority mapping, should get default (0) priority.
     */
    @Test
    public void test03SomeRequestsQueuedAndPrioritizedDefaultPriority() throws Exception {
        createTestFiles(20);
        GLOBAL_SESSION.setProperty(GlobalConfiguration.SCOPE_GLOBAL,"QOS_FILTER_ENABLED", "true");
        // wait until old cached filter config has expired (with some margin)
        Thread.sleep(CONFIG_CACHE_TIMEOUT * 1000 + 1000);

        try {
            CLIENT_CLI.execute("signdocument", "-servlet",
                              "/signserver/worker/" + WORKER2_NAME,
                              "-threads", "20",
                              "-indir", inDir.getRoot().getAbsolutePath(),
                              "-outdir", outDir.getRoot().getAbsolutePath());
            final List<Map<String, Object>> lastLogFields = queryLastLogFields(20);
            int queuedRequests = 0;

            for (final Map<String, Object> details : lastLogFields) {
                final String prio = (String) details.get("QOS_PRIORITY");

                if ("0".equals(prio)) {
                    queuedRequests++;
                }
            }

            assertTrue("Some requests should have been queued at prio 0", queuedRequests > 0);
        } finally {
            GLOBAL_SESSION.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "QOS_FILTER_ENABLED");
            // wait until old cached filter config has expired (with some margin)
            Thread.sleep(CONFIG_CACHE_TIMEOUT * 1000 + 1000);
        }
    }

    /**
     * Test that setting max accepted requests to a higher value than
     * the number of concurrent threads run will not result in queueing requests.
     */
    @Test
    public void test04HigherMaxRequests() throws Exception {
        try {
            GLOBAL_SESSION.setProperty(GlobalConfiguration.SCOPE_GLOBAL,"QOS_MAX_REQUESTS", "50");
            GLOBAL_SESSION.setProperty(GlobalConfiguration.SCOPE_GLOBAL,"QOS_FILTER_ENABLED", "true");
            // wait until old cached filter config has expired (with some margin)
            Thread.sleep(CONFIG_CACHE_TIMEOUT * 1000 + 1000);

            createTestFiles(20);
            CLIENT_CLI.execute("signdocument", "-servlet",
                              "/signserver/worker/" + WORKER1_NAME,
                              "-threads", "20",
                              "-indir", inDir.getRoot().getAbsolutePath(),
                              "-outdir", outDir.getRoot().getAbsolutePath());
            final List<Map<String, Object>> lastLogFields = queryLastLogFields(20);
            int nonQueuedRequests = 0;

            for (final Map<String, Object> details : lastLogFields) {
                final String prio = (String) details.get("QOS_PRIORITY");

                if ("not set".equals(prio)) {
                    nonQueuedRequests++;
                }
            }

            assertEquals("No requests should be queued", 20, nonQueuedRequests);
        } finally {
            GLOBAL_SESSION.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,"QOS_MAX_REQUESTS");
            GLOBAL_SESSION.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,"QOS_FILTER_ENABLED");
            // wait until old cached filter config has expired (with some margin)
            Thread.sleep(CONFIG_CACHE_TIMEOUT * 1000 + 1000);
        }
    }

    // Test that setting a higher max priority level correctly works with a worker configured to that level.
    @Test
    public void test05HigherMaxPriorityLevel() throws Exception {
        try {
            GLOBAL_SESSION.setProperty(GlobalConfiguration.SCOPE_GLOBAL,"QOS_MAX_PRIORITY", "50");
            GLOBAL_SESSION.setProperty(GlobalConfiguration.SCOPE_GLOBAL,"QOS_PRIORITIES", "1:1,1000:50,1002:2");
            GLOBAL_SESSION.setProperty(GlobalConfiguration.SCOPE_GLOBAL,"QOS_FILTER_ENABLED", "true");

            // wait until old cached filter config has expired (with some margin)
            Thread.sleep(CONFIG_CACHE_TIMEOUT * 1000 + 1000);

            createTestFiles(20);
            CLIENT_CLI.execute("signdocument", "-servlet",
                              "/signserver/worker/" + WORKER1_NAME,
                              "-threads", "20",
                              "-indir", inDir.getRoot().getAbsolutePath(),
                              "-outdir", outDir.getRoot().getAbsolutePath());
            final List<Map<String, Object>> lastLogFields = queryLastLogFields(20);
            int queuedRequests = 0;

            for (final Map<String, Object> details : lastLogFields) {
                final String prio = (String) details.get("QOS_PRIORITY");

                if ("50".equals(prio)) {
                    queuedRequests++;
                }
            }

            assertTrue("Some requests were queued at priority 50", queuedRequests > 0);
        } finally {
            GLOBAL_SESSION.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,"QOS_MAX_PRIORITY");
            // reset priority level mapping
            GLOBAL_SESSION.setProperty(GlobalConfiguration.SCOPE_GLOBAL,"QOS_PRIORITIES", "1:1,1000:5,1002:2");
            GLOBAL_SESSION.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,"QOS_FILTER_ENABLED");
            // wait until old cached filter config has expired (with some margin)
            Thread.sleep(CONFIG_CACHE_TIMEOUT * 1000 + 1000);
        }
    }

    // Test that when not setting GLOB.QOS_FILTER_ENABLED it default to inactive, not prioritizing any requests.
    @Test
    public void test06NoRequestsPrioritizedDefault() throws Exception {
        createTestFiles(20);
        CLIENT_CLI.execute("signdocument", "-servlet",
                          "/signserver/worker/" + WORKER1_NAME,
                          "-threads", "20",
                          "-indir", inDir.getRoot().getAbsolutePath(),
                          "-outdir", outDir.getRoot().getAbsolutePath());
        final List<Map<String, Object>> lastLogFields = queryLastLogFields(20);
        int noPrioritySet = 0;

        for (final Map<String, Object> details : lastLogFields) {
            final String prio = (String) details.get("QOS_PRIORITY");

            if ("not set".equals(prio)) {
                noPrioritySet++;
            }
        }

        assertEquals("No requests prioritized", 20, noPrioritySet);
    }

    // Test that setting GLOB.QOS_FILTER_ENABLED to explicitly false results in inactive, not prioritizing any requests.
    @Test
    public void test07NoRequestsPrioritizedExplicitFalse() throws Exception {
        createTestFiles(20);
        GLOBAL_SESSION.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "QOS_FILTER_ENABLED", "false");
        // wait until old cached filter config has expired (with some margin)
        Thread.sleep(CONFIG_CACHE_TIMEOUT * 1000 + 1000);

        try {
            CLIENT_CLI.execute("signdocument", "-servlet",
                              "/signserver/worker/" + WORKER1_NAME,
                              "-threads", "20",
                              "-indir", inDir.getRoot().getAbsolutePath(),
                              "-outdir", outDir.getRoot().getAbsolutePath());
            final List<Map<String, Object>> lastLogFields = queryLastLogFields(20);
            int noPrioritySet = 0;

            for (final Map<String, Object> details : lastLogFields) {
                final String prio = (String) details.get("QOS_PRIORITY");

                if ("not set".equals(prio)) {
                    noPrioritySet++;
                }
            }

            assertEquals("No requests prioritized", 20, noPrioritySet);
        } finally {
            GLOBAL_SESSION.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,"QOS_FILTER_ENABLED");
            // wait until old cached filter config has expired (with some margin)
            Thread.sleep(CONFIG_CACHE_TIMEOUT * 1000 + 1000);
        }
    }

    // Test that setting GLOB.QOS_FILTER_ENABLED to an invalid value results in inactive, not prioritizing any requests.
    @Test
    public void test08NoRequestsPrioritizedInvalidEnabled() throws Exception {
        createTestFiles(20);
        GLOBAL_SESSION.setProperty(GlobalConfiguration.SCOPE_GLOBAL,"QOS_FILTER_ENABLED", "_invalid_");
        // wait until old cached filter config has expired (with some margin)
        Thread.sleep(CONFIG_CACHE_TIMEOUT * 1000 + 1000);

        try {
            CLIENT_CLI.execute("signdocument", "-servlet",
                              "/signserver/worker/" + WORKER1_NAME,
                              "-threads", "20",
                              "-indir", inDir.getRoot().getAbsolutePath(),
                              "-outdir", outDir.getRoot().getAbsolutePath());
            final List<Map<String, Object>> lastLogFields = queryLastLogFields(20);
            int noPrioritySet = 0;

            for (final Map<String, Object> details : lastLogFields) {
                final String prio = (String) details.get("QOS_PRIORITY");

                if ("not set".equals(prio)) {
                    noPrioritySet++;
                }
            }

            assertEquals("No requests prioritized", 20, noPrioritySet);
        } finally {
            GLOBAL_SESSION.removeProperty(GlobalConfiguration.SCOPE_GLOBAL,"QOS_FILTER_ENABLED");
            // wait until old cached filter config has expired (with some margin)
            Thread.sleep(CONFIG_CACHE_TIMEOUT * 1000 + 1000);
        }
    }

    @AfterClass
    public static void tearDownClass() {
        MODULES_TC.removeWorker(WORKER1_ID);
        MODULES_TC.removeWorker(WORKER2_ID);
    }

    private void createTestFiles(final int numFiles) throws IOException {
        for (int i = 0; i < numFiles; i++) {
            final File file = inDir.newFile("file-" + i);
            FileUtils.writeStringToFile(file, "hello", StandardCharsets.UTF_8,false);
        }
    }

    /**
     * Query the last log field of events of type PROCESS.
     *
     * @param numRows number of last rows to include, will cause failure if this number of rows are not found
     * @return additional details map
     */
    private List<Map<String, Object>> queryLastLogFields(final int numRows) throws Exception {
        final List<Map<String, Object>> result = new LinkedList<>();
        Term t = QueryUtil.parseCriteria("eventType EQ PROCESS", AuditLogFields.ALLOWED_FIELDS, AuditLogFields.NO_ARG_OPS, Collections.emptySet(), AuditLogFields.LONG_FIELDS, AuditLogFields.DATE_FIELDS);
        QueryCriteria qc = QueryCriteria.create().add(t).add(Criteria.orderDesc(AuditRecordData.FIELD_TIMESTAMP));

        Set<String> devices = getAuditorSession().getQuerySupportingLogDevices();
        if (devices.isEmpty()) {
            throw new Exception("No log devices available for querying");
        }
        final String device = devices.iterator().next();

        List<? extends AuditLogEntry> logs =
                WORKER_SESSION.selectAuditLogs(0, numRows, qc, device);
        assertEquals("new log rows", numRows, logs.size());

        logs.forEach(row -> result.add(row.getMapAdditionalDetails()));

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
