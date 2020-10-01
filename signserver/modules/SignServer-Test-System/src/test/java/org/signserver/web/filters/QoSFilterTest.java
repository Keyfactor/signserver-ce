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

import java.rmi.RemoteException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.naming.NamingException;
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
import org.junit.Test;
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
public class QoSFilterTest extends ModulesTestCase {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(QoSFilterTest.class);

    private static final int WORKERID1 = 1000;
    private static final String WORKERNAME1 = "SleepWorkerTest";
    
    private final CLITestHelper clientCLI = getClientCLI();
    private final WorkerSessionRemote workerSession = getWorkerSession();
    private final GlobalConfigurationSessionRemote globalSession = getGlobalSession();
    private SecurityEventsAuditorSessionRemote auditorSession = null;
    
    @BeforeClass
    public void test01Setup() throws Exception {
        addDummySigner("org.signserver.server.signers.SleepWorker", null,
                       WORKERID1, WORKERNAME1, null, null, null);
        workerSession.setWorkerProperty(WORKERID1, "SLEEP_TIME", "1000");
        workerSession.setWorkerProperty(WORKERID1, "WORKERLOGGER",
                                        "org.signserver.server.log.SecurityEventsWorkerLogger");
        workerSession.reloadConfiguration(WORKERID1);
        // set priority mapping
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                  "QOS_PRIORITIES",
                                  WORKERID1 + ":5");
    }

    @Before
    public void setUp() throws Exception {
        Assume.assumeFalse("Test does not run in NODB mode",
                           "nodb".equalsIgnoreCase(getDeployConfig().getProperty("database.name")));
        
    }

    /**
     * Test that a single request will not be queued by the QoSFilter.
     *
     * @throws Exception 
     */
    @Test
    public void test02SingleRequest() throws Exception {
        clientCLI.execute("signdocument", "-servlet",
                          "/signserver/worker/" + WORKERNAME1,
                          "-data", "foo");
        final List<Map<String, Object>> lastLogFields = queryLastLogFields(1);

        assertEquals("Priority not set by filter", "not set",
                     lastLogFields.get(0).get("QOS_PRIORITY"));
    }

    @AfterClass
    public void test99TearDown() throws Exception {
        removeWorker(WORKERID1);
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
