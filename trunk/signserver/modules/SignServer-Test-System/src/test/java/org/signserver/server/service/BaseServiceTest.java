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
package org.signserver.server.service;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Date;
import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.common.ServiceConfig;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerUtil;
import org.signserver.common.StaticWorkerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.ejb.interfaces.WorkerSessionRemote;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * TODO: Document me!
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class BaseServiceTest extends ModulesTestCase {
    private static final Logger LOG = Logger.getLogger(BaseServiceTest.class);

    private static WorkerSessionRemote sSSession = null;
    private static String tmpFile;
    private static final int INTERVAL = 8;
    private static final int INTERVALMS = INTERVAL * 1000;
    private static final int WORKER_ID = 17;

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        sSSession = ServiceLocator.getInstance().lookupRemote(WorkerSessionRemote.class);
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        sSSession.setWorkerProperty(WORKER_ID, WorkerConfig.TYPE, WorkerType.TIMED_SERVICE.name());
        sSSession.setWorkerProperty(WORKER_ID, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.timedservices.DummyTimedService");

        sSSession.setWorkerProperty(WORKER_ID, ServiceConfig.ACTIVE, "TRUE");
        sSSession.setWorkerProperty(WORKER_ID, ServiceConfig.INTERVAL,
                String.valueOf(INTERVAL));
        final String signserverhome = PathUtil.getAppHome().getAbsolutePath();
        tmpFile = signserverhome + "/tmp/testservicefile.tmp";
        sSSession.setWorkerProperty(WORKER_ID, "OUTPATH", tmpFile);

        resetCount();

        sSSession.reloadConfiguration(WORKER_ID);
    }

    /**
     * Test the counter is updated. The test checks the elapsed real time
     * to avoid random failures due to i.e. GC runs.
     */
    @Test
    public void test01BasicService() throws Exception {

        final long before = System.currentTimeMillis();
        Thread.sleep((3 * INTERVAL + 1) * 1000);
        final long after = System.currentTimeMillis();
        final int readCount = readCount();
        assertTrue("readCount: " + readCount, readCount >= 2);
        // check count based on elapsed time, plus some margin
        assertTrue(readCount <= (after - before) / INTERVALMS + 2);
    }

    /*
     * Test getting last run timestamp. Also check that the configured interval is correct.
     */
    @Test
    public void test02GetStatus() throws Exception {
        StaticWorkerStatus status = (StaticWorkerStatus) sSSession.getStatus(new WorkerIdentifier(WORKER_ID));
        Date lastRun = new ServiceConfig(status.getActiveSignerConfig()).getLastRunTimestamp();
        assertTrue(lastRun.before(new Date()));
        assertTrue(lastRun.after(new Date(System.currentTimeMillis() - INTERVALMS * 2)));
        assertEquals(status.getActiveSignerConfig().getProperties().get("INTERVAL"), String.valueOf(INTERVAL));
    }

    /**
     * Tests that the counter is not updated when setting ACTIVE=FALSE.
     */
    @Test
    public void test03TestInActive() throws Exception {
        sSSession.setWorkerProperty(WORKER_ID, ServiceConfig.ACTIVE, "FALSE");
        sSSession.reloadConfiguration(WORKER_ID);

        final int readCount = readCount();
        Thread.sleep(2 * INTERVAL);
        assertEquals(readCount, readCount());
    }

    /**
     * Only test that singleton mode works as nonsingleton service in one node services.
     */
    @Test
    public void test04TestOneNodeSingleton() throws Exception {
        final int oldReadCount = readCount();
        sSSession.setWorkerProperty(WORKER_ID, ServiceConfig.ACTIVE, "TRUE");
        sSSession.setWorkerProperty(WORKER_ID, ServiceConfig.SINGLETON, "TRUE");
        sSSession.reloadConfiguration(WORKER_ID);

        Thread.sleep(3 * INTERVAL);
        final int readCount = readCount();

        assertTrue(readCount >= oldReadCount);
        assertTrue(readCount <= oldReadCount + 1);
    }

    /**
     * Test the CRON-like interval syntax for setting update intervals.
     */
    @Test
    public void test05TestCronExpression() throws Exception {
        sSSession.removeWorkerProperty(WORKER_ID, ServiceConfig.SINGLETON);
        sSSession.removeWorkerProperty(WORKER_ID, ServiceConfig.INTERVAL);

        sSSession.setWorkerProperty(WORKER_ID, ServiceConfig.CRON, "* * * ? * *");

        sSSession.reloadConfiguration(WORKER_ID);
        final int oldReadCount = readCount();

        final long before = System.currentTimeMillis();
        Thread.sleep(4 * INTERVAL);
        final long after = System.currentTimeMillis();
        final int readCount = readCount();
        LOG.info("oldReadCount: " + oldReadCount);
        LOG.info("readCount: " + readCount);
        assertTrue(readCount >= oldReadCount);
        assertTrue(readCount <= oldReadCount + (after - before) / 1000 + 1);
    }

    /**
     * Test setting an update interval based on a millisecond value.
     */
    @Test
    public void test06intervalMs() throws Exception {
        sSSession.removeWorkerProperty(WORKER_ID, ServiceConfig.SINGLETON);
        sSSession.removeWorkerProperty(WORKER_ID, ServiceConfig.INTERVAL);
        sSSession.removeWorkerProperty(WORKER_ID, ServiceConfig.CRON);
        sSSession.setWorkerProperty(WORKER_ID, ServiceConfig.INTERVALMS,
                String.valueOf(INTERVALMS));
        sSSession.reloadConfiguration(WORKER_ID);

        final int oldReadCount = readCount();

        final long before = System.currentTimeMillis();
        Thread.sleep(3 * INTERVALMS + 1000);
        final long after = System.currentTimeMillis();
        final int readCount = readCount();
        LOG.info("oldReadCount: " + oldReadCount);
        LOG.info("readCount: " + readCount);
        assertTrue("readCount: " + readCount,
                readCount >= oldReadCount + (after - before) / INTERVALMS - 1);
        assertTrue(readCount <= oldReadCount + (after - before) / INTERVALMS + 1);
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(WORKER_ID);
    }

    private int readCount() throws IOException {
        FileInputStream fis = new FileInputStream(tmpFile);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int next;
        try {
            while ((next = fis.read()) != -1) {
                baos.write(next);
            }
        } finally {
            try {
                fis.close();
            } catch (IOException e) {
                // ignored
            }
        }
        return Integer.parseInt(new String(baos.toByteArray()));
    }

    private void resetCount() {
        File file = new File(tmpFile);
        if (file.exists()) {
            assertTrue("Couldn't delete countfile", file.delete());
        }
    }
}
