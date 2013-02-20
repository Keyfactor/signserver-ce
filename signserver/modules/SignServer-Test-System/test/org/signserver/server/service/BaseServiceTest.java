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

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ServiceConfig;
import org.signserver.common.ServiceStatus;
import org.signserver.common.SignServerUtil;
import org.signserver.common.ServiceLocator;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;

/**
 * TODO: Document me!
 * @version $Id$
 */
public class BaseServiceTest extends TestCase {
    private static final Logger LOG = Logger.getLogger(BaseServiceTest.class);
    
    private static IGlobalConfigurationSession.IRemote gCSession = null;
    private static IWorkerSession.IRemote sSSession = null;
    private static String tmpFile;
    private static final int INTERVAL = 8;
    private static final int INTERVALMS = INTERVAL * 1000;
    private static final int WORKER_ID = 17;
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
        gCSession = ServiceLocator.getInstance().lookupRemote(IGlobalConfigurationSession.IRemote.class);
        sSSession = ServiceLocator.getInstance().lookupRemote(IWorkerSession.IRemote.class);
    }

    public void test00SetupDatabase() throws Exception {

        gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + WORKER_ID + ".CLASSPATH", "org.signserver.server.timedservices.DummyTimedService");

        sSSession.setWorkerProperty(WORKER_ID, ServiceConfig.ACTIVE, "TRUE");
        sSSession.setWorkerProperty(WORKER_ID, ServiceConfig.INTERVAL,
                String.valueOf(INTERVAL));
        String signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
        tmpFile = signserverhome + "/tmp/testservicefile.tmp";
        sSSession.setWorkerProperty(WORKER_ID, "OUTPATH", tmpFile);

        resetCount();

        sSSession.reloadConfiguration(WORKER_ID);
    }

    /**
     * Test the counter is updated. The test checks the elapsed real time
     * to avoid random failures due to i.e. GC runs.
     * @throws Exception
     */
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
     * Test method for 'org.signserver.server.MRTDSigner.getStatus()'
     */
    public void test02GetStatus() throws Exception {
        ServiceStatus status = (ServiceStatus) sSSession.getStatus(WORKER_ID);
        Date lastRun = new ServiceConfig(status.getActiveSignerConfig()).getLastRunTimestamp();
        assertTrue(lastRun.before(new Date()));
        assertTrue(lastRun.after(new Date(System.currentTimeMillis() - INTERVALMS * 2)));
        assertTrue(status.getActiveSignerConfig().getProperties().get("INTERVAL").equals(String.valueOf(INTERVAL)));

    }

    /**
     * Tests that the counter is not updated when setting ACTIVE=FALSE.
     * @throws Exception
     */
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
     * @throws Exception
     */
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

    public void test99TearDownDatabase() throws Exception {
        gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER17.CLASSPATH");

        sSSession.removeWorkerProperty(17, "INTERVAL");
        sSSession.removeWorkerProperty(17, "INTERVALMS");
        sSSession.removeWorkerProperty(17, "CRON");
        sSSession.removeWorkerProperty(17, ServiceConfig.SINGLETON);
        String signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
        sSSession.removeWorkerProperty(17, "OUTPATH");

        sSSession.reloadConfiguration(17);
    }

    private int readCount() throws IOException {
        FileInputStream fis = new FileInputStream(tmpFile);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int next = 0;
        try {
            while ((next = fis.read()) != -1) {
                baos.write(next);
            }
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    // ignored
                }
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
