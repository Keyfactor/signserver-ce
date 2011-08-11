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

    private static IGlobalConfigurationSession.IRemote gCSession = null;
    private static IWorkerSession.IRemote sSSession = null;
    private static String tmpFile;
    private static final int INTERVAL = 7;
    private static final int INTERVALMS = 7000;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
        gCSession = ServiceLocator.getInstance().lookupRemote(IGlobalConfigurationSession.IRemote.class);
        sSSession = ServiceLocator.getInstance().lookupRemote(IWorkerSession.IRemote.class);
    }

    public void test00SetupDatabase() throws Exception {

        gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER17.CLASSPATH", "org.signserver.server.timedservices.DummyTimedService");

        sSSession.setWorkerProperty(17, ServiceConfig.ACTIVE, "TRUE");
        sSSession.setWorkerProperty(17, ServiceConfig.INTERVAL,
                String.valueOf(INTERVAL));
        String signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
        tmpFile = signserverhome + "/tmp/testservicefile.tmp";
        sSSession.setWorkerProperty(17, "OUTPATH", tmpFile);

        resetCount();

        sSSession.reloadConfiguration(17);
    }

    public void test01BasicService() throws Exception {


        Thread.sleep((3 * INTERVAL + 1) * 1000);
        final int readCount = readCount();
        assertTrue("readCount: " + readCount,
                readCount >= 3 && readCount <= 4);
    }

    /*
     * Test method for 'org.signserver.server.MRTDSigner.getStatus()'
     */
    public void test02GetStatus() throws Exception {
        ServiceStatus status = (ServiceStatus) sSSession.getStatus(17);
        Date lastRun = new ServiceConfig(status.getActiveSignerConfig()).getLastRunTimestamp();
        assertTrue(lastRun.before(new Date()) && lastRun.after(new Date(System.currentTimeMillis() - 14000)));
        assertTrue(status.getActiveSignerConfig().getProperties().get("INTERVAL").equals(String.valueOf(INTERVAL)));

    }

    public void test03TestInActive() throws Exception {
        sSSession.setWorkerProperty(17, ServiceConfig.ACTIVE, "FALSE");
        sSSession.reloadConfiguration(17);

        final int readCount = readCount();

        Thread.sleep(2 * INTERVAL);
        assertEquals(readCount, readCount());
    }

    /**
     * Only test that singleton mode works as nonsingleton service in one node services.
     */
    public void test04TestOneNodeSingleton() throws Exception {

        final int oldReadCount = readCount();
        sSSession.setWorkerProperty(17, ServiceConfig.ACTIVE, "TRUE");
        sSSession.setWorkerProperty(17, ServiceConfig.SINGLETON, "TRUE");
        sSSession.reloadConfiguration(17);

        Thread.sleep(3 * INTERVAL);
        final int readCount = readCount();
        System.out.println("readCount: " + readCount);
        assertTrue(readCount >= oldReadCount + 0
                && readCount <= oldReadCount + 1);

    }

    /**
     * Only test that singleton mode works as nonsingleton service in one node services.
     */
    public void test05TestCronExpression() throws Exception {
        sSSession.removeWorkerProperty(17, ServiceConfig.SINGLETON);
        sSSession.removeWorkerProperty(17, ServiceConfig.INTERVAL);

        sSSession.setWorkerProperty(17, ServiceConfig.CRON, "* * * ? * *");

        sSSession.reloadConfiguration(17);
        final int oldReadCount = readCount();

        Thread.sleep(4 * INTERVAL);
        final int readCount = readCount();
        System.out.println("readCount: " + readCount);
        assertTrue(readCount >= oldReadCount + 0
                && readCount <= oldReadCount + 1);
    }

    public void test06intervalMs() throws Exception {
        sSSession.removeWorkerProperty(17, ServiceConfig.SINGLETON);
        sSSession.removeWorkerProperty(17, ServiceConfig.INTERVAL);
        sSSession.removeWorkerProperty(17, ServiceConfig.CRON);
        sSSession.setWorkerProperty(17, ServiceConfig.INTERVALMS,
                String.valueOf(INTERVALMS));
        sSSession.reloadConfiguration(17);

        final int oldReadCount = readCount();

        Thread.sleep(3 * INTERVALMS + 1000);
        final int readCount = readCount();
        assertTrue("readCount: " + readCount,
                readCount >= oldReadCount + 3
                && readCount <= oldReadCount + 4);
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
        while ((next = fis.read()) != -1) {
            baos.write(next);
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
