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
package org.signserver.timemonitor.status;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.util.LinkedList;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.signserver.timemonitor.common.LeapState;
import org.signserver.timemonitor.common.ReportState;
import org.signserver.timemonitor.common.TimeMonitorRuntimeConfig;
import org.signserver.timemonitor.common.TimeState;
import org.signserver.timemonitor.core.StateHolder;
import org.signserver.timemonitor.core.TimeMonitorAppConfig;
import org.signserver.timemonitor.core.TimeMonitorAppConfigTest;
import org.signserver.timemonitor.core.TimeMonitorRunnable;
import org.signserver.timemonitor.core.TimeMonitorRunnableTest;

/**
 * Tests the SateWebServer class.
 *
 * @author Markus Kilås
 * @version $Id: StateWebServerTest.java 4574 2012-12-11 08:16:50Z marcus $
 */
public class StateWebServerTest extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(StateWebServerTest.class);

    private volatile TimeState timeState;
    private volatile ReportState reportState;
    private volatile LeapState leapState;
    private volatile long lastUpdated;
    private volatile String configVersion = "123";
    private volatile long offset = 456;

    public StateWebServerTest(String testName) {
        super(testName);
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Test of start method, of class StateWebServer.
     * @throws java.lang.Exception
     */
    public void testHttpHandler() throws Exception {
        System.out.println("HttpHandler");

        TimeMonitorAppConfig appConfig = TimeMonitorAppConfig.load(TimeMonitorAppConfigTest.getAppProperties());
        LinkedList<String> errors = new LinkedList<>();
        TimeMonitorRuntimeConfig runConfig = TimeMonitorRuntimeConfig.load(TimeMonitorRunnableTest.getRunProperties(), errors);
        if (!errors.isEmpty()) {
            throw new Exception("Error in test config: " + errors.toString());
        }

        final StateHolder stateHolder = new TimeMonitorRunnable(appConfig, runConfig) {
            @Override
            public StringBuilder getStateLine() {
                return TimeMonitorRunnable.getStateLine(lastUpdated, timeState, reportState, leapState, configVersion, offset, 1001, 2002, 3003);
            }
        };

        final int port = 19898;

        StateWebServer server = new StateWebServer(stateHolder, InetAddress.getByName("127.0.0.1"), port, 0, 2);
        try {
            server.start();

            final URL url = new URL("http://127.0.0.1:" + port + "/state");

            timeState = TimeState.INSYNC;
            reportState = ReportState.REPORTED;
            leapState = LeapState.NONE;
            lastUpdated = 1352107377123L;
            offset = 0;
            byte[] bytes = readBody(url);
            String body = new String(bytes);
            assertEquals("state", "1352107377123,INSYNC,REPORTED,NONE,123,0,1001,2002,3003", body);

            timeState = TimeState.OUT_OF_SYNC;
            reportState = ReportState.FAILED_TO_REPORT;
            leapState = LeapState.POSITIVE;
            lastUpdated = 1352107366123L;
            configVersion = "abbeff";
            offset = 456;
            bytes = readBody(url);
            body = new String(bytes);
            assertEquals("state", "1352107366123,OUT_OF_SYNC,FAILED_TO_REPORT,POSITIVE,abbeff,456,1001,2002,3003", body);

            timeState = TimeState.SOON_OUT_OF_SYNC;
            reportState = ReportState.REPORTED_BUT_EXPIRE_TIME_SHORT;
            leapState = LeapState.UNKNOWN;
            lastUpdated = 1352107355123L;
            offset = 100;
            bytes = readBody(url);
            body = new String(bytes);
            assertEquals("state", "1352107355123,SOON_OUT_OF_SYNC,REPORTED_BUT_EXPIRE_TIME_SHORT,UNKNOWN,abbeff,100,1001,2002,3003", body);
        } finally {
            server.stop(2);
        }
    }

    protected static byte[] readBody(final URL url) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setAllowUserInteraction(false);
        conn.setDoOutput(false);
        String responseMessage = conn.getResponseMessage();
        LOG.debug("responseMessage: " + responseMessage);

        assertEquals("response code", 200, conn.getResponseCode());

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        InputStream in = null;
        try {
            in = conn.getInputStream();

            int b;
            while ((b = in.read()) != -1) {
                bout.write(b);
            }

            return bout.toByteArray();
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {} // NOPMD
            }
            conn.disconnect();
        }
    }

}
