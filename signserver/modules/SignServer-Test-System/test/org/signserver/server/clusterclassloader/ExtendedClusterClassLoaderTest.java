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
package org.signserver.server.clusterclassloader;

import java.net.URL;

import javax.xml.namespace.QName;

import junit.framework.TestCase;

import org.signserver.common.SignServerUtil;
import org.signserver.common.ServiceLocator;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.genericws.gen.DummyWS;
import org.signserver.server.genericws.gen.DummyWSService;
import org.signserver.test.system.SignServerBuildProperties;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class ExtendedClusterClassLoaderTest extends TestCase {

    private static IWorkerSession.IRemote sSSession = null;
    private static String signserverhome;
    private static final int WORKERID = 7632;
    private static int moduleVersion;

    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
        sSSession = ServiceLocator.getInstance().lookupRemote(
                IWorkerSession.IRemote.class);
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
        TestUtils.redirectToTempOut();
        TestUtils.redirectToTempErr();
        TestingSecurityManager.install();
    }

    public void test00SetupDatabase() throws Exception {
        MARFileParser marFileParser = new MARFileParser(signserverhome + "/dist-server/dummyws.mar");
        moduleVersion = marFileParser.getVersionFromMARFile();

        TestUtils.assertSuccessfulExecution(new String[]{"module", "add",
                    signserverhome + "/dist-server/dummyws.mar", "junittest"});
        assertTrue(TestUtils.grepTempOut("Loading module DUMMYWS"));
        assertTrue(TestUtils.grepTempOut("Module loaded successfully."));

        sSSession.setWorkerProperty(WORKERID,
                "hibernate.connection.datasource",
                SignServerBuildProperties.getInstance().getProperty(
                SignServerBuildProperties.DATASOURCE_JNDINAMEPREFIX)
                + SignServerBuildProperties.getInstance().getProperty(
                SignServerBuildProperties.DATASOURCE_JNDINAME));

        sSSession.reloadConfiguration(WORKERID);
    }

    public void test01TestBasicJPA() throws Exception {
        QName qname = new QName("gen.genericws.server.signserver.org", "DummyWSService");
        DummyWSService dummywsservice = new DummyWSService(new URL("http://localhost:8080/signserver/ws/dummyws/dummyws?wsdl"), qname);
        DummyWS dummyws = dummywsservice.getDummyWSPort();

        String result = dummyws.test("dbtest");
        assertTrue(result, result.equals("success"));
    }

    public void test99RemoveDatabase() throws Exception {
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker",
                    "" + WORKERID});

        TestUtils.assertSuccessfulExecution(new String[]{"module", "remove", "DUMMYWS", "" + moduleVersion});
        assertTrue(TestUtils.grepTempOut("Removal of module successful."));
        sSSession.reloadConfiguration(WORKERID);
    }

    /* (non-Javadoc)
     * @see junit.framework.TestCase#tearDown()
     */
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        TestingSecurityManager.remove();
    }
}
