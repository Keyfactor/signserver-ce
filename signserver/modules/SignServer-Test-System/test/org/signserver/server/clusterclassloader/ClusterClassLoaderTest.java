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
import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;

import org.signserver.cli.signserver;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestAndResponseManager;
import org.signserver.protocol.ws.ProcessRequestWS;
import org.signserver.protocol.ws.ProcessResponseWS;
import org.signserver.protocol.ws.client.WSClientUtil;
import org.signserver.protocol.ws.gen.SignServerWS;
import org.signserver.protocol.ws.gen.SignServerWSService;
import org.signserver.testutils.ExitException;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class ClusterClassLoaderTest extends ModulesTestCase {

    private static String signserverhome;
    private SignServerWS signServerWS;

    public ClusterClassLoaderTest() {
        setupSSLKeystores();
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        TestUtils.redirectToTempOut();
        TestUtils.redirectToTempErr();
        TestingSecurityManager.install();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
        QName qname = new QName("gen.ws.protocol.signserver.org", "SignServerWSService");
        SignServerWSService signServerWSService =
                new SignServerWSService(new URL("https://localhost:"
                + getPublicHTTPSPort()
                + "/signserver/signserverws/signserverws?wsdl"),
                qname);
        signServerWS = signServerWSService.getSignServerWSPort();
    }

    public void testClusterClassLoader() throws Exception {
        assertSuccessfulExecution(new String[]{"module", "add",
                    signserverhome + "/res/test/testcodev1.mar"});
        assertTrue(TestUtils.grepTempOut("Loading module TESTCODE with version 1"));
        assertTrue(TestUtils.grepTempOut("Module loaded successfully."));

        assertSuccessfulExecution(new String[]{"module", "add",
                    signserverhome + "/res/test/testcodev2.mar"});
        assertTrue(TestUtils.grepTempOut("Loading module TESTCODE with version 2"));
        assertTrue(TestUtils.grepTempOut("Module loaded successfully."));

        assertSuccessfulExecution(new String[]{"reload",
                    "8888"});
        assertTrue(TestUtils.grepTempOut("SignServer reloaded successfully"));

        assertSuccessfulExecution(new String[]{"reload",
                    "8889"});
        assertTrue(TestUtils.grepTempOut("SignServer reloaded successfully"));

        assertSuccessfulExecution(new String[]{"reload",
                    "8890"});
        assertTrue(TestUtils.grepTempOut("SignServer reloaded successfully"));



        GenericSignRequest signRequest1 = new GenericSignRequest(12, "testreq".getBytes());
        ProcessRequestWS req1 = new ProcessRequestWS(signRequest1);

        ArrayList<ProcessRequestWS> reqs = new ArrayList<ProcessRequestWS>();
        reqs.add(req1);

        List<ProcessResponseWS> result = WSClientUtil.convertProcessResponseWS(signServerWS.process("8888", WSClientUtil.convertProcessRequestWS(reqs)));
        assertTrue(result.size() == 1);
        assertTrue(result.get(0).getRequestID() == 12);
        GenericSignResponse genresp = (GenericSignResponse) RequestAndResponseManager.parseProcessResponse(result.get(0).getResponseData());
        String processedString = new String(genresp.getProcessedData());
        assertTrue(processedString, processedString.equals("testreq, classname + v1.org.signserver.server.clusterclassloader.testcode.ReturnVersionTestProcessable"));


        GenericSignRequest signRequest2 = new GenericSignRequest(13, "testreq".getBytes());
        ProcessRequestWS req2 = new ProcessRequestWS(signRequest2);

        ArrayList<ProcessRequestWS> reqs2 = new ArrayList<ProcessRequestWS>();
        reqs2.add(req2);

        List<ProcessResponseWS> result2 = WSClientUtil.convertProcessResponseWS(signServerWS.process("8889", WSClientUtil.convertProcessRequestWS(reqs2)));
        assertTrue(result2.size() == 1);
        assertTrue(result2.get(0).getRequestID() == 13);
        GenericSignResponse genresp2 = (GenericSignResponse) RequestAndResponseManager.parseProcessResponse(result2.get(0).getResponseData());
        String processedString2 = new String(genresp2.getProcessedData());
        assertTrue(processedString2, processedString2.equals("testreq, classname + v2.org.signserver.server.clusterclassloader.testcode.ReturnVersionTestProcessable"));

        GenericSignRequest signRequest3 = new GenericSignRequest(13, "testreq".getBytes());
        ProcessRequestWS req3 = new ProcessRequestWS(signRequest3);

        ArrayList<ProcessRequestWS> reqs3 = new ArrayList<ProcessRequestWS>();
        reqs3.add(req3);

        List<ProcessResponseWS> result3 = WSClientUtil.convertProcessResponseWS(signServerWS.process("8890", WSClientUtil.convertProcessRequestWS(reqs3)));
        assertTrue(result3.size() == 1);
        assertTrue(result3.get(0).getRequestID() == 13);
        GenericSignResponse genresp3 = (GenericSignResponse) RequestAndResponseManager.parseProcessResponse(result3.get(0).getResponseData());
        String processedString3 = new String(genresp3.getProcessedData());
        assertTrue(processedString3, processedString3.equals("testreq, classname + v1.org.signserver.server.clusterclassloader.testcode.ReturnVersionTestProcessable"));

    }

    public void testRemoveConfiguration() throws Exception {
        assertSuccessfulExecution(new String[]{"module", "remove",
                    "testcode", "1"});
        assertTrue(TestUtils.grepTempOut("Removing module TESTCODE version 1"));
        assertTrue(TestUtils.grepTempOut("Removal of module successful."));

        assertSuccessfulExecution(new String[]{"module", "remove",
                    "testcode", "2"});
        assertTrue(TestUtils.grepTempOut("Removing module TESTCODE version 2"));
        assertTrue(TestUtils.grepTempOut("Removal of module successful."));

        assertSuccessfulExecution(new String[]{"removeworker",
                    "8888"});

        assertSuccessfulExecution(new String[]{"removeworker",
                    "8889"});

        assertSuccessfulExecution(new String[]{"removeworker",
                    "8890"});

        assertSuccessfulExecution(new String[]{"reload",
                    "8888"});
        assertTrue(TestUtils.grepTempOut("SignServer reloaded successfully"));

        assertSuccessfulExecution(new String[]{"reload",
                    "8889"});
        assertTrue(TestUtils.grepTempOut("SignServer reloaded successfully"));

        assertSuccessfulExecution(new String[]{"reload",
                    "8890"});
        assertTrue(TestUtils.grepTempOut("SignServer reloaded successfully"));
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        TestingSecurityManager.remove();
    }

    private void assertSuccessfulExecution(String[] args) {
        try {
            TestUtils.flushTempOut();
            signserver.main(args);
        } catch (ExitException e) {
            TestUtils.printTempErr();
            TestUtils.printTempOut();
            assertTrue(false);
        }
    }
}
