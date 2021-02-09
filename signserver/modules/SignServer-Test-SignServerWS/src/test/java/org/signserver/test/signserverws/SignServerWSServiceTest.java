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
package org.signserver.test.signserverws;

import java.io.IOException;
import java.net.URL;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;

import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestAndResponseManager;
import org.signserver.protocol.ws.gen.IllegalRequestException_Exception;
import org.signserver.protocol.ws.gen.InvalidWorkerIdException_Exception;
import org.signserver.protocol.ws.gen.ProcessRequestWS;
import org.signserver.protocol.ws.gen.ProcessResponseWS;
import org.signserver.protocol.ws.gen.SignServerWS;
import org.signserver.protocol.ws.gen.SignServerWSService;
import org.signserver.protocol.ws.gen.WorkerStatusWS;
import org.signserver.test.conf.SignerConfigurationBuilder;
import org.signserver.test.util.WSTestUtil;
import org.signserver.testutils.ModulesTestCase;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * Test calling the latest SignServerWSService using SignServer WSDL.
 * This tests assumes that test-configuration.properties as been applied to SignServer.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SignServerWSServiceTest extends ModulesTestCase {

    // Logger for this class
    private static final Logger LOG = Logger.getLogger(SignServerWSServiceTest.class);
    // Endpoints configuration
    private final String ENDPOINT_NAME = "SignServerWSService";
    private final String ENDPOINT_NAMESPACE = "gen.ws.protocol.signserver.org";
    private final String ENDPOINT_URL = "https://" + getHTTPHost() + ":" + getPublicHTTPSPort() + "/signserver/" +
            ENDPOINT_NAME + "/SignServerWS?wsdl";
    private final String ENDPOINT_WSDL_IN_CLASSPATH = "META-INF/wsdl/SignServerWSService.wsdl";
    // Worker ID as defined in test-configuration.properties.
    private static final int WORKER_ID_INT = 7003;
    private static final String WORKER_ID = "" + WORKER_ID_INT;
    private static final int REQUEST_ID = 4711;
    // Non-existing worker ID
    private static final String NON_EXISTING_WORKER_ID = "1231231";
    //
    private static SSLSocketFactory sslSocketFactory;
    // Class under test
    private SignServerWS ws;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @BeforeClass
    public static void beforeClass() throws Exception {
        sslSocketFactory = initSSLKeystore();
    }

    @Before
    public void setUp() throws Exception {
        LOG.info("Initializing test using WS URL: " + ENDPOINT_URL);
        final QName qname = new QName(ENDPOINT_NAMESPACE, ENDPOINT_NAME);
        final URL resource = SignServerWS.class.getResource(ENDPOINT_WSDL_IN_CLASSPATH);
        final SignServerWSService signServerWSService = new SignServerWSService(resource, qname);
        // Create an instance of WS
        ws =  signServerWSService.getSignServerWSPort();
        // Define binding
        final BindingProvider bp = (BindingProvider) ws;
        final Map<String, Object> requestContext = bp.getRequestContext();
        requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, ENDPOINT_URL);
        // Set the secure connection
        if (sslSocketFactory != null) {
            final Client client = ClientProxy.getClient(bp);
            final HTTPConduit http = (HTTPConduit) client.getConduit();
            final TLSClientParameters params = new TLSClientParameters();
            params.setSSLSocketFactory(sslSocketFactory);
            http.setTlsClientParameters(params);
            final HTTPClientPolicy policy = http.getClient();
            policy.setAutoRedirect(true);
        }
        addDummySigner(WORKER_ID_INT, "SignServerWSServiceTest_XMLSigner", true);
        // Add a Signer Worker
        addTestXMLSigner(
                SignerConfigurationBuilder.builder()
                        .withSignerId(WORKER_ID_INT)
                        .withSignerName("signserverwsTest_XMLSigner")
                        .withAutoActivate(true)
        );
    }

    @After
    public void tearDown() {
        removeWorker(WORKER_ID_INT);
    }

    @Test
    public void successOnGetStatusOfExisting() throws Exception {
        LOG.info("successOnGetStatusOfExisting");
        // given
        // when
        final List<WorkerStatusWS> statuses = ws.getStatus(WORKER_ID);
        assertEquals("Number of results", 1, statuses.size());
        final WorkerStatusWS status = statuses.get(0);
        // then
        LOG.info("Status: " + WSTestUtil.toJsonString(status));
        assertEquals("workerName", WORKER_ID, status.getWorkerName());
        assertNull("errormessage", status.getErrormessage());
        assertEquals("overallStatus", "ALLOK", status.getOverallStatus());
    }

    @Test
    public void failOnGetStatusOfNonExisting() throws Exception {
        LOG.info("failOnGetStatusOfNonExisting");
        // given
        expectedException.expect(InvalidWorkerIdException_Exception.class);
        expectedException.expectMessage("No such worker: " + NON_EXISTING_WORKER_ID);
        // when
        ws.getStatus(NON_EXISTING_WORKER_ID);
    }

    @Test
    public void successOnProcess() throws Exception {
        LOG.info("successOnProcess");
        // given
        final List<ProcessRequestWS> requests = populateRequestWSs("<root/>");
        // when
        final List<ProcessResponseWS> responses = ws.process(WORKER_ID, requests);
        // then
        assertEquals("Number of results", 1, responses.size());
        final GenericSignResponse response = (GenericSignResponse) RequestAndResponseManager.parseProcessResponse(Base64.decode(responses.get(0).getResponseDataBase64()));
        LOG.info("Response: " + WSTestUtil.toJsonString(responses.get(0)));
        assertEquals("requestID", REQUEST_ID, response.getRequestID());
        final Certificate certificate = response.getSignerCertificate();
        assertNotNull("Certificate", certificate);
    }

    @Test
    public void failOnProcessOfNonExisting() throws Exception {
        LOG.info("failOnProcessOfNonExisting");
        // given
        expectedException.expect(InvalidWorkerIdException_Exception.class);
        expectedException.expectMessage("No such worker: " + NON_EXISTING_WORKER_ID);
        final List<ProcessRequestWS> requests = populateRequestWSs("<root/>");
        // when
        ws.process(NON_EXISTING_WORKER_ID, requests);
    }

    @Test
    public void failOnProcessOfIllegalRequest() throws Exception {
        LOG.info("failOnProcessOfIllegalRequest");
        // given
        expectedException.expect(IllegalRequestException_Exception.class);
        expectedException.expectMessage("Document parsing error");
        final List<ProcessRequestWS> requests = populateRequestWSs("< not-an-well-formed-xml-doc");
        // when
        ws.process(WORKER_ID, requests);
    }

    private List<ProcessRequestWS> populateRequestWSs(final String content) throws IOException {
        final List<ProcessRequestWS> requests = new ArrayList<>();
        final ProcessRequestWS request = new ProcessRequestWS();
        request.setRequestDataBase64(
                new String(
                        Base64.encode(RequestAndResponseManager.serializeProcessRequest(
                                new GenericSignRequest(REQUEST_ID, content.getBytes()))
                        )
                )
        );
        requests.add(request);
        return requests;
    }
}
