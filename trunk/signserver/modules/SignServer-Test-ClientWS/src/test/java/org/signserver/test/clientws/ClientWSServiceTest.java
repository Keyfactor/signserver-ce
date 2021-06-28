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
package org.signserver.test.clientws;

import java.net.URL;
import java.nio.charset.StandardCharsets;
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
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.signserver.client.clientws.ClientWS;
import org.signserver.client.clientws.ClientWSService;
import org.signserver.client.clientws.DataResponse;
import org.signserver.client.clientws.RequestFailedException_Exception;
import org.signserver.test.conf.SignerConfigurationBuilder;
import org.signserver.test.util.WSTestUtil;
import org.signserver.testutils.ModulesTestCase;

import static org.junit.Assert.assertNotNull;

/**
 * System test calling ClientWSService.
 *
 * This tests assumes that test-configuration.properties has been applied to SignServer.
 *
 * @author Andrey Sergeev 15-jan-2021
 * @version $Id$
 */
public class ClientWSServiceTest extends ModulesTestCase {

    private static final Logger LOG = Logger.getLogger(ClientWSServiceTest.class);
    // Endpoints configuration
    private final String ENDPOINT_NAME = "ClientWSService";
    private final String ENDPOINT_NAMESPACE = "http://clientws.signserver.org/";
    private final String ENDPOINT_URL = "https://" + getHTTPHost() + ":" + getPublicHTTPSPort() + "/signserver/" +
            ENDPOINT_NAME + "/ClientWS?wsdl";
    private final String ENDPOINT_WSDL_IN_CLASSPATH = "META-INF/wsdl/localhost_8080/signserver/" +
            ENDPOINT_NAME + "/ClientWS.wsdl";
    // Worker ID as defined in test-configuration.properties.
    private static final int WORKER_ID_INT = 7003;
    private static final String WORKER_ID = "" + WORKER_ID_INT;
    // Non-existing worker ID
    private static final String NON_EXISTING_WORKER_ID = "1231231";
    private static final String TEST_XML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root/>";
    private static final String TEST_XML_BROKEN = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root";
    //
    private static SSLSocketFactory sslSocketFactory;
    // Class under test
    private ClientWS ws;

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
        final URL resource = ClientWS.class.getResource(ENDPOINT_WSDL_IN_CLASSPATH);
        final ClientWSService clientWSService = new ClientWSService(resource, qname);
        // Create an instance of WS
        ws = clientWSService.getClientWSPort();
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
        // Add a Signer Worker
        addTestXMLSigner(
                SignerConfigurationBuilder.builder()
                        .withSignerId(WORKER_ID_INT)
                        .withSignerName("ClientWSServiceTest_XMLSigner")
                        .withAutoActivate(true)
        );
    }

    @After
    public void tearDown() {
        removeWorker(WORKER_ID_INT);
    }

    /** Tests that a request can be successfully sent and the values that comes back are not null. */
    @Test
    public void successOnProcessData() throws Exception {
        LOG.info("successOnProcessData");
        // given
        final byte[] requestData = TEST_XML.getBytes(StandardCharsets.UTF_8);
        // when
        final DataResponse response = ws.processData(WORKER_ID, null, requestData);
        // then
        LOG.info("Response: " + WSTestUtil.toJsonString(response));
        assertNotNull("Response", response);
        assertNotNull("Archive Id", response.getArchiveId());
        assertNotNull("Data", response.getData());
        //assertNotNull("Request Id", response.getRequestId());
        assertNotNull("Signer Certificate", response.getSignerCertificate());
    }

    /**
     * Tests for failure on request to non-existing worker.
     */
    @Test
    public void failOnProcessOfNonExisting() throws Exception {
        LOG.info("failOnProcessDataOfNonExisting");
        // given
        expectedException.expect(RequestFailedException_Exception.class);
        expectedException.expectMessage("No such worker: " + NON_EXISTING_WORKER_ID);
        final byte[] requestData = TEST_XML.getBytes(StandardCharsets.UTF_8);
        // when
        ws.processData(NON_EXISTING_WORKER_ID, null, requestData);
    }

    /**
     * Tests for failure on request with invalid xml.
     */
    @Test
    public void failOnProcessOfBrokenXml() throws Exception {
        LOG.info("failOnProcessOfBrokenXml");
        // given
        expectedException.expect(RequestFailedException_Exception.class);
        expectedException.expectMessage("Document parsing error");
        final byte[] requestData = TEST_XML_BROKEN.getBytes(StandardCharsets.UTF_8);
        // when
        ws.processData(WORKER_ID, null, requestData);
    }
}
