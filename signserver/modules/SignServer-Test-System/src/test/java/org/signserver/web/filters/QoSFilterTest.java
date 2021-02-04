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
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.naming.NamingException;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeFalse;

import org.apache.commons.io.FileUtils;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionRemote;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.elems.Term;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.signserver.admin.common.query.AuditLogFields;
import org.signserver.admin.common.query.QueryUtil;
import org.signserver.client.clientws.ClientWS;
import org.signserver.client.clientws.ClientWSService;
import org.signserver.client.clientws.DataResponse;
import org.signserver.common.CESeCoreModules;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ServiceLocator;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionRemote;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.test.conf.QoSFilterPropertiesBuilder;
import org.signserver.test.conf.SignerConfigurationBuilder;
import org.signserver.test.conf.WorkerPropertiesBuilder;
import org.signserver.test.util.WSTestUtil;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.web.common.filters.QoSFilterProperties;

/**
 * System tests for the QoSFilter.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class QoSFilterTest extends ModulesTestCase {

    // Logger for this class
    private static final Logger LOG = Logger.getLogger(QoSFilterTest.class);
    //
    private static final String SIGNSERVER_HOME = System.getenv("SIGNSERVER_HOME");
    // Workers
    private static final int WORKER1_ID = 1000;
    private static final String WORKER1_NAME = "SleepWorkerTest";
    private static final int WORKER2_ID = 1001;
    private static final String WORKER2_NAME = "SleepWorkerTest2";
    // Session instances
    private static final CLITestHelper CLIENT_CLI = getCurrentClientCLI();
    private static final WorkerSessionRemote WORKER_SESSION = getCurrentWorkerSession();
    private static final GlobalConfigurationSessionRemote GLOBAL_SESSION = getCurrentGlobalSession();
    private SecurityEventsAuditorSessionRemote auditorSession = null;
    // Contains QoSFilter Global Property names to flush the configuration
    private final static List<String> QOS_FILTER_PROPS_LIST = Arrays.asList(
            QoSFilterProperties.QOS_FILTER_ENABLED,
            QoSFilterProperties.QOS_PRIORITIES,
            QoSFilterProperties.QOS_MAX_REQUESTS,
            QoSFilterProperties.QOS_MAX_PRIORITY
    );
    private static long qoSFilterCacheTtlS = 3;
    // A reset flag for QOS Properties to minimize possible delays if not needed for reload of cache
    private boolean shouldResetQosProps = false;
    //
    private static SSLSocketFactory sslSocketFactory;

    @Rule
    public final TemporaryFolder inDir = new TemporaryFolder();
    @Rule
    public final TemporaryFolder outDir = new TemporaryFolder();

    @BeforeClass
    public static void setupClass() throws Exception {
        assertNotNull("Please set SIGNSERVER_HOME environment variable", SIGNSERVER_HOME);
        addTestSleepWorker(
                SignerConfigurationBuilder.builder()
                        .withSignerId(WORKER1_ID)
                        .withSignerName(WORKER1_NAME)
                        .withAutoActivate(true)
        );
        applyWorkerPropertiesAndReload(
                WorkerPropertiesBuilder.builder()
                        .withWorkerId(WORKER1_ID)
                        .withSleepTime(1000L)
                        .withWorkerLogger("org.signserver.server.log.SecurityEventsWorkerLogger")
        );
        addTestSleepWorker(
                SignerConfigurationBuilder.builder()
                        .withSignerId(WORKER2_ID)
                        .withSignerName(WORKER2_NAME)
                        .withAutoActivate(true)
        );
        applyWorkerPropertiesAndReload(
                WorkerPropertiesBuilder.builder()
                        .withWorkerId(WORKER2_ID)
                        .withSleepTime(1000L)
                        .withWorkerLogger("org.signserver.server.log.SecurityEventsWorkerLogger")
        );
        // set priority mapping, include some unused signers to test that parsing the set works as expected
        GLOBAL_SESSION.setProperty(
                GlobalConfiguration.SCOPE_GLOBAL, QoSFilterProperties.QOS_PRIORITIES, "1:1,1000:5,1002:2");
        // set cache reload to 3 seconds
        GLOBAL_SESSION.setProperty(
                GlobalConfiguration.SCOPE_GLOBAL, QoSFilterProperties.QOS_CACHE_TTL_S, "" + qoSFilterCacheTtlS);
        // Enabled parameter to get default behaviour
        GLOBAL_SESSION.setProperty(
                GlobalConfiguration.SCOPE_GLOBAL, QoSFilterProperties.QOS_FILTER_ENABLED, "true");
        // wait until old cached filter config has expired (DEFAULT (10s) + with some margin)
        Thread.sleep((10 + 1) * 1000);
        //
        sslSocketFactory = initSSLKeystore();
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
        removeWorkerById(WORKER1_ID);
        removeWorkerById(WORKER2_ID);
        // Reset QoSFilter
        // Reset Global Configuration by removing all properties
        for (String property : QOS_FILTER_PROPS_LIST) {
            GLOBAL_SESSION.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, property);
        }
        GLOBAL_SESSION.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, QoSFilterProperties.QOS_CACHE_TTL_S);
        GLOBAL_SESSION.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, QoSFilterProperties.QOS_FILTER_ENABLED);
        // wait until old cached filter config has expired (with some margin)
        Thread.sleep((qoSFilterCacheTtlS + 1) * 1000);
    }

    @Before
    public void setUp() throws Exception {
        assumeFalse("Test does not run in NODB mode",
                "nodb".equalsIgnoreCase(getDeployConfig().getProperty("database.name")));
    }

    @After
    public void tearDown() throws Exception {
        if(shouldResetQosProps) {
            // Reset Global Configuration by removing all properties
            for (String property : QOS_FILTER_PROPS_LIST) {
                GLOBAL_SESSION.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, property);
            }
            // Reset priorities
            GLOBAL_SESSION.setProperty(
                    GlobalConfiguration.SCOPE_GLOBAL,
                    QoSFilterProperties.QOS_PRIORITIES, "1:1,1000:5,1002:2"
            );
            // wait until old cached filter config has expired (with some margin)
            Thread.sleep((qoSFilterCacheTtlS + 1) * 1000);
            // Reset flag
            shouldResetQosProps = false;
        }
    }

    // Test that a single request will not be queued by the QoSFilter.
    @Test
    public void singleRequest() throws Exception {
        // given
        applyQoSFilterProperties(QoSFilterPropertiesBuilder.builder().withFilterEnabled("true"));
        // when
        CLIENT_CLI.execute("signdocument", "-servlet",
                          "/signserver/worker/" + WORKER1_NAME,
                          "-data", "foo");
        // then
        final int priorityHits = countPriorityHits(1, "not set");
        assertEquals("Priority not set by filter", 1, priorityHits);
    }

    /**
     * Test that sending more more requests to the SleepWorker that the hard-coded max concurrent requests will result
     * in some requests getting queued by the filter (and thus having the worker log field set accordingly).
     */
    @Test
    public void someRequestsQueuedAndPrioritized() throws Exception {
        // given
        createTestFiles(20);
        applyQoSFilterProperties(QoSFilterPropertiesBuilder.builder().withFilterEnabled("true"));
        // when
        CLIENT_CLI.execute("signdocument", "-servlet",
                          "/signserver/worker/" + WORKER1_NAME,
                          "-threads", "20",
                          "-indir", inDir.getRoot().getAbsolutePath(),
                          "-outdir", outDir.getRoot().getAbsolutePath());
        // then
        final int priorityHits = countPriorityHits(20, "5");
        assertTrue("Some requests should have been queued at priority 5", priorityHits > 0);
    }

    /**
     * Test that sending more more requests to the SleepWorker that the hard-coded max concurrent requests will result
     * in some requests getting queued by the filter (and thus having the worker log field set accordingly). Using a
     * signer with explicit priority mapping, should get default (0) priority.
     */
    @Test
    public void someRequestsQueuedAndPrioritizedWithDefaultPriority() throws Exception {
        // given
        createTestFiles(20);
        applyQoSFilterProperties(QoSFilterPropertiesBuilder.builder().withFilterEnabled("true"));
        // when
        CLIENT_CLI.execute("signdocument", "-servlet",
                          "/signserver/worker/" + WORKER2_NAME,
                          "-threads", "20",
                          "-indir", inDir.getRoot().getAbsolutePath(),
                          "-outdir", outDir.getRoot().getAbsolutePath());
        // then
        final int priorityHits = countPriorityHits(20, "0");
        assertTrue("Some requests should have been queued at priority 0", priorityHits > 0);
    }

    /**
     * Test that setting max accepted requests to a higher value than
     * the number of concurrent threads run will not result in queueing requests.
     */
    @Test
    public void higherMaxRequests() throws Exception {
        // given
        createTestFiles(20);
        applyQoSFilterProperties(QoSFilterPropertiesBuilder.builder().withFilterEnabled("true").withMaxRequests("50"));
        // when
        CLIENT_CLI.execute("signdocument", "-servlet",
                          "/signserver/worker/" + WORKER1_NAME,
                          "-threads", "20",
                          "-indir", inDir.getRoot().getAbsolutePath(),
                          "-outdir", outDir.getRoot().getAbsolutePath());
        // then
        final int priorityHits = countPriorityHits(20, "not set");
        assertEquals("No requests should be queued", 20, priorityHits);
    }

    // Test that setting a higher max priority level correctly works with a worker configured to that level.
    @Test
    public void higherMaxPriorityLevel() throws Exception {
        // given
        createTestFiles(20);
        applyQoSFilterProperties(
                QoSFilterPropertiesBuilder.builder()
                        .withFilterEnabled("true")
                        .withPriorities("1:1,1000:50,1002:2")
                        .withMaxPriority("50")
        );
        // when
        CLIENT_CLI.execute("signdocument", "-servlet",
                          "/signserver/worker/" + WORKER1_NAME,
                          "-threads", "20",
                          "-indir", inDir.getRoot().getAbsolutePath(),
                          "-outdir", outDir.getRoot().getAbsolutePath());
        // then
        final int priorityHits = countPriorityHits(20, "50");
        assertTrue("Some requests were queued at priority 50", priorityHits > 0);
    }

    // Test that when not setting GLOB.QOS_FILTER_ENABLED it default to inactive, not prioritizing any requests.
    @Test
    public void noRequestsPrioritizedByDefault() throws Exception {
        // given
        createTestFiles(20);
        // when
        CLIENT_CLI.execute("signdocument", "-servlet",
                          "/signserver/worker/" + WORKER1_NAME,
                          "-threads", "20",
                          "-indir", inDir.getRoot().getAbsolutePath(),
                          "-outdir", outDir.getRoot().getAbsolutePath());
        // then
        final int priorityHits = countPriorityHits(20, "not set");
        assertEquals("No requests prioritized (unset)", 20, priorityHits);
    }

    // Test that setting GLOB.QOS_FILTER_ENABLED to explicitly false results in inactive, not prioritizing any requests.
    @Test
    public void noRequestsPrioritizedExplicitFalse() throws Exception {
        // given
        createTestFiles(20);
        applyQoSFilterProperties(QoSFilterPropertiesBuilder.builder().withFilterEnabled("false"));
        // when
        CLIENT_CLI.execute("signdocument", "-servlet",
                          "/signserver/worker/" + WORKER1_NAME,
                          "-threads", "20",
                          "-indir", inDir.getRoot().getAbsolutePath(),
                          "-outdir", outDir.getRoot().getAbsolutePath());
        // then
        final int priorityHits = countPriorityHits(20, "not set");
        assertEquals("No requests prioritized (false)", 20, priorityHits);
    }

    // Test that setting GLOB.QOS_FILTER_ENABLED to an invalid value results in inactive, not prioritizing any requests.
    @Test
    public void noRequestsPrioritizedInvalidEnabled() throws Exception {
        // given
        applyQoSFilterProperties(QoSFilterPropertiesBuilder.builder().withFilterEnabled("false"));
        createTestFiles(20);
        applyQoSFilterProperties(QoSFilterPropertiesBuilder.builder().withFilterEnabled("_invalid_"));
        // when
        CLIENT_CLI.execute("signdocument", "-servlet",
                          "/signserver/worker/" + WORKER1_NAME,
                          "-threads", "20",
                          "-indir", inDir.getRoot().getAbsolutePath(),
                          "-outdir", outDir.getRoot().getAbsolutePath());
        // then
        final int priorityHits = countPriorityHits(20, "not set");
        assertEquals("No requests prioritized (_invalid_)", 20, priorityHits);
    }

    @Test
    public void singleClientWSRequest() throws Exception {
        // given
        applyQoSFilterProperties(QoSFilterPropertiesBuilder.builder().withFilterEnabled("true"));
        final byte[] requestData = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root/>".getBytes(StandardCharsets.UTF_8);
        final ClientWS ws = createClientWSService();
        // when
        final DataResponse response = ws.processData("" + WORKER1_ID, null, requestData);
        // then
        LOG.info("Response: " + WSTestUtil.toJsonString(response));
        assertNotNull("Response", response);
        final int priorityHits = countPriorityHits(1, "not set");
        assertEquals("Priority not set by filter", 1, priorityHits);
    }

    private void applyQoSFilterProperties(final QoSFilterPropertiesBuilder qoSFilterProps) throws Exception {
        if(qoSFilterProps.getFilterEnabled() != null) {
            GLOBAL_SESSION.setProperty(
                    GlobalConfiguration.SCOPE_GLOBAL,
                    QoSFilterProperties.QOS_FILTER_ENABLED,
                    qoSFilterProps.getFilterEnabled()
            );
        }
        if(qoSFilterProps.getPriorities() != null) {
            GLOBAL_SESSION.setProperty(
                    GlobalConfiguration.SCOPE_GLOBAL,
                    QoSFilterProperties.QOS_PRIORITIES,
                    qoSFilterProps.getPriorities()
            );
        }
        if(qoSFilterProps.getMaxRequests() != null) {
            GLOBAL_SESSION.setProperty(
                    GlobalConfiguration.SCOPE_GLOBAL,
                    QoSFilterProperties.QOS_MAX_REQUESTS,
                    qoSFilterProps.getMaxRequests()
            );
        }
        if(qoSFilterProps.getMaxPriority() != null) {
            GLOBAL_SESSION.setProperty(
                    GlobalConfiguration.SCOPE_GLOBAL,
                    QoSFilterProperties.QOS_MAX_PRIORITY,
                    qoSFilterProps.getMaxPriority()
            );
        }
        // wait until old cached filter config has expired (with some margin)
        Thread.sleep((qoSFilterCacheTtlS + 1) * 1000);
        shouldResetQosProps = true;
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
        final Term term = QueryUtil.parseCriteria(
                "eventType EQ PROCESS",
                AuditLogFields.ALLOWED_FIELDS,
                AuditLogFields.NO_ARG_OPS,
                Collections.emptySet(),
                AuditLogFields.LONG_FIELDS,
                AuditLogFields.DATE_FIELDS
        );
        final QueryCriteria qc = QueryCriteria
                .create()
                .add(term)
                .add(Criteria.orderDesc(AuditRecordData.FIELD_TIMESTAMP));

        final Set<String> devices = getAuditorSession().getQuerySupportingLogDevices();
        if (devices.isEmpty()) {
            throw new Exception("No log devices available for querying");
        }
        final String device = devices.stream().findFirst().get();
        List<? extends AuditLogEntry> logs = WORKER_SESSION.selectAuditLogs(0, numRows, qc, device);
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

    private int countPriorityHits(final int numRows, final String priorityToMatch) throws Exception {
        final List<Map<String, Object>> lastLogFields = queryLastLogFields(numRows);
        int count = 0;
        for (Map<String, Object> details : lastLogFields) {
            final String priority = (String) details.get(QoSFilterProperties.QOS_PRIORITY);
            if (priorityToMatch.equals(priority)) {
                count++;
            }
        }
        return count;
    }

    private ClientWS createClientWSService() {
        // Configure Endpoint
        final String endpointName = "ClientWSService";
        final String endpointUrl = "https://" + getHTTPHost() + ":" + getPublicHTTPSPort() + "/signserver/" +
                endpointName + "/ClientWS?wsdl";
        final String endpointWsdl = "META-INF/wsdl/localhost_8080/signserver/" + endpointName + "/ClientWS.wsdl";
        //
        final QName qname = new QName("http://clientws.signserver.org/", endpointName);
        final URL resource = ClientWS.class.getResource(endpointWsdl);
        final ClientWSService clientWSService = new ClientWSService(resource, qname);
        // Create an instance of WS
        final ClientWS ws = clientWSService.getClientWSPort();
        // Define binding
        final BindingProvider bp = (BindingProvider) ws;
        final Map<String, Object> requestContext = bp.getRequestContext();
        requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, endpointUrl);
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
        return ws;
    }
}
