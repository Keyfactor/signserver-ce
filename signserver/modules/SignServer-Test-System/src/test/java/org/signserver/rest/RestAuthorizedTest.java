package org.signserver.rest;

import io.restassured.http.Method;
import io.restassured.response.Response;
import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.cli.CommandLineInterface;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.RestTestUtils;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;


/**
 * System test for testing authorization for the REST API.
 *
 * @version $Id$
 */
public class RestAuthorizedTest extends ModulesTestCase {
    private static final int HELLO_WORKER_ID = 80005;
    private static final String HELLO_WORKER_NAME = "HelloWorker_REST_Authorized";

    private static final Logger LOG = Logger.getLogger(RestAuthorizedTest.class);
    private static final ModulesTestCase mt = new ModulesTestCase();
    private static final CLITestHelper cli = mt.getAdminCLI();

    private final RestTestUtils rtu = new RestTestUtils();

    @BeforeClass
    public static void setUp() throws UnexpectedCommandFailureException, IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, cli.execute("wsadmins", "-allowany", String.valueOf(false)));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("wsadmins", "-add", "-certserialno", mt.getAdminOneSerialNumber(),
                        "-issuerdn", mt.getAdminOneIssuerDn()));
    }

    @AfterClass
    public static void tearDown() throws UnexpectedCommandFailureException, IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("wsadmins", "-remove", "-certserialno", mt.getAdminOneSerialNumber(),
                        "-issuerdn", mt.getAdminOneIssuerDn()));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("wsadmins", "-allowany"));
    }


    /**
     * Test authorized REST call to add worker without ID.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testAuthorizedRestPostAddWorkerWithoutID() throws Exception {
        LOG.debug("testAuthorizedRestPostAddWorkerWithoutID");
        int workerID = 0;
        try {
            final Response response = mt.callRest(
                    Method.POST,
                    201,
                    "",
                    "/workers/",
                    rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME),
                    mt.getAuthorizedStore());

            workerID = getWorkerSession().getWorkerId(HELLO_WORKER_NAME);
            assertNotEquals("Check new worker created with a new worker ID", 0, workerID);
            assertEquals("Check response status code 201", 201, response.statusCode());
        } finally {
            removeWorker(workerID);
        }
    }

    /**
     * Test authorized REST POST call to add worker by ID.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testAuthorizedRestPostAddWorkerWithID() throws Exception {
        LOG.debug("testAuthorizedRestPostAddWorkerWithID");
        int workerID = 0;
        try {
            final Response response = mt.callRest(
                    Method.POST,
                    201,
                    "",
                    "/workers/" + HELLO_WORKER_ID,
                    rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME),
                    mt.getAuthorizedStore());

            workerID = getWorkerSession().getWorkerId(HELLO_WORKER_NAME);
            assertNotEquals("Check new worker created with a new worker ID", 0, workerID);
            assertEquals("Check response status code 201", 201, response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test authorized REST PATCH worker to update the properties.
     */
    @Test
    public void testAuthorizedRestPatchWorker() throws Exception {
        LOG.debug("testAuthorizedRestPatchWorker");

        try {
            mt.callRest(Method.POST, 201, "", "/workers/" + HELLO_WORKER_ID, rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME), mt.getAuthorizedStore());
            final Response response = mt.callRest(
                    Method.PATCH,
                    200,
                    "application/json",
                    "/workers/" + HELLO_WORKER_ID,
                    rtu.createPatchWorkerEditRequestJsonBody(),
                    mt.getAuthorizedStore());

            assertEquals("value1", getWorkerSession().getCurrentWorkerConfig(HELLO_WORKER_ID).getProperties().getProperty("PROPERTY1"));
            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertTrue("Response message: " + responseJsonObject, responseJsonObject.toString().contains("Worker properties successfully updated"));
            assertEquals("Check response status code is 200.", 200, response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test authorized REST PUT worker to replace all worker properties.
     */
    @Test
    public void testAuthorizedRestPutWorker() throws Exception {
        LOG.debug("testAuthorizedRestPutWorker");

        try {
            mt.callRest(Method.POST, 201, "", "/workers/" + HELLO_WORKER_ID, rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME), mt.getAuthorizedStore());
            final Response response = mt.callRest(
                    Method.PUT,
                    200,
                    "application/json",
                    "/workers/" + HELLO_WORKER_ID,
                    rtu.createPutWorkerReplaceRequestJsonBody(HELLO_WORKER_NAME),
                    mt.getAuthorizedStore());

            assertEquals("Properties Replaced!", getWorkerSession().getCurrentWorkerConfig(HELLO_WORKER_ID).getProperties().getProperty("GREETING"));
            assertEquals(null, getWorkerSession().getCurrentWorkerConfig(HELLO_WORKER_ID).getProperties().getProperty("AUTHTYPE"));
            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertTrue("Response message: " + responseJsonObject, responseJsonObject.toString().contains("Worker properties successfully replaced"));
            assertEquals("Check response status code 200", 200, response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test authorized REST DELETE worker.
     */
    @Test
    public void testAuthorizedDeleteWorker() throws Exception {
        LOG.debug("testAuthorizedDeleteWorker");
        try {
            mt.callRest(Method.POST, 201, "", "/workers/" + HELLO_WORKER_ID, rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME), mt.getAuthorizedStore());
            final Response response = mt.callRest(
                    Method.DELETE,
                    200,
                    "application/json",
                    "/workers/" + HELLO_WORKER_ID,
                    new JSONObject(),
                    mt.getAuthorizedStore());

            assertFalse("Check worker with the given worker name removed", getWorkerSession().getAllWorkers().contains(HELLO_WORKER_ID));
            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertTrue("Response message: " + responseJsonObject, responseJsonObject.toString().contains("Worker removed successfully"));
            assertEquals("Check response status code 200", 200, response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }
}
