package org.signserver.rest;

import io.restassured.http.Method;
import io.restassured.response.Response;
import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.junit.Test;
import org.signserver.testutils.ModulesTestCase;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


/**
 * System test for testing authorization for the REST API.
 *
 * @version $Id$
 */
public class RestAuthorizationTest extends ModulesTestCase {
    private static final int HELLO_WORKER_ID = 80004;
    private static final String HELLO_WORKER_NAME = "HelloWorker_REST";

    private static final Logger LOG = Logger.getLogger(RestAuthorizationTest.class);
    private static final ModulesTestCase mt = new ModulesTestCase();

    private JSONObject createPostWorkerAddRequestJsonBody() {
        JSONObject properties = new JSONObject();
        properties.put("NAME", HELLO_WORKER_NAME);
        properties.put("TYPE", "PROCESSABLE");
        properties.put("AUTHTYPE", "NOAUTH");
        properties.put("GREETING", "Hi");
        properties.put("IMPLEMENTATION_CLASS", "org.signserver.module.sample.workers.HelloWorker");

        JSONObject patchRequestJsonBody = new JSONObject();
        patchRequestJsonBody.put("properties", properties);

        return patchRequestJsonBody;
    }

    private JSONObject createPatchWorkerEditRequestJsonBody() {
        JSONObject properties = new JSONObject();
        properties.put("property1", "value1");
        properties.put("-GREETING", "");

        JSONObject patchRequestJsonBody = new JSONObject();
        patchRequestJsonBody.put("properties", properties);

        return patchRequestJsonBody;
    }


    private JSONObject createPutWorkerReplaceRequestJsonBody() {
        JSONObject properties = new JSONObject();
        properties.put("NAME", HELLO_WORKER_NAME);
        properties.put("TYPE", "PROCESSABLE");
        properties.put("GREETING", "Properties Replaced!");
        properties.put("IMPLEMENTATION_CLASS", "org.signserver.module.sample.workers.HelloWorker");

        JSONObject patchRequestJsonBody = new JSONObject();
        patchRequestJsonBody.put("properties", properties);

        return patchRequestJsonBody;
    }

    /**
     * Test unauthorized REST call to add worker without ID.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testUnauthorizedRestPostAddWorkerWithoutID() throws Exception {
        LOG.debug("testUnauthorizedRestPostAddWorkerWithoutID");
        final Response response = mt.callRest(
                Method.POST,
                401,
                "",
                "/workers/",
                createPostWorkerAddRequestJsonBody(),
                mt.getUnauthorizedStore());

        assertEquals("Check response status code is 401.", 401, response.statusCode());
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
                    createPostWorkerAddRequestJsonBody(),
                    mt.getAuthorizedStore());

            workerID = getWorkerSession().getWorkerId("HelloWorker_REST");
            assertTrue("Check new worker created with a new worker ID", workerID != 0);
            assertEquals("Check response status code 201", 201, response.statusCode());
        } finally {
            removeWorker(workerID);
        }
    }

    /**
     * Test unauthorized REST POST call to add worker by ID.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testUnauthorizedRestPostAddWorkerWithID() throws Exception {
        LOG.debug("testUnauthorizedRestPostAddWorkerWithID");
        try {
            final Response response = mt.callRest(
                    Method.POST,
                    401,
                    "",
                    "/workers/" + HELLO_WORKER_ID,
                    createPostWorkerAddRequestJsonBody(),
                    mt.getUnauthorizedStore());
            assertEquals("Check response status code is 401.", 401, response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
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
                    createPostWorkerAddRequestJsonBody(),
                    mt.getAuthorizedStore());

            workerID = getWorkerSession().getWorkerId("HelloWorker_REST");
            assertTrue("Check new worker created with a new worker ID", workerID != 0);
            assertEquals("Check response status code 201", 201, response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test unauthorized REST PATCH worker to update the properties.
     */
    @Test
    public void testUnauthorizedRestPatchWorker() throws Exception {
        LOG.debug("testUnauthorizedRestPatchWorker");

        try {
            mt.callRest(Method.POST, 201, "", "/workers/" + HELLO_WORKER_ID, createPostWorkerAddRequestJsonBody(), mt.getAuthorizedStore());
            final Response response = mt.callRest(
                    Method.PATCH,
                    401,
                    "application/json",
                    "/workers/" + HELLO_WORKER_ID,
                    createPatchWorkerEditRequestJsonBody(),
                    mt.getUnauthorizedStore());

            assertEquals("Check response status code 401", 401, response.statusCode());
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
            mt.callRest(Method.POST, 201, "", "/workers/" + HELLO_WORKER_ID, createPostWorkerAddRequestJsonBody(), mt.getAuthorizedStore());
            final Response response = mt.callRest(
                    Method.PATCH,
                    200,
                    "application/json",
                    "/workers/" + HELLO_WORKER_ID,
                    createPatchWorkerEditRequestJsonBody(),
                    mt.getAuthorizedStore());

            assertEquals("value1", getWorkerSession().getCurrentWorkerConfig(HELLO_WORKER_ID).getProperties().getProperty("PROPERTY1"));
            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertTrue("Response contains the correct message", responseJsonObject.toString().contains("Worker properties successfully updated"));
            assertEquals("Check response status code is 200.", 200, response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test unauthorized REST PUT worker to replace all worker properties.
     */
    @Test
    public void testUnauthorizedRestPutWorker() throws Exception {
        LOG.debug("testUnauthorizedRestPutWorker");

        try {
            mt.callRest(Method.POST, 201, "", "/workers/" + HELLO_WORKER_ID, createPostWorkerAddRequestJsonBody(), mt.getAuthorizedStore());
            final Response response = mt.callRest(
                    Method.PUT,
                    401,
                    "application/json",
                    "/workers/" + HELLO_WORKER_ID,
                    createPutWorkerReplaceRequestJsonBody(),
                    mt.getUnauthorizedStore());

            assertEquals("Check response status code is 401.", 401, response.statusCode());
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
            mt.callRest(Method.POST, 201, "", "/workers/" + HELLO_WORKER_ID, createPostWorkerAddRequestJsonBody(), mt.getAuthorizedStore());
            final Response response = mt.callRest(
                    Method.PUT,
                    200,
                    "application/json",
                    "/workers/" + HELLO_WORKER_ID,
                    createPutWorkerReplaceRequestJsonBody(),
                    mt.getAuthorizedStore());

            assertEquals("Properties Replaced!", getWorkerSession().getCurrentWorkerConfig(HELLO_WORKER_ID).getProperties().getProperty("GREETING"));
            assertEquals(null, getWorkerSession().getCurrentWorkerConfig(HELLO_WORKER_ID).getProperties().getProperty("AUTHTYPE"));
            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertTrue("Response contains the correct message", responseJsonObject.toString().contains("Worker properties successfully replaced"));
            assertEquals("Check response status code 200", 200, response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test unauthorized REST DELETE worker.
     */
    @Test
    public void testUnauthorizedDeleteWorker() throws Exception {
        LOG.debug("testUnauthorizedDeleteWorker");
        try {
            mt.callRest(Method.POST, 201, "", "/workers/" + HELLO_WORKER_ID, createPostWorkerAddRequestJsonBody(), mt.getAuthorizedStore());
            final Response response = mt.callRest(
                    Method.DELETE,
                    401,
                    "application/json",
                    "/workers/" + HELLO_WORKER_ID,
                    new JSONObject(),
                    mt.getUnauthorizedStore());

            assertEquals("Check response status code is 401.", 401, response.statusCode());
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
            mt.callRest(Method.POST, 201, "", "/workers/" + HELLO_WORKER_ID, createPostWorkerAddRequestJsonBody(), mt.getAuthorizedStore());
            final Response response = mt.callRest(
                    Method.DELETE,
                    200,
                    "application/json",
                    "/workers/" + HELLO_WORKER_ID,
                    new JSONObject(),
                    mt.getAuthorizedStore());

            assertFalse("Check worker with the given worker name removed", getWorkerSession().getAllWorkers().contains(HELLO_WORKER_ID));
            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertTrue("Response contains the correct message", responseJsonObject.toString().contains("Worker removed successfully!"));
            assertEquals("Check response status code 200", 200, response.statusCode());
            assertEquals("Check response status code is 200.", 200, response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }
}
