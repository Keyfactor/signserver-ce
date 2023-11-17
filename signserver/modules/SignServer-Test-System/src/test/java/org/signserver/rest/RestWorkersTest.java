package org.signserver.rest;

import io.restassured.RestAssured;
import io.restassured.config.SSLConfig;
import io.restassured.response.Response;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.json.simple.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.util.PathUtil;
import org.signserver.module.cmssigner.CMSSigner;
import org.signserver.module.cmssigner.PlainSigner;
import org.signserver.module.pdfsigner.PDFSigner;
import org.signserver.testutils.ModulesTestCase;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;


/**
 * System tests for the REST API - Workers.
 *
 * @version $Id$
 */
public class RestWorkersTest extends ModulesTestCase {
    private String baseURL;
    private String baseHttpsURL;
    private static final int PDFSIGNER_WORKER_ID = 80001;
    private static final String PDFSIGNER_WORKER_NAME = "PDFSigner_REST";
    private static final int CMSSIGNER_WORKER_ID = 80002;
    private static final String CMSSIGNER_WORKER_NAME = "CMSSigner_REST";
    private static final int PLAINSIGNER_WORKER_ID = 80003;
    private static final String PLAINSIGNER_WORKER_NAME = "PlainSigner_REST";
    private static final int HELLO_WORKER_ID = 80004;
    private static final String HELLO_WORKER_NAME = "HelloWorker_REST";

    private static final Logger LOG = Logger.getLogger(RestWorkersTest.class);
    private static final ModulesTestCase moduleTestCase = new ModulesTestCase();

    @Before
    public void setUp() throws FileNotFoundException {
        baseURL = getSignServerBaseURL() + "/rest/v1";
        baseHttpsURL = "https://" + moduleTestCase.getHTTPHost() + ":" + moduleTestCase.getPrivateHTTPSPort() + "/signserver/rest/v1";

        RestAssured.config = RestAssured.config().sslConfig(new SSLConfig()
                .keyStore(moduleTestCase.getSignServerHome().getAbsolutePath() + "/res/test/dss10/dss10_admin1.p12", "foo123")
                .trustStore(moduleTestCase.getSignServerHome().getAbsolutePath() + "/p12/truststore.jks", "changeit"));
    }

    /**
     * Generate a test Json Object with sample data, metaData in it.
     */
    private JSONObject createPostProcessRequestJsonBody() {
        JSONObject metaData = new JSONObject();
        metaData.put("name1", "value1");
        metaData.put("name2", "value2");

        JSONObject postRequestJsonBody = new JSONObject();
        postRequestJsonBody.put("metaData", metaData);
        postRequestJsonBody.put("data", "Sample Text!");

        return postRequestJsonBody;
    }

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
     * Generate a test Json Object from a sample PDF file, metaData and encoding base64 in it.
     *
     * @throws IOException in case of error
     */
    private JSONObject createPostRequestJsonBodyPDF() throws IOException {

        File home;
        home = PathUtil.getAppHome();
        File samplePdf = new File(home, "res/test/pdf/sample.pdf");
        String base64DataString = Base64.toBase64String(FileUtils.readFileToByteArray(samplePdf));

        JSONObject metaData = new JSONObject();
        metaData.put("name1", "value1");
        metaData.put("name2", "value2");

        JSONObject postRequestJsonBody = new JSONObject();
        postRequestJsonBody.put("encoding", "BASE64");
        postRequestJsonBody.put("metaData", metaData);
        postRequestJsonBody.put("data", base64DataString);

        return postRequestJsonBody;
    }

    /**
     * Test REST POST workers process by worker name, signing data string with CMSSigner.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersCMSSignerProcess() throws Exception {
        LOG.debug("testRestPostWorkersCMSSignerProcess");
        try {
            addSigner(CMSSigner.class.getName(), CMSSIGNER_WORKER_ID, CMSSIGNER_WORKER_NAME, true);
            // Check statusCode is 200 and response content type is json
            Response response = given()
                    .contentType(JSON)
                    .accept(JSON)
                    .body(createPostProcessRequestJsonBody())
                    .when()
                    .post(baseURL + "/workers/" + CMSSIGNER_WORKER_NAME + "/process")
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));

            assertEquals("Check response status code is 200.", 200, response.statusCode());
            assertTrue("Check response contains archiveId.", responseJsonObject.containsKey("archiveId"));
        } finally {
            removeWorker(CMSSIGNER_WORKER_ID);
        }
    }

    /**
     * Test REST POST workers process by worker name, signing data string with PlainSigner.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersPlainSignerProcess() throws Exception {
        LOG.debug("testRestPostWorkersPlainSignerProcess");
        try {
            addSigner(PlainSigner.class.getName(), PLAINSIGNER_WORKER_ID, PLAINSIGNER_WORKER_NAME, true);
            // Check statusCode is 200 and response content type is json
            Response response = given()
                    .contentType(JSON)
                    .accept(JSON)
                    .body(createPostProcessRequestJsonBody())
                    .when()
                    .post(baseURL + "/workers/" + PLAINSIGNER_WORKER_NAME + "/process")
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));

            assertEquals("Check response status code is 200.", 200, response.statusCode());
            assertTrue("Check response contains archiveId.", responseJsonObject.containsKey("archiveId"));
        } finally {
            removeWorker(PLAINSIGNER_WORKER_ID);
        }
    }


    /**
     * Test REST POST workers process by worker ID, signing a pdf file sending to PDFSigner in base64 encoded form.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersPDFSignerProcess() throws Exception {
        LOG.debug("testRestPostWorkersPDFSignerProcess");
        try {
            addSigner(PDFSigner.class.getName(), PDFSIGNER_WORKER_ID, PDFSIGNER_WORKER_NAME, true);

            Response response = given()
                    .contentType(JSON)
                    .accept(JSON)
                    .body(createPostRequestJsonBodyPDF())
                    .when()
                    .post(baseURL + "/workers/" + PDFSIGNER_WORKER_ID + "/process")
                    .then()
                    //.statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));

            assertEquals("Check response status code.", 200, response.statusCode());
            assertTrue("Check response contains archiveId.", responseJsonObject.containsKey("archiveId"));

            byte[] responsePDFBytes = Base64.decode(responseJsonObject.get("data").toString());
            String responsePDFString = new String(responsePDFBytes);

            assertTrue("Check response PDF file contains signature and SignServer.",
                    responsePDFString.contains("Signature") && responsePDFString.contains("SignServer"));
        } finally {
            removeWorker(PDFSIGNER_WORKER_ID);
        }
    }

    /**
     * Test REST POST workers process by worker name, signing data string with
     * PlainSigner without metadata.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersPlainSignerProcessWithoutMetadata() throws Exception {
        LOG.debug("testRestPostWorkersPlainSignerProcessWithoutMetadata");
        try {
            addSigner(PlainSigner.class.getName(), PLAINSIGNER_WORKER_ID, PLAINSIGNER_WORKER_NAME, true);

            // Body without metaData
            JSONObject body = new JSONObject();
            body.put("data", "Sample Text!");

            // Check statusCode is 200 and response content type is json
            Response response = given()
                    .contentType(JSON)
                    .accept(JSON)
                    .body(body)
                    .when()
                    .post(baseURL + "/workers/" + PLAINSIGNER_WORKER_NAME + "/process")
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertTrue("Check response contains archiveId.", responseJsonObject.containsKey("archiveId"));
        } finally {
            removeWorker(PLAINSIGNER_WORKER_ID);
        }
    }

    /**
     * Test REST POST workers process by worker name, signing data string with
     * PlainSigner without metadata.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersPlainSignerProcessWithoutData() throws Exception {
        LOG.debug("testRestPostWorkersPlainSignerProcessWithoutData");
        try {
            addSigner(PlainSigner.class.getName(), PLAINSIGNER_WORKER_ID, PLAINSIGNER_WORKER_NAME, true);

            // Body without metaData
            JSONObject metaData = new JSONObject();
            metaData.put("name1", "value1");
            metaData.put("name2", "value2");
            JSONObject body = new JSONObject();
            body.put("metaData", metaData);

            // Check statusCode is 200 and response content type is json
            Response response = given()
                    .contentType(JSON)
                    .accept(JSON)
                    .body(body)
                    .when()
                    .post(baseURL + "/workers/" + PLAINSIGNER_WORKER_NAME + "/process")
                    .then()
                    .statusCode(400)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertTrue("Check response contains archiveId.", responseJsonObject.containsKey("error"));
        } finally {
            removeWorker(PLAINSIGNER_WORKER_ID);
        }
    }

    /**
     * Test REST POST with a worker that is non-existent. Should return status code 404
     */
    @Test
    public void testRestNoSuchWorkerExceptionStatusCode() {
        LOG.debug("testRestNoSuchWorkerExceptionStatusCode");
        Response response = given()
                .contentType(JSON)
                .accept(JSON)
                .body(createPostProcessRequestJsonBody())
                .when()
                .post(baseURL + "/workers/" + "nosuchworker101" + "/process")
                .then()
                .statusCode(404)
                .contentType("application/json")
                .extract().response();

        JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));

        assertEquals("Check response status code is 404.", 404, response.statusCode());
        assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));
    }

    /**
     * Test REST POST with an offline crypto token. Should return status code 503
     */
    @Test
    public void testRestCryptoTokenOfflineExceptionStatusCode() throws Exception {
        LOG.debug("testRestCryptoTokenOfflineExceptionStatusCode");
        try {
            addSigner(CMSSigner.class.getName(), CMSSIGNER_WORKER_ID, CMSSIGNER_WORKER_NAME, false);
            Response response = given()
                    .contentType(JSON)
                    .accept(JSON)
                    .body(createPostProcessRequestJsonBody())
                    .when()
                    .post(baseURL + "/workers/" + CMSSIGNER_WORKER_NAME + "/process")
                    .then()
                    .statusCode(503)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));

            assertEquals("Check response status code is 503.", 503, response.statusCode());
            assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));
        } finally {
            removeWorker(CMSSIGNER_WORKER_ID);
        }
    }

    /**
     * Test REST POST with an empty body. Should return status code 400
     */
    @Test
    public void testRestIllegalRequestExceptionStatusCode() throws Exception {
        LOG.debug("testRestIllegalRequestExceptionStatusCode");
        try {
            addSigner(CMSSigner.class.getName(), CMSSIGNER_WORKER_ID, CMSSIGNER_WORKER_NAME, true);
            JSONObject body = new JSONObject();
            Response response = given()
                    .contentType(JSON)
                    .accept(JSON)
                    .body(body)
                    .when()
                    .post(baseURL + "/workers/" + CMSSIGNER_WORKER_NAME + "/process")
                    .then()
                    .statusCode(400)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));

            assertEquals("Check response status code is 400.", 400, response.statusCode());
            assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));
        } finally {
            removeWorker(CMSSIGNER_WORKER_ID);
        }
    }

    /**
     * Test REST POST with an CMSSigner that is missing a crucial worker property. Should return status code 500
     */
    @Test
    public void testInternalServerExceptionStatusCode() throws Exception {
        LOG.debug("testInternalServerExceptionStatusCode");
        try {
            addSigner(CMSSigner.class.getName(), CMSSIGNER_WORKER_ID, CMSSIGNER_WORKER_NAME, true);
            getWorkerSession().removeWorkerProperty(CMSSIGNER_WORKER_ID, "IMPLEMENTATION_CLASS");
            getWorkerSession().reloadConfiguration(CMSSIGNER_WORKER_ID);
            Response response = given()
                    .contentType(JSON)
                    .accept(JSON)
                    .body(createPostProcessRequestJsonBody())
                    .when()
                    .post(baseURL + "/workers/" + CMSSIGNER_WORKER_NAME + "/process")
                    .then()
                    .statusCode(500)
                    .contentType("application/json")
                    .extract().response();
            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));

            assertEquals("Check response status code is 500.", 500, response.statusCode());
            assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));
        } finally {
            removeWorker(CMSSIGNER_WORKER_ID);
        }
    }

    /**
     * Test REST POST as an unauthorized user. Should return status code 401
     */
    @Test
    public void testRestRequestFailedExceptionStatusCode() throws Exception {
        LOG.debug("testRestRequestFailedExceptionStatusCode");
        try {
            addSigner(CMSSigner.class.getName(), CMSSIGNER_WORKER_ID, CMSSIGNER_WORKER_NAME, true);
            getWorkerSession().setWorkerProperty(CMSSIGNER_WORKER_ID, "AUTHTYPE", "org.signserver.server.UsernameAuthorizer");
            getWorkerSession().setWorkerProperty(CMSSIGNER_WORKER_ID, "ACCEPT_USERNAMES", "nonuser");
            getWorkerSession().reloadConfiguration(CMSSIGNER_WORKER_ID);
            Response response = given()
                    .contentType(JSON)
                    .accept(JSON)
                    .body(createPostProcessRequestJsonBody())
                    .when()
                    .post(baseURL + "/workers/" + CMSSIGNER_WORKER_ID + "/process")
                    .then()
                    .statusCode(401)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));

            assertEquals("Check response status code 401.", 401, response.statusCode());
            assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));
        } finally {
            removeWorker(CMSSIGNER_WORKER_ID);
        }
    }

    /**
     * Test REST POST to create a worker with provided properties and worker ID.
     */
    @Test
    public void testRestPostAddWorkerWithID() {
        LOG.debug("testRestPostAddWorkerWithID");

        try {
            Response response = given()
                    .relaxedHTTPSValidation()
                    .contentType(JSON)
                    .accept(JSON)
                    .body(createPostWorkerAddRequestJsonBody())
                    .when()
                    .post(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(201)
                    .extract().response();

            assertEquals("HelloWorker_REST", getWorkerSession().getCurrentWorkerConfig(HELLO_WORKER_ID).getProperties().getProperty("NAME"));
            assertEquals("Check response status code 201", 201, response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test REST POST to create a worker with provided properties.
     */
    @Test
    public void testRestPostAddWorkerWithoutID() throws InvalidWorkerIdException {
        LOG.debug("testRestPostAddWorkerWithoutID");
        int workerID = 0;
        try {
            Response response = given()
                    .relaxedHTTPSValidation()
                    .contentType(JSON)
                    .accept(JSON)
                    .body(createPostWorkerAddRequestJsonBody())
                    .when()
                    .post(baseHttpsURL + "/workers")
                    .then()
                    .statusCode(201)
                    .extract().response();

            workerID = getWorkerSession().getWorkerId("HelloWorker_REST");
            assertTrue("Check new worker created with a new worker ID", workerID != 0);
            assertEquals("Check response status code 201", 201, response.statusCode());
        } finally {
            removeWorker(workerID);
        }
    }

    /**
     * Test REST PATCH worker to update the properties.
     */
    @Test
    public void testRestPatchWorker() {
        LOG.debug("testRestPatchWorker");

        try {
            Response response = given()
                    .relaxedHTTPSValidation()
                    .contentType(JSON)
                    .accept(JSON)
                    .body(createPostWorkerAddRequestJsonBody())
                    .when()
                    .post(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(201)
                    .extract().response();

            assertEquals("Check response status code 201", 201, response.statusCode());
            assertEquals("Check there is no worker property called PROPERTY1",
                    null, getWorkerSession().getCurrentWorkerConfig(HELLO_WORKER_ID).getProperties().getProperty("PROPERTY1"));

            response = given()
                    .relaxedHTTPSValidation()
                    .contentType(JSON)
                    .accept(JSON)
                    .body(createPatchWorkerEditRequestJsonBody())
                    .when()
                    .patch(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            assertEquals("value1", getWorkerSession().getCurrentWorkerConfig(HELLO_WORKER_ID).getProperties().getProperty("PROPERTY1"));
            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertTrue("Response contains the correct message", responseJsonObject.toString().contains("Worker properties successfully updated"));
            assertEquals("Check response status code 200", 200, response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test REST PUT worker to replace all worker properties.
     */
    @Test
    public void testRestPutWorker() {
        LOG.debug("testRestPutWorker");

        try {

            Response response = given()
                    .relaxedHTTPSValidation()
                    .contentType(JSON)
                    .accept(JSON)
                    .body(createPostWorkerAddRequestJsonBody())
                    .when()
                    .post(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(201)
                    .extract().response();

            assertEquals("Check response status code 201", 201, response.statusCode());
            assertEquals("Check worker property before replace",
                    "Hi", getWorkerSession().getCurrentWorkerConfig(HELLO_WORKER_ID).getProperties().getProperty("GREETING"));
            assertEquals("Check worker property before replace",
                    "NOAUTH", getWorkerSession().getCurrentWorkerConfig(HELLO_WORKER_ID).getProperties().getProperty("AUTHTYPE"));

            response = given()
                    .relaxedHTTPSValidation()
                    .contentType(JSON)
                    .accept(JSON)
                    .body(createPutWorkerReplaceRequestJsonBody())
                    .when()
                    .put(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

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
     * Test REST DELETE worker.
     */
    @Test
    public void testRestDeleteWorker() throws InvalidWorkerIdException {
        LOG.debug("testRestDeleteWorker");

        try {
            Response response = given()
                    .relaxedHTTPSValidation()
                    .contentType(JSON)
                    .accept(JSON)
                    .body(createPostWorkerAddRequestJsonBody())
                    .when()
                    .post(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(201)
                    .extract().response();

            assertEquals("Check response status code 201", 201, response.statusCode());
            assertTrue("Check worker with the given worker name created", getWorkerSession().getAllWorkers().contains(HELLO_WORKER_ID));

            response = given()
                    .relaxedHTTPSValidation()
                    .accept(JSON)
                    .when()
                    .delete(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            assertFalse("Check worker with the given worker name removed", getWorkerSession().getAllWorkers().contains(HELLO_WORKER_ID));
            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertTrue("Response contains the correct message", responseJsonObject.toString().contains("Worker removed successfully!"));
            assertEquals("Check response status code 200", 200, response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }
}
