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

/**
 * System test for testing not authorized calls for the REST API.
 *
 * @version $Id$
 */
public class RestUnauthorizedTest extends ModulesTestCase {
    private static final int HELLO_WORKER_ID = 80006;
    private static final String HELLO_WORKER_NAME = "HelloWorker_REST_Unauthorized";

    private static final Logger LOG = Logger.getLogger(RestUnauthorizedTest.class);
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
                rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME),
                mt.getUnauthorizedStore());

        assertEquals("Check response status code is 401.", 401, response.statusCode());
    }

    /**
     * Test unauthorized REST call to add worker without ID on Public HTTPS.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testUnauthorizedRestPostAddWorkerWithoutIDOnPublicHTTPS() throws Exception {
        LOG.debug("testUnauthorizedRestPostAddWorkerWithoutIDOnPublicHTTPS");
        final Response response = mt.callRestOnPublicHTTPS(
                Method.POST,
                401,
                "",
                "/workers/",
                rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME),
                mt.getUnauthorizedStore());

        assertEquals("Check response status code is 401.", 401, response.statusCode());
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
                    rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME),
                    mt.getUnauthorizedStore());
            assertEquals("Check response status code is 401.", 401, response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test unauthorized REST POST call to add worker by ID on Public HTTPS.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testUnauthorizedRestPostAddWorkerWithIDOnPublicHTTPS() throws Exception {
        LOG.debug("testUnauthorizedRestPostAddWorkerWithIDOnPublicHTTPS");
        try {
            final Response response = mt.callRestOnPublicHTTPS(
                    Method.POST,
                    401,
                    "",
                    "/workers/" + HELLO_WORKER_ID,
                    rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME),
                    mt.getUnauthorizedStore());
            assertEquals("Check response status code is 401.", 401, response.statusCode());
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
            mt.callRest(Method.POST, 201, "", "/workers/" + HELLO_WORKER_ID, rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME), mt.getAuthorizedStore());
            final Response response = mt.callRest(
                    Method.PATCH,
                    401,
                    "application/json",
                    "/workers/" + HELLO_WORKER_ID,
                    rtu.createPatchWorkerEditRequestJsonBody(),
                    mt.getUnauthorizedStore());

            assertEquals("Check response status code 401", 401, response.statusCode());
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
            mt.callRest(Method.POST, 201, "", "/workers/" + HELLO_WORKER_ID, rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME), mt.getAuthorizedStore());
            final Response response = mt.callRest(
                    Method.PUT,
                    401,
                    "application/json",
                    "/workers/" + HELLO_WORKER_ID,
                    rtu.createPutWorkerReplaceRequestJsonBody(HELLO_WORKER_NAME),
                    mt.getUnauthorizedStore());

            assertEquals("Check response status code is 401.", 401, response.statusCode());
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
            mt.callRest(Method.POST, 201, "", "/workers/" + HELLO_WORKER_ID, rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME), mt.getAuthorizedStore());
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
}
