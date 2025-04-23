package org.signserver.rest;

import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import io.restassured.RestAssured;
import static io.restassured.RestAssured.given;
import io.restassured.builder.MultiPartSpecBuilder;
import io.restassured.config.SSLConfig;

import static io.restassured.http.ContentType.ANY;
import static io.restassured.http.ContentType.JSON;
import io.restassured.response.Response;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.json.simple.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.module.cmssigner.CMSSigner;
import org.signserver.module.cmssigner.PlainSigner;
import org.signserver.module.pdfsigner.PDFSigner;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.RestTestUtils;

import java.io.File;
import java.io.FileNotFoundException;

import static io.restassured.http.ContentType.MULTIPART;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;


/**
 * System tests for the REST API - Workers.
 *
 * @version $Id$
 */
public class RestWorkersTest extends ModulesTestCase {
    private String baseURL;
    private String baseHttpsURL;
    private final RestTestUtils rtu = new RestTestUtils();
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
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPostProcessRequestJsonBody())
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
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPostProcessRequestJsonBody())
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
     * Test REST POST workers process by worker name that uploads and signs a txt file with PlainSigner.
     * This test checks that all expected response fields are present in the response.
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersPlainSignerProcessMultiPart() throws Exception {
        LOG.debug("testRestPostWorkersPlainSignerProcessMultiPart");
        try {
            addSigner(PlainSigner.class.getName(), PLAINSIGNER_WORKER_ID, PLAINSIGNER_WORKER_NAME, true);
            // Check statusCode is 200 and response content type is json
            Response response = given()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(MULTIPART)
                    .accept(JSON)
                    .multiPart("txt", rtu.createPostRequestFormDataBody("res/test/HelloDeb.txt"))
                    .when()
                    .post(baseURL + "/workers/" + PLAINSIGNER_WORKER_NAME + "/process")
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();


            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));

            assertEquals("Check response status code is 200.", 200, response.statusCode());
            assertTrue("Check response contains data.", responseJsonObject.containsKey("data"));
            assertTrue("Check response contains archiveId.", responseJsonObject.containsKey("archiveId"));
            assertTrue("Check response contains metaData.", responseJsonObject.containsKey("metaData"));
            assertTrue("Check response contains requestId.", responseJsonObject.containsKey("requestId"));
            assertTrue("Check response contains signerCertificate.", responseJsonObject.containsKey("signerCertificate"));
        } finally {
            removeWorker(PLAINSIGNER_WORKER_ID);
        }
    }

    /**
     * Test REST POST workers process by worker name that uploads and signs a txt file with PlainSigner and a file
     * is returned.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersPlainSignerProcessMultiPartOctetStream() throws Exception {
        LOG.debug("testRestPostWorkersPlainSignerProcessMultiPartOctetStream");
        try {
            addSigner(PlainSigner.class.getName(), PLAINSIGNER_WORKER_ID, PLAINSIGNER_WORKER_NAME, true);
            // Check statusCode is 200 and response content type is json
            Response response = given()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(MULTIPART)
                    .accept("application/octet-stream")
                    .multiPart("txt", rtu.createPostRequestFormDataBody("res/test/HelloDeb.txt"))
                    .when()
                    .post(baseURL + "/workers/" + PLAINSIGNER_WORKER_NAME + "/process")
                    .then()
                    .statusCode(200)
                    .contentType("application/octet-stream")
                    .extract().response();

            assertTrue(response.contentType().equals("application/octet-stream"));

            assertEquals("Check response status code is 200.", 200, response.statusCode());
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
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPostRequestJsonBodyPDF())
                    .when()
                    .post(baseURL + "/workers/" + PDFSIGNER_WORKER_ID + "/process")
                    .then()
                    .statusCode(200)
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
     * Test REST POST workers process by uploading a file that exceeds the HTTP_MAX_UPLOAD_SIZE global configuration.
     *
     * This test sets Content-Type in the multipart.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersFileSizeMatchingMaxUploadSizeWithContentLength() throws Exception {
        LOG.debug("testRestPostWorkersFileSizeMatchingMaxUploadSizeWithContentLength");
        addSigner(PDFSigner.class.getName(), PDFSIGNER_WORKER_ID, PDFSIGNER_WORKER_NAME, true);

        File pdf = rtu.createPostRequestFormDataBody("res/test/pdf/sample.pdf");
        // Set maximum file upload size to exact size of file
        getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, "HTTP_MAX_UPLOAD_SIZE", "14677"); //String.valueOf(pdf.length()));
        getGlobalSession().reload();
        Thread.sleep(2100); // WorkerResource.UPLOAD_CONFIG_CACHE_TIME=2000
        try {
            Response response = given()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(MULTIPART)
                    .accept(JSON)
                    .multiPart(new MultiPartSpecBuilder(pdf).controlName("pdf").header("Content-Length", String.valueOf(14677/*pdf.length()*/)).build())
                    .when()
                    .post(baseURL + "/workers/" + PDFSIGNER_WORKER_ID + "/process")
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            assertEquals("Check response status code.", 200, response.statusCode());
        } finally {
            removeWorker(PDFSIGNER_WORKER_ID);
            getGlobalSession().removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "HTTP_MAX_UPLOAD_SIZE");
            getGlobalSession().reload();
            Thread.sleep(2100);
        }
    }

    /**
     * Test REST POST workers process by uploading a file that exceeds the HTTP_MAX_UPLOAD_SIZE global configuration.
     *
     * This test sets Content-Type in the multipart.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersFileSizeExceedingMaxUploadSizeWithContentLength() throws Exception {
        LOG.debug("testRestPostWorkersFileSizeExceedingMaxUploadSizeWithContentLength");
        addSigner(PDFSigner.class.getName(), PDFSIGNER_WORKER_ID, PDFSIGNER_WORKER_NAME, true);

        final File pdf = rtu.createPostRequestFormDataBody("res/test/pdf/sample.pdf");
        // Set maximum file upload size to 700 bytes
        getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, "HTTP_MAX_UPLOAD_SIZE", String.valueOf(pdf.length() - 1)); // One less than the file
        getGlobalSession().reload();
        Thread.sleep(2100); // WorkerResource.UPLOAD_CONFIG_CACHE_TIME=2000
        try {
            Response response = given()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(MULTIPART)
                    .accept(JSON)
                    .multiPart(new MultiPartSpecBuilder(pdf).controlName("pdf").header("Content-Length", String.valueOf(pdf.length())).build())
                    .when()
                    .post(baseURL + "/workers/" + PDFSIGNER_WORKER_ID + "/process")
                    .then()
                    .statusCode(413)
                    .contentType("application/json")
                    .extract().response();

            assertEquals("Check response status code.", 413, response.statusCode());
        } finally {
            removeWorker(PDFSIGNER_WORKER_ID);
            getGlobalSession().removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "HTTP_MAX_UPLOAD_SIZE");
            getGlobalSession().reload();
            Thread.sleep(2100);
        }
    }

    /**
     * Test REST POST workers process by uploading a file that exceeds the HTTP_MAX_UPLOAD_SIZE global configuration.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersFileSizeMatchingMaxUploadSize() throws Exception {
        LOG.debug("testRestPostWorkersFileSizeExceedingMaxUploadSize");
        addSigner(PDFSigner.class.getName(), PDFSIGNER_WORKER_ID, PDFSIGNER_WORKER_NAME, true);

        File pdf = rtu.createPostRequestFormDataBody("res/test/pdf/sample.pdf");
        // Set maximum file upload size to exact size of file
        getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, "HTTP_MAX_UPLOAD_SIZE", String.valueOf(pdf.length()));
        getGlobalSession().reload();
        Thread.sleep(2100); // WorkerResource.UPLOAD_CONFIG_CACHE_TIME=2000

        try {
            Response response = given()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(MULTIPART)
                    .accept(JSON)
                    .multiPart("pdf", pdf)
                    .when()
                    .post(baseURL + "/workers/" + PDFSIGNER_WORKER_ID + "/process")
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            assertEquals("Check response status code.", 200, response.statusCode());
        } finally {
            removeWorker(PDFSIGNER_WORKER_ID);
            getGlobalSession().removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "HTTP_MAX_UPLOAD_SIZE");
            getGlobalSession().reload();
            Thread.sleep(2100);
        }
    }

    /**
     * Test REST POST workers process by uploading a file that exceeds the HTTP_MAX_UPLOAD_SIZE global configuration.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersFileSizeExceedingByOneByteMaxUploadSize() throws Exception {
        LOG.debug("testRestPostWorkersFileSizeExceedingByOneByteMaxUploadSize");
        addSigner(PDFSigner.class.getName(), PDFSIGNER_WORKER_ID, PDFSIGNER_WORKER_NAME, true);

        File pdf = rtu.createPostRequestFormDataBody("res/test/pdf/sample.pdf");
        // Set maximum file upload size so that the file is one byte too big for the HTTP_MAX_UPLOAD_SIZE
        getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, "HTTP_MAX_UPLOAD_SIZE", String.valueOf(pdf.length() - 1));
        getGlobalSession().reload();
        Thread.sleep(2100); // WorkerResource.UPLOAD_CONFIG_CACHE_TIME=2000
        try {
            Response response = given()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(MULTIPART)
                    .accept(JSON)
                    .multiPart("pdf", pdf)
                    .when()
                    .post(baseURL + "/workers/" + PDFSIGNER_WORKER_ID + "/process")
                    .then()
                    .statusCode(413)
                    .contentType("application/json")
                    .extract().response();

            assertEquals("Check response status code.", 413, response.statusCode());
        } finally {
            removeWorker(PDFSIGNER_WORKER_ID);
            getGlobalSession().removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "HTTP_MAX_UPLOAD_SIZE");
            getGlobalSession().reload();
            Thread.sleep(2100);
        }
    }

    /**
     * Test REST POST workers process by worker ID, uploading a pdf file and signing it with a PDFSigner.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersPDFSignerProcessMultiPart() throws Exception {
        LOG.debug("testRestPostWorkersPDFSignerProcessMultiPart");
        try {
            addSigner(PDFSigner.class.getName(), PDFSIGNER_WORKER_ID, PDFSIGNER_WORKER_NAME, true);

            Response response = given()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(MULTIPART)
                    .accept(JSON)
                    .multiPart("pdf", rtu.createPostRequestFormDataBody("res/test/pdf/sample.pdf"))
                    .when()
                    .post(baseURL + "/workers/" + PDFSIGNER_WORKER_ID + "/process")
                    .then()
                    .statusCode(200)
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
     * Test REST POST workers process accepting any Content-Type.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersProcessMultiPartAcceptAnyContentType() throws Exception {
        LOG.debug("testRestPostWorkersProcessMultiPartAcceptAnyContentType");
        try {
            addSigner(PDFSigner.class.getName(), PDFSIGNER_WORKER_ID, PDFSIGNER_WORKER_NAME, true);

            Response response = given()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(MULTIPART)
                    .accept(ANY)
                    .multiPart("pdf", rtu.createPostRequestFormDataBody("res/test/pdf/sample.pdf"))
                    .when()
                    .post(baseURL + "/workers/" + PDFSIGNER_WORKER_ID + "/process")
                    .then()
                    .statusCode(406)
                    .extract().response();

            assertEquals("Check response status code.", 406, response.statusCode());
        } finally {
            removeWorker(PDFSIGNER_WORKER_ID);
        }
    }

    /**
     * Test REST POST workers process by worker ID, uploading a pdf file and signing it with a PDFSigner and a file
     * is returned.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersPDFSignerProcessMultiPartOctetStream() throws Exception {
        LOG.debug("testRestPostWorkersPDFSignerProcessMultiPartOctetStream");
        try {
            addSigner(PDFSigner.class.getName(), PDFSIGNER_WORKER_ID, PDFSIGNER_WORKER_NAME, true);

            Response response = given()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(MULTIPART)
                    .accept("application/octet-stream")
                    .multiPart("pdf", rtu.createPostRequestFormDataBody("res/test/pdf/sample.pdf"))
                    .when()
                    .post(baseURL + "/workers/" + PDFSIGNER_WORKER_ID + "/process")
                    .then()
                    .statusCode(200)
                    .contentType("application/pdf")
                    .extract().response();

            assertTrue(response.contentType().equals("application/pdf"));

            assertEquals("Check response status code.", 200, response.statusCode());

        } finally {
            removeWorker(PDFSIGNER_WORKER_ID);
        }
    }

    /**
     * Test REST POST workers process by worker ID, uploading a password-protected pdf file and signing it with a PDFSigner.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersPDFSignerProcessMultiPartWithPassword() throws Exception {
        LOG.debug("testRestPostWorkersPDFSignerProcessMultiPartWithPassword");
        try {
            addSigner(PDFSigner.class.getName(), PDFSIGNER_WORKER_ID, PDFSIGNER_WORKER_NAME, true);

            Response response = given()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(MULTIPART)
                    .accept(JSON)
                    .multiPart("password-pdf", rtu.createPostRequestFormDataBody("res/test/pdf/sample-owner123.pdf"))
                    .multiPart("REQUEST_METADATA.pdfPassword", "owner123")
                    .when()
                    .post(baseURL + "/workers/" + PDFSIGNER_WORKER_ID + "/process")
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));

            assertEquals("Check response status code.", 200, response.statusCode());
            assertTrue("Check response contains archiveId.", responseJsonObject.containsKey("archiveId"));
            byte[] responsePDFBytes = Base64.decode(responseJsonObject.get("data").toString());
            PdfReader reader = new PdfReader(responsePDFBytes);
            final PdfPKCS7 p7 = reader.getAcroFields().verifySignature((String) reader.getAcroFields().getSignatureNames().get(0));
            assertEquals("overriding reason", "Signed by SignServer", p7.getReason());

        } finally {
            removeWorker(PDFSIGNER_WORKER_ID);
        }
    }

    /**
     * Test REST POST workers process by worker ID, uploading a password-protected pdf file and signing it with a PDFSigner.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersPDFSignerProcessMultiPartWithPasswordMetadataWithSpecialCharactersUtf8() throws Exception {
        LOG.debug("testRestPostWorkersPDFSignerProcessMultiPartWithPasswordMetadataWithSpecialCharactersUtf8");
        try {
            addSigner(PDFSigner.class.getName(), PDFSIGNER_WORKER_ID, PDFSIGNER_WORKER_NAME, true);

            Response response = given()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(MULTIPART)
                    .accept(JSON)
                    .multiPart("password-pdf", rtu.createPostRequestFormDataBody("res/test/pdf/sample-useraao.pdf"))
                    .multiPart(new MultiPartSpecBuilder("useråäö").controlName("REQUEST_METADATA.pdfPassword").emptyFileName().charset(StandardCharsets.UTF_8).build())
                    /*.log().all(true)*/
                    .when()
                    .post(baseURL + "/workers/" + PDFSIGNER_WORKER_ID + "/process")
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));

            assertEquals("Check response status code.", 200, response.statusCode());
            assertTrue("Check response contains archiveId.", responseJsonObject.containsKey("archiveId"));
            byte[] responsePDFBytes = Base64.decode(responseJsonObject.get("data").toString());
            PdfReader reader = new PdfReader(responsePDFBytes, "useråäö".getBytes(StandardCharsets.ISO_8859_1));
            final PdfPKCS7 p7 = reader.getAcroFields().verifySignature((String) reader.getAcroFields().getSignatureNames().get(0));
            assertEquals("overriding reason", "Signed by SignServer", p7.getReason());

        } finally {
            removeWorker(PDFSIGNER_WORKER_ID);
        }
    }

    /**
     * Test REST POST workers process by worker ID, uploading a password-protected pdf file and signing it with a PDFSigner.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersPDFSignerProcessMultiPartWithPasswordMetadataWithSpecialCharactersLatin1() throws Exception {
        LOG.debug("testRestPostWorkersPDFSignerProcessMultiPartWithPasswordMetadataWithSpecialCharactersLatin1");
        try {
            addSigner(PDFSigner.class.getName(), PDFSIGNER_WORKER_ID, PDFSIGNER_WORKER_NAME, true);

            Response response = given()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(MULTIPART)
                    .accept(JSON)
                    .multiPart("password-pdf", rtu.createPostRequestFormDataBody("res/test/pdf/sample-useraao.pdf"))
                    .multiPart(new MultiPartSpecBuilder("useråäö").controlName("REQUEST_METADATA.pdfPassword").emptyFileName().charset(StandardCharsets.ISO_8859_1).build())
                    /*.log().all(true)*/
                    .when()
                    .post(baseURL + "/workers/" + PDFSIGNER_WORKER_ID + "/process")
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));

            assertEquals("Check response status code.", 200, response.statusCode());
            assertTrue("Check response contains archiveId.", responseJsonObject.containsKey("archiveId"));
            byte[] responsePDFBytes = Base64.decode(responseJsonObject.get("data").toString());
            PdfReader reader = new PdfReader(responsePDFBytes, "useråäö".getBytes(StandardCharsets.ISO_8859_1));
            final PdfPKCS7 p7 = reader.getAcroFields().verifySignature((String) reader.getAcroFields().getSignatureNames().get(0));
            assertEquals("overriding reason", "Signed by SignServer", p7.getReason());

        } finally {
            removeWorker(PDFSIGNER_WORKER_ID);
        }
    }

    /**
     * Test REST POST workers process by worker ID, uploading a password-protected pdf file and signing it with a PDFSigner.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersPDFSignerProcessMultiPartWithPasswordFieldWithSpecialCharacters() throws Exception {
        LOG.debug("testRestPostWorkersPDFSignerProcessMultiPartWithPasswordFieldWithSpecialCharacters");
        try {
            addSigner(PDFSigner.class.getName(), PDFSIGNER_WORKER_ID, PDFSIGNER_WORKER_NAME, true);

            Response response = given()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(MULTIPART)
                    .accept(JSON)
                    .multiPart("password-pdf", rtu.createPostRequestFormDataBody("res/test/pdf/sample-useraao.pdf"))
                    .multiPart(new MultiPartSpecBuilder("useråäö").controlName("pdfPassword").emptyFileName().charset(StandardCharsets.UTF_8).build())
                    /*.log().all(true)*/
                    .when()
                    .post(baseURL + "/workers/" + PDFSIGNER_WORKER_ID + "/process")
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));

            assertEquals("Check response status code.", 200, response.statusCode());
            assertTrue("Check response contains archiveId.", responseJsonObject.containsKey("archiveId"));
            byte[] responsePDFBytes = Base64.decode(responseJsonObject.get("data").toString());
            PdfReader reader = new PdfReader(responsePDFBytes, "useråäö".getBytes(StandardCharsets.ISO_8859_1));
            final PdfPKCS7 p7 = reader.getAcroFields().verifySignature((String) reader.getAcroFields().getSignatureNames().get(0));
            assertEquals("overriding reason", "Signed by SignServer", p7.getReason());

        } finally {
            removeWorker(PDFSIGNER_WORKER_ID);
        }
    }

    /**
     * Test REST POST workers process by worker ID, uploading a password-protected pdf file and
     * attempting to signing it with a PDFSigner using a wrong password.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRestPostWorkersPDFSignerProcessMultiPartWithWrongPassword() throws Exception {
        LOG.debug("testRestPostWorkersPDFSignerProcessMultiPartWithWrongPassword");
        try {
            addSigner(PDFSigner.class.getName(), PDFSIGNER_WORKER_ID, PDFSIGNER_WORKER_NAME, true);

            Response response = given()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(MULTIPART)
                    .accept(JSON)
                    .multiPart("password-pdf", rtu.createPostRequestFormDataBody("res/test/pdf/sample-open123.pdf"))
                    .multiPart("REQUEST_METADATA.pdfPassword", "veryWrongPassword")
                    .when()
                    .post(baseURL + "/workers/" + PDFSIGNER_WORKER_ID + "/process")
                    .then()
                    .statusCode(400)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));

            assertEquals("Check response status code.", 400, response.statusCode());
            assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));
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
                    .header("X-Keyfactor-Requested-With", "1")
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
                    .header("X-Keyfactor-Requested-With", "1")
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
                .header("X-Keyfactor-Requested-With", "1")
                .contentType(JSON)
                .accept(JSON)
                .body(rtu.createPostProcessRequestJsonBody())
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
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPostProcessRequestJsonBody())
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
                    .header("X-Keyfactor-Requested-With", "1")
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
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPostProcessRequestJsonBody())
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
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPostProcessRequestJsonBody())
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
     * Test REST POST without header. Should return status code 403
     */
    @Test
    public void testAccessForbiddenStatusCode() {
        LOG.debug("testAccessForbiddenStatusCode");
        Response response = given()
                .contentType(JSON)
                .accept(JSON)
                .body(rtu.createPostWorkerAddRequestJsonBody(CMSSIGNER_WORKER_NAME))
                .when()
                .post(baseURL + "/workers/" + CMSSIGNER_WORKER_ID)
                .then()
                .statusCode(403)
                .contentType("application/json")
                .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));

            assertEquals("Check response status code 403.", 403, response.statusCode());
            assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));
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
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME))
                    .when()
                    .post(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(201)
                    .extract().response();

            assertEquals("HelloWorker_REST", getWorkerSession().exportWorkerConfig(HELLO_WORKER_ID).getProperty("NAME"));
            assertEquals("Check response status code 201", 201, response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test REST POST to create a worker with an empty body. Should return status code 400
     */
    @Test
    public void testRestPostAddWorkerIllegalRequestExceptionStatusCode() {
        LOG.debug("testRestPostAddWorkerIllegalRequestExceptionStatusCode");
        JSONObject body = new JSONObject();

        try {
            Response response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(body)
                    .when()
                    .post(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(400)
                    .extract().response();
            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));

            assertEquals("Check response status code is 400.", 400, response.statusCode());
            assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));

        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test REST POST to create a worker with worker ID already exists. Should return status code 409
     */
    @Test
    public void testRestPostWorkerExistsExceptionStatusCode() {
        LOG.debug("testRestPostWorkerExistsExceptionStatusCode");

        try {
            Response response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME))
                    .when()
                    .post(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(201)
                    .extract().response();
            assertEquals("Check response status code is 201.", 201, response.statusCode());

            response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME))
                    .when()
                    .post(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(409)
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));

            assertEquals("Check response status code is 409.", 409, response.statusCode());
            assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));

        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test REST POST to create a worker with a wrong request body. Should return status code 500
     */
    @Test
    public void testRestPostAddWorkerInternalServerExceptionStatusCode() {
        LOG.debug("testRestPostAddWorkerInternalServerExceptionStatusCode");
        String dummyMessageBody = "Text";

        try {
            Response response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(dummyMessageBody)
                    .when()
                    .post(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(500)
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertEquals("Check response status code is 500.", 500, response.statusCode());
            assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));

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
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME))
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
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME))
                    .when()
                    .post(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(201)
                    .extract().response();

            assertEquals("Check response status code 201", 201, response.statusCode());
            assertEquals("Check there is no worker property called PROPERTY1",
                    null, getWorkerSession().exportWorkerConfig(HELLO_WORKER_ID).getProperty("PROPERTY1"));

            response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPatchWorkerEditRequestJsonBody())
                    .when()
                    .patch(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            assertEquals("value1", getWorkerSession().exportWorkerConfig(HELLO_WORKER_ID).getProperty("PROPERTY1"));
            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertTrue("Response contains the correct message", responseJsonObject.toString().contains("Worker properties successfully updated"));
            assertEquals("Check response status code 200", 200, response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test REST PATCH worker to update worker properties with a wrong message body. Should return status code 400.
     */
    @Test
    public void testRestPatchWorkerIllegalRequestExceptionStatusCode() {
        LOG.debug("testRestPatchWorkerIllegalRequestExceptionStatusCode");
        JSONObject body = new JSONObject();

        try {
            Response response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME))
                    .when()
                    .post(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(201)
                    .extract().response();

            assertEquals("Check response status code 201", 201, response.statusCode());

            response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(body)
                    .when()
                    .patch(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(400)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertEquals("Check response status code is 400.", 400, response.statusCode());
            assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test REST PATCH worker to update worker properties with a wrong worker ID. Should return status code 404.
     */
    @Test
    public void testRestPatchWorkerNoSuchWorkerExceptionStatusCode() {
        LOG.debug("testRestPatchWorkerNoSuchWorkerExceptionStatusCode");
        int dummyWorkerID = 8787878;

        try {
            Response response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPutWorkerReplaceRequestJsonBody(HELLO_WORKER_NAME))
                    .when()
                    .patch(baseHttpsURL + "/workers/" + dummyWorkerID)
                    .then()
                    .statusCode(404)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertEquals("Check response status code is 404.", 404, response.statusCode());
            assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test REST PATCH worker to update worker properties with a wrong message body. Should return status code 500.
     */
    @Test
    public void testRestPatchWorkerInternalServerExceptionStatusCode() {
        LOG.debug("testRestPatchWorkerInternalServerExceptionStatusCode");
        String dummyMessageBody = "Text";

        try {
            Response response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(dummyMessageBody)
                    .when()
                    .patch(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(500)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertEquals("Check response status code is 500.", 500, response.statusCode());
            assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));
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
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME))
                    .when()
                    .post(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(201)
                    .extract().response();

            assertEquals("Check response status code 201", 201, response.statusCode());
            assertEquals("Check worker property before replace",
                    "Hi", getWorkerSession().exportWorkerConfig(HELLO_WORKER_ID).getProperty("GREETING"));
            assertEquals("Check worker property before replace",
                    "NOAUTH", getWorkerSession().exportWorkerConfig(HELLO_WORKER_ID).getProperty("AUTHTYPE"));

            response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPutWorkerReplaceRequestJsonBody(HELLO_WORKER_NAME))
                    .when()
                    .put(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            assertEquals("Properties Replaced!", getWorkerSession().exportWorkerConfig(HELLO_WORKER_ID).getProperty("GREETING"));
            assertEquals(null, getWorkerSession().exportWorkerConfig(HELLO_WORKER_ID).getProperty("AUTHTYPE"));
            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertTrue("Response contains the correct message", responseJsonObject.toString().contains("Worker properties successfully replaced"));
            assertEquals("Check response status code 200", 200, response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test REST PUT worker to replace all worker properties with a wrong message body. Should return status code 400.
     */
    @Test
    public void testRestPutWorkerIllegalRequestExceptionStatusCode() {
        LOG.debug("testRestPutWorkerIllegalRequestExceptionStatusCode");
        JSONObject body = new JSONObject();

        try {
            Response response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME))
                    .when()
                    .post(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(201)
                    .extract().response();

            assertEquals("Check response status code 201", 201, response.statusCode());

            response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(body)
                    .when()
                    .put(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(400)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertEquals("Check response status code is 400.", 400, response.statusCode());
            assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test REST PUT worker to replace all worker properties with a wrong worker ID. Should return status code 404.
     */
    @Test
    public void testRestPutWorkerNoSuchWorkerExceptionStatusCode() {
        LOG.debug("testRestPutWorkerNoSuchWorkerExceptionStatusCode");
        int dummyWorkerID = 8787878;

        try {
            Response response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPutWorkerReplaceRequestJsonBody(HELLO_WORKER_NAME))
                    .when()
                    .put(baseHttpsURL + "/workers/" + dummyWorkerID)
                    .then()
                    .statusCode(404)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertEquals("Check response status code is 404.", 404, response.statusCode());
            assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test REST PUT worker to replace all worker properties with a wrong message body. Should return status code 500.
     */
    @Test
    public void testRestPutWorkerInternalServerExceptionStatusCode() {
        LOG.debug("testRestPutWorkerInternalServerExceptionStatusCode");
        String dummyMessageBody = "Text";

        try {
            Response response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(dummyMessageBody)
                    .when()
                    .put(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(500)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertEquals("Check response status code is 500.", 500, response.statusCode());
            assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));
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
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME))
                    .when()
                    .post(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(201)
                    .extract().response();

            assertEquals("Check response status code 201", 201, response.statusCode());
            assertTrue("Check worker with the given worker name created", getWorkerSession().getAllWorkers().contains(HELLO_WORKER_ID));

            response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .accept(JSON)
                    .when()
                    .delete(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            assertFalse("Check worker with the given worker name removed", getWorkerSession().getAllWorkers().contains(HELLO_WORKER_ID));
            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertTrue("Response contains the correct message", responseJsonObject.toString().contains("Worker removed successfully"));
            assertEquals("Check response status code 200", 200, response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test REST get worker configuration operation.
     */
    @Test
    public void testRestGetWorkerConfig() throws InvalidWorkerIdException {
        LOG.debug("testRestGetWorkerConfig");

        try {
            final JSONObject body =
                    rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME);
            final JSONObject configProperties =
                    (JSONObject) body.get("properties");

            configProperties.put("PIN", "foo123");

            final int expectedNumberProperties = configProperties.size();

            Response response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(body)
                    .when()
                    .post(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(201)
                    .extract().response();

            assertEquals("Check response status code 201", 201,
                         response.statusCode());
            assertTrue("Check worker with the given worker name created",
                       getWorkerSession().getAllWorkers().contains(HELLO_WORKER_ID));

            response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .accept(JSON)
                    .when()
                    .get(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            final JSONObject responseJsonObject =
                    new JSONObject(response.jsonPath().getJsonObject("$"));
            final Object properties = responseJsonObject.get("properties");
            assertNotNull("Response contains properties", properties);
            assertEquals("Check response status code 200", 200,
                         response.statusCode());

            final Map<String, String> propertiesMap =
                    (Map<String, String>) properties;

            // check expected worker properties
            assertEquals("Number of properties", expectedNumberProperties,
                         propertiesMap.size());
            assertEquals("Name exists", HELLO_WORKER_NAME,
                         propertiesMap.get("NAME"));
            assertEquals("Type exists", "PROCESSABLE",
                         propertiesMap.get("TYPE"));
            assertEquals("Authtype exists", "NOAUTH",
                         propertiesMap.get("AUTHTYPE"));
            assertEquals("Greeting exists", "Hi",
                         propertiesMap.get("GREETING"));
            assertEquals("Implementation class exists",
                         "org.signserver.module.sample.workers.HelloWorker",
                         propertiesMap.get("IMPLEMENTATION_CLASS"));
            assertEquals("PIN comes out as masked", "_MASKED_",
                         propertiesMap.get("PIN"));
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test the list workers operation.
     */
    @Test
    public void testRestListWorkers() {
        LOG.debug("testRestListWorkers");

        try {
            // get list before adding a new worker
            Response response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .accept(JSON)
                    .when()
                    .get(baseHttpsURL + "/workers/")
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject =
                    new JSONObject(response.jsonPath().getJsonObject("$"));
            List<Map<String, Object>> workers = (List<Map<String, Object>>) responseJsonObject.get("workers");

            assertNotNull("Workers object found", workers);

            int count = 0;
            for (final Map<String, Object> w : workers) {
                final Integer id = (Integer) w.get("id");
                final String name = (String) w.get("name");

                assertNotNull("Contains ID", id);
                assertNotNull("Contains name", name);
                count++;
            }

            // create new worker
            response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME))
                    .when()
                    .post(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(201)
                    .extract().response();

            assertEquals("Check response status code 201", 201,
                         response.statusCode());
            assertTrue("Check worker with the given worker name created",
                       getWorkerSession().getAllWorkers().contains(HELLO_WORKER_ID));

            response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .accept(JSON)
                    .when()
                    .get(baseHttpsURL + "/workers/")
                    .then()
                    .statusCode(200)
                    .contentType("application/json")
                    .extract().response();

            responseJsonObject =
                    new JSONObject(response.jsonPath().getJsonObject("$"));

            workers = (List<Map<String, Object>>) responseJsonObject.get("workers");

            assertNotNull("Workers object found", workers);

            int newCount = 0;
            boolean foundNew = false;

            for (final Map<String, Object> w : workers) {
                final Integer id = (Integer) w.get("id");
                final String name = (String) w.get("name");

                if (id == HELLO_WORKER_ID) {
                    assertEquals("Got name of new worker", HELLO_WORKER_NAME, name);
                    foundNew = true;
                }
                newCount++;
            }

            assertTrue("Found new worker in response", foundNew);
            assertEquals("One new worker", count + 1, newCount);
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test the list workers operation. Not setting the custom header, should
     * not be allowed.
     */
    @Test
    public void testRestListWorkersNoHeader() {
        LOG.debug("testRestListWorkersNoHeader");

        // get list before adding a new worker
        Response response = given()
                .relaxedHTTPSValidation()
                .accept(JSON)
                .when()
                .get(baseHttpsURL + "/workers/")
                .then()
                .statusCode(403)
                .contentType("application/json")
                .extract().response();

        assertEquals("Response code", 403, response.getStatusCode());

        JSONObject responseJsonObject =
                new JSONObject(response.jsonPath().getJsonObject("$"));
        List<Map<String, Object>> workers = (List<Map<String, Object>>) responseJsonObject.get("workers");

        assertNull("Workers object not found", workers);
    }


    /**
     * Test REST get worker configuration operation when no custom header is set.
     */
    @Test
    public void testRestGetWorkerConfigNoHeader() throws InvalidWorkerIdException {
        LOG.debug("testRestGetWorkerConfigNoHeader");

        try {
            Response response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .body(rtu.createPostWorkerAddRequestJsonBody(HELLO_WORKER_NAME))
                    .when()
                    .post(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(201)
                    .extract().response();

            assertEquals("Check response status code 201", 201,
                         response.statusCode());
            assertTrue("Check worker with the given worker name created",
                       getWorkerSession().getAllWorkers().contains(HELLO_WORKER_ID));

            response = given()
                    .relaxedHTTPSValidation()
                    .accept(JSON)
                    .when()
                    .get(baseHttpsURL + "/workers/" + HELLO_WORKER_ID)
                    .then()
                    .statusCode(403)
                    .contentType("application/json")
                    .extract().response();

            final JSONObject responseJsonObject =
                    new JSONObject(response.jsonPath().getJsonObject("$"));
            final Object properties =
                    responseJsonObject.get("properties");
            assertNull("Response does not contain properties", properties);
            assertEquals("Check response status code 403", 403,
                         response.statusCode());
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test REST get worker configuration operation with a non-existing worker ID.
     */
    @Test
    public void testRestGetWorkerConfigNonExistingWorker() {
        LOG.debug("testRestDeleteWorker");

        final Response response = given()
                .relaxedHTTPSValidation()
                .header("X-Keyfactor-Requested-With", "1")
                .accept(JSON)
                .when()
                .get(baseHttpsURL + "/workers/1000000")
                .then()
                .statusCode(404)
                .contentType("application/json")
                .extract().response();

        final JSONObject responseJsonObject =
                new JSONObject(response.jsonPath().getJsonObject("$"));

        assertEquals("Check response status code is 404.", 404, response.statusCode());
        assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));
    }

    /**
     * Test REST DELETE worker with a wrong worker ID. Should return status code 404.
     */
    @Test
    public void testRestDeleteWorkerNoSuchWorkerExceptionStatusCode() {
        LOG.debug("testRestDeleteWorkerNoSuchWorkerExceptionStatusCode");
        int dummyWorkerID = 8787878;

        try {
            Response response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .when()
                    .delete(baseHttpsURL + "/workers/" + dummyWorkerID)
                    .then()
                    .statusCode(404)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertEquals("Check response status code is 404.", 404, response.statusCode());
            assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

    /**
     * Test REST DELETE worker with an invalid worker ID (Not an integer value). Should return status code 500.
     */
    @Test
    public void testRestDeleteWorkerInternalServerExceptionStatusCode() {
        LOG.debug("testRestDeleteWorkerInternalServerExceptionStatusCode");
        String dummyWorkerID = "NotAnInteger";

        try {
            Response response = given()
                    .relaxedHTTPSValidation()
                    .header("X-Keyfactor-Requested-With", "1")
                    .contentType(JSON)
                    .accept(JSON)
                    .when()
                    .put(baseHttpsURL + "/workers/" + dummyWorkerID)
                    .then()
                    .statusCode(500)
                    .contentType("application/json")
                    .extract().response();

            JSONObject responseJsonObject = new JSONObject(response.jsonPath().getJsonObject("$"));
            assertEquals("Check response status code is 500.", 500, response.statusCode());
            assertTrue("Check that the response contains error key.", responseJsonObject.containsKey("error"));
        } finally {
            removeWorker(HELLO_WORKER_ID);
        }
    }

}
