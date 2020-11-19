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
package org.signserver.web;

import org.signserver.testutils.WebTestCase;
import java.io.IOException;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.bouncycastle.util.Arrays;

import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.module.xmlvalidator.XMLValidatorTestData;

import org.junit.Test;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.WorkerIdentifier;
import org.signserver.server.signers.EchoRequestMetadataSigner;
import org.signserver.testutils.ModulesTestCase;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Tests that the right HTTP status codes are returned in different situations.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class GenericProcessServletResponseTest extends WebTestCase {

    private static final long UPLOAD_CONFIG_CACHE_TIME = 2000; // Note: From GeneriProcessServlet.UPLOAD_CONFIG_CACHE_TIME

    @Override
    protected String getServletURL() {
        return getPreferredHTTPProtocol() + getHTTPHost() + ":" + getPreferredHTTPPort() + "/signserver/process";
    }

    /**
     * Sets up a dummy signer.
     * @throws Exception in case of error
     */
    @Test
    public void test00SetupDatabase() throws Exception {
        addDummySigner1(false);
        addCMSSigner1();
        addXMLValidator();
        addSigner("org.signserver.server.signers.EchoRequestMetadataSigner", 123, "DummySigner123", true);
        getWorkerSession().activateSigner(new WorkerIdentifier(getSignerIdDummy1()), ModulesTestCase.KEYSTORE_PASSWORD);
        getWorkerSession().activateSigner(new WorkerIdentifier(getSignerIdCMSSigner1()), ModulesTestCase.KEYSTORE_PASSWORD);
    }

    /**
     * Test that a successful request returns status code 200.
     */
    @Test
    public void test01HttpStatus200() {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", getSignerNameDummy1());
        fields.put("data", "<root/>");

        assertStatusReturned(fields, 200);
    }

    /**
     * Test that a bad request returns status code 400.
     * This request misses the "data" field.
     */
    @Test
    public void test02HttpStatus400_missingField() {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", getSignerNameDummy1());
        // Notice: No "data" field added

        assertStatusReturned(fields, 400);
    }

    /**
     * Test that a bad request returns status code 400.
     * This request contains an invalid XML document.
     */
    @Test
    public void test02HttpStatus400_invalidDocument() {
        final String invalidXMLDoc = "<noEndTagToThis>";
        Map<String, String> fields = new HashMap<>();
        fields.put("workerId", String.valueOf(getSignerIdDummy1()));
        fields.put("data", invalidXMLDoc);

        assertStatusReturned(fields, 400);
    }

    /**
     * Test that a bad request returns status code 400.
     * This request contains an unknown encoding property.
     */
    @Test
    public void test02HttpStatus400_unknownEncoding() {
        final String unknownEncoding = "_unknownEncoding123_";
        Map<String, String> fields = new HashMap<>();
        fields.put("workerId", String.valueOf(getSignerIdDummy1()));
        fields.put("data", "<root/>");
        fields.put("encoding", unknownEncoding);

        // Run tests but skip the multipart/form-data as it does not use any
        // encoding property
        assertStatusReturned(fields, 400, true);
    }

    /**
     * Test that a request for non-existing worker returns status code 404.
     */
    @Test
    public void test03HttpStatus404_nonExistingName() {
        final String nonExistingWorker = "_NotExistingWorker123_";
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", nonExistingWorker);
        fields.put("data", "<root/>");

        assertStatusReturned(fields, 404);
    }

    /**
     * Test that a request for non-existing worker returns status code 404.
     */
    @Test
    public void test03HttpStatus404_nonExistingId() {
        final int nonExistingId = 0;
        Map<String, String> fields = new HashMap<>();
        fields.put("workerId", String.valueOf(nonExistingId));
        fields.put("data", "<root/>");

        assertStatusReturned(fields, 404);
    }

    /**
     * Test that when the cryptotoken is offline the status code is 503.
     */
    @Test
    public void test04HttpStatus503() {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", getSignerNameDummy1());
        fields.put("data", "<root/>");

        try {
            // Deactivate crypto token
            try {
                getWorkerSession().deactivateSigner(new WorkerIdentifier(getSignerIdDummy1()));
            } catch (CryptoTokenOfflineException | InvalidWorkerIdException ex) {
                fail(ex.getMessage());
            }

            assertStatusReturned(fields, 503);
        } finally {
            // Activat crypto token
            try {
                getWorkerSession().activateSigner(new WorkerIdentifier(getSignerIdDummy1()), ModulesTestCase.KEYSTORE_PASSWORD);
            } catch (CryptoTokenAuthenticationFailureException | CryptoTokenOfflineException | InvalidWorkerIdException ex) {
                fail(ex.getMessage());
            }
        }
    }

    /**
     * Test that when an exception occurs status code 500 is returned.
     */
    @Test
    public void test05HttpStatus500_exception() throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException, InvalidWorkerIdException {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", getSignerNameDummy1());
        fields.put("data", "<root/>");

        // Set any bad properties that will make the signer fail with an exception
        final String originalSignatureAlgorithm = getWorkerSession().getCurrentWorkerConfig(
                getSignerIdDummy1()).getProperty("SIGNATUREALGORITHM");

        final String badKeyData = "_any-non-existing-alg_";
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), "SIGNATUREALGORITHM",
                badKeyData);
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        getWorkerSession().activateSigner(new WorkerIdentifier(getSignerIdDummy1()), ModulesTestCase.KEYSTORE_PASSWORD);

        try {
            assertStatusReturned(fields, 500);
        } finally {
            // Restore
            if (originalSignatureAlgorithm == null) {
                getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), "SIGNATUREALGORITHM");
            } else {
                getWorkerSession().setWorkerProperty(getSignerIdDummy1(), "SIGNATUREALGORITHM",
                    originalSignatureAlgorithm);
            }
            getWorkerSession().reloadConfiguration(getSignerIdDummy1());
            getWorkerSession().activateSigner(new WorkerIdentifier(getSignerIdDummy1()), ModulesTestCase.KEYSTORE_PASSWORD);
        }
    }

    @Test
    public void test06AttachmentFileName() throws Exception {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", getSignerNameCMSSigner1());
        fields.put("data", "Something to sign...");

        final String expectedResponseFilename = "mydocument.dat.p7s";
        final String expected = "attachment; filename=\"" + expectedResponseFilename + "\"";

        HttpURLConnection con = sendPostMultipartFormData(getServletURL(), fields, "mydocument.dat");
        assertEquals(200, con.getResponseCode());

        final String actual = con.getHeaderField("Content-Disposition");
        assertEquals("Returned filename", expected, actual);

        con.disconnect();
    }

    /**
     * Test explicitly setting the processType request parameter
     * to signDocument (the default value).
     */
    @Test
    public void test07ExplicitProcessTypeSignDocument() {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", getSignerNameDummy1());
        fields.put("processType", "signDocument");
        fields.put("data", "<root/>");

        assertStatusReturned(fields, 200);
    }

    /**
     * Test setting processType to validateDocument for a signer.
     */
    @Test
    public void test08WrongProcessType() {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", getSignerNameDummy1());
        fields.put("processType", "validateDocument");
        fields.put("data", "<root/>");

        assertStatusReturned(fields, 400);
    }

    /**
     * Test setting processType to signDocument for a validator.
     */
    @Test
    public void test08WrongProcessTypeValidator() {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", getWorkerNameXmlValidator());
        fields.put("processType", "signDocument");
        fields.put("data", "<root/>");

        assertStatusReturned(fields, 400);
    }

    /**
     * Test setting an invalid value for processType.
     */
    @Test
    public void test10InvalidProcessType() {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", getSignerNameDummy1());
        fields.put("processType", "foobar");
        fields.put("data", "<root/>");

        assertStatusReturned(fields, 400);
    }

    /**
     * Test issuing a validateDocument call.
     */
    @Test
    public void test11ValidateDocument() throws Exception {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerId", Integer.toString(getWorkerIdXmlValidator()));
        fields.put("processType", "validateDocument");
        fields.put("data", XMLValidatorTestData.TESTXML1);

        final byte[] content = sendPostFormUrlencodedReadBody(getServletURL(), fields);
        assertEquals("Response content", "VALID", new String(content));
    }

    /**
     * Test validating a document with an invalid signature.
     */
    @Test
    public void test12ValidateDocumentInvalid() throws Exception {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerId", Integer.toString(getWorkerIdXmlValidator()));
        fields.put("processType", "validateDocument");
        fields.put("data", XMLValidatorTestData.TESTXML2);

        final byte[] content = sendPostFormUrlencodedReadBody(getServletURL(), fields);
        assertEquals("Response content", "INVALID", new String(content));
    }

    /**
     * Test validating a valid certificate using the validation service through the HTTP servlet.
     */
    @Test
    public void test13ValidateCertificate() throws Exception {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerId", Integer.toString(getWorkerIdValidationService()));
        fields.put("processType", "validateCertificate");
        fields.put("data", XMLValidatorTestData.CERT_ISSUER);
        fields.put("encoding", "base64");

        // test returned status (GET, POST and POST with multi-part content)
        assertStatusReturned(fields, 200);

        // check the returned content
        final byte[] content = sendAndReadyBody(fields);
        assertEquals("Response content", "VALID;;This certificate is valid;-1;", new String(content));
    }

    /**
     * Test validating an other, non-supported issuer using the validation service through the HTTP servlet.
     */
    @Test
    public void test14ValidateCertificateOther() throws Exception {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerId", Integer.toString(getWorkerIdValidationService()));
        fields.put("processType", "validateCertificate");
        fields.put("data", XMLValidatorTestData.CERT_OTHER);
        fields.put("encoding", "base64");

        // check the returned content
        final byte[] content = sendAndReadyBody(fields);
        assertEquals("Response content", "ISSUERNOTSUPPORTED;;Issuer of given certificate isn't supported;-1;", new String(content));
    }

    private Properties parseMetadataResponse(final byte[] resp)
        throws IOException {
        final String propsString = new String(resp);
        final Properties props = new Properties();

        props.load(new StringReader(propsString));

        return props;
    }

    /**
     * Test setting a single REQUEST_METADATA.x param.
     */
    @Test
    public void test15RequestMetadataSingleParam() throws Exception {
        final Map<String, String> fields = new HashMap<>();
        fields.put("workerId", "123");
        fields.put("data", "foo");
        fields.put("REQUEST_METADATA.FOO", "BAR");

        assertStatusReturned(fields, 200);

        final byte[] resp = sendAndReadyBody(fields);
        final Properties props = parseMetadataResponse(resp);

        assertEquals("Contains property", "BAR", props.getProperty("FOO"));
    }

    /**
     * Test passing in metdata parameters using the properties file syntax.
     */
    @Test
    public void test16RequestMetadataPropertiesFile() throws Exception {
        final Map<String, String> fields = new HashMap<>();
        fields.put("workerId", "123");
        fields.put("data", "foo");
        fields.put("REQUEST_METADATA", "FOO=BAR\nFOO2=BAR2");

        assertStatusReturned(fields, 200);

        final byte[] resp = sendAndReadyBody(fields);
        final Properties props = parseMetadataResponse(resp);

        assertEquals("Contains property", "BAR", props.getProperty("FOO"));
        assertEquals("Contains property", "BAR2", props.getProperty("FOO2"));
    }

    /**
     * Test passing in metadata parameters using the properties file syntax
     * and also override a single parameter.
     */
    @Test
    public void test17RequestMetadataOverride() throws Exception {
        final Map<String, String> fields = new HashMap<>();
        fields.put("workerId", "123");
        fields.put("data", "foo");
        fields.put("REQUEST_METADATA", "FOO=BAR\nFOO2=BAR2");
        fields.put("REQUEST_METADATA.FOO", "OVERRIDE");

        assertStatusReturned(fields, 200);

        final byte[] resp = sendAndReadyBody(fields);
        final Properties props = parseMetadataResponse(resp);

        assertEquals("Contains property", "OVERRIDE", props.getProperty("FOO"));
        assertEquals("Contains property", "BAR2", props.getProperty("FOO2"));
    }

    /**
     * Test including properties with an escaped "=" sign as part of a property value.
     */
    @Test
    public void test18RequestMetadataEscaped() throws Exception {
        final Map<String, String> fields = new HashMap<>();
        fields.put("workerId", "123");
        fields.put("data", "foo");
        fields.put("REQUEST_METADATA", "FOO=FOO\\=BAR\nFOO2=BAR2");

        assertStatusReturned(fields, 200);

        final byte[] resp = sendAndReadyBody(fields);
        final Properties props = parseMetadataResponse(resp);

        assertEquals("Contains property", "FOO=BAR", props.getProperty("FOO"));
        assertEquals("Contains property", "BAR2", props.getProperty("FOO2"));
    }

    /**
     * Test including a property value broken up on two lines with a line-ending \.
     */
    @Test
    public void test19RequestMetadataLineEndingBackslash() throws Exception {
        final Map<String, String> fields = new HashMap<>();
        fields.put("workerId", "123");
        fields.put("data", "foo");
        fields.put("REQUEST_METADATA", "FOO=BAR\\\nNEXT_LINE\nFOO2=BAR2");

        assertStatusReturned(fields, 200);

        final byte[] resp = sendAndReadyBody(fields);
        final Properties props = parseMetadataResponse(resp);

        assertEquals("Contains property", "BARNEXT_LINE", props.getProperty("FOO"));
        assertEquals("Contains property", "BAR2", props.getProperty("FOO2"));
    }

    /**
     * Test with a comment line in the property file.
     */
    @Test
    public void test20RequestMetadataWithCommentLine() throws Exception {
        final Map<String, String> fields = new HashMap<>();
        fields.put("workerId", "123");
        fields.put("data", "foo");
        fields.put("REQUEST_METADATA", "FOO=BAR\n# Comment = a comment\nFOO2=BAR2");

        assertStatusReturned(fields, 200);

        final byte[] resp = sendAndReadyBody(fields);
        final Properties props = parseMetadataResponse(resp);

        // Properties.load() seems to include some sort of marker as the first entry...
        assertEquals("Number of properties", 3, props.size());
    }

    /**
     * Test with extra whitespace surrounding the "=".
     */
    @Test
    public void test21RequestMetadataExtraWhitespace() throws Exception {
        final Map<String, String> fields = new HashMap<>();
        fields.put("workerId", "123");
        fields.put("data", "foo");
        fields.put("REQUEST_METADATA", "FOO = BAR\nFOO2 = BAR2");

        assertStatusReturned(fields, 200);

        final byte[] resp = sendAndReadyBody(fields);
        final Properties props = parseMetadataResponse(resp);

        assertEquals("Contains property", "BAR", props.getProperty("FOO"));
        assertEquals("Contains property", "BAR2", props.getProperty("FOO2"));
    }

    /**
     * Tests that the maximum upload size can be configured and is enforced.
     */
    @Test
    public void test22MaxUploadSize() throws Exception {
        try {
            getGlobalSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, "HTTP_MAX_UPLOAD_SIZE", "700"); // 700 bytes max
            getGlobalSession().reload();
            // Wait for caching in GenericProcessServlet to expire
            Thread.sleep(UPLOAD_CONFIG_CACHE_TIME);

            Map<String, String> fields = new HashMap<>();
            fields.put("workerName", getSignerNameCMSSigner1());

            // Test with a small number of bytes
            // Note we can not test with 700 bytes as there is also headers that take up space
            byte[] data = new byte[10];
            Arrays.fill(data, "a".getBytes(StandardCharsets.US_ASCII)[0]);
            fields.put("data", new String(data, StandardCharsets.US_ASCII));

            assertStatusReturned(fields, 200);

            // Test with more than 700 bytes upload
            data = new byte[701];
            Arrays.fill(data, "a".getBytes(StandardCharsets.US_ASCII)[0]);
            fields.put("data", new String(data, StandardCharsets.US_ASCII));

            assertStatusReturned(fields, 413);
        } finally {
            getGlobalSession().removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "HTTP_MAX_UPLOAD_SIZE");
            getGlobalSession().reload();
            // Wait for caching in GenericProcessServlet to expire
            Thread.sleep(UPLOAD_CONFIG_CACHE_TIME);
        }
    }

    /**
     * Remove the workers created etc.
     * @throws Exception in case of error
     */
    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdDummy1());
        removeWorker(getSignerIdCMSSigner1());
        removeWorker(getWorkerIdXmlValidator());
        removeWorker(getWorkerIdValidationService());
        removeWorker(123);
    }
}
