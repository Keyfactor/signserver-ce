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

import java.io.IOException;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests that the right HTTP status codes are returned in different situations.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class ServletResponseTest extends ModulesTestCase {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ServletResponseTest.class);
    
    private static final String KEYDATA = "KEYDATA";
    private static final String CRLF = "\r\n";
    
    /**
     * Sets up a dummy signer.
     * @throws Exception in case of error
     */
    public void test00SetupDatabase() throws Exception {
        addDummySigner1();
    }
    
    /**
     * Test that a successful request returns status code 200.
     */
    public void test01HttpStatus200() {
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerName", getSignerNameDummy1());
        fields.put("data", "<root/>");
            
        assertStatusReturned(fields, 200);
    }    
    
    /**
     * Test that a bad request returns status code 400.
     * This request misses the "data" field.
     */
    public void test02HttpStatus400_missingField() {
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerName", getSignerNameDummy1());
        // Notice: No "data" field added
        
        assertStatusReturned(fields, 400);
    }
    
    /**
     * Test that a bad request returns status code 400.
     * This request contains an invalid XML document.
     */
    public void test02HttpStatus400_invalidDocument() {
        final String invalidXMLDoc = "<noEndTagToThis>";
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerId", String.valueOf(getSignerIdDummy1()));
        fields.put("data", invalidXMLDoc);
        
        assertStatusReturned(fields, 400);
    }
    
    /**
     * Test that a bad request returns status code 400.
     * This request contains an unknown encoding property.
     */
    public void test02HttpStatus400_unknownEncoding() {
        final String unknownEncoding = "_unknownEncoding123_";
        Map<String, String> fields = new HashMap<String, String>();
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
    public void test04HttpStatus404_nonExistingName() {
        final String nonExistingWorker = "_NotExistingWorker123_";
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerName", nonExistingWorker);
        fields.put("data", "<root/>");
        
        assertStatusReturned(fields, 404);
    }
    
    /**
     * Test that a request for non-existing worker returns status code 404.
     */
    public void test04HttpStatus404_nonExistingId() {
        final int nonExistingId = 0;
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerId", String.valueOf(nonExistingId));
        fields.put("data", "<root/>");
        
        assertStatusReturned(fields, 404);
    }
    
    /**
     * Test that when the cryptotoken is offline the status code is 503.
     */
    public void test05HttpStatus503() {
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerName", getSignerNameDummy1());
        fields.put("data", "<root/>");
        
        try {
            // Deactivate crypto token
            try {
                getWorkerSession().deactivateSigner(getSignerIdDummy1());
            } catch (CryptoTokenOfflineException ex) {
                fail(ex.getMessage());
            } catch (InvalidWorkerIdException ex) {
                fail(ex.getMessage());
            }
            
           assertStatusReturned(fields, 503);
        } finally {
            // Activat crypto token
            try {
                getWorkerSession().activateSigner(getSignerIdDummy1(), "");
            } catch (CryptoTokenAuthenticationFailureException ex) {
                fail(ex.getMessage());
            } catch (CryptoTokenOfflineException ex) {
                fail(ex.getMessage());
            } catch (InvalidWorkerIdException ex) {
                fail(ex.getMessage());
            }
        }
    }
    
    /**
     * Test that when an exception occurs status code 500 is returned.
     */
    public void test04HttpStatus500_exception() {
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerName", getSignerNameDummy1());
        fields.put("data", "<root/>");
        
        // Set any bad properties that will make the signer fail with an exception
        final String originalKeyData = getWorkerSession().getCurrentWorkerConfig(
                getSignerIdDummy1()).getProperty(KEYDATA);
        final String badKeyData = "_any-bad-key-data_";
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), KEYDATA, 
                badKeyData);
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        try {
            assertStatusReturned(fields, 500);
        } finally {
            // Restore KEYDATA
            getWorkerSession().setWorkerProperty(getSignerIdDummy1(), KEYDATA, 
                originalKeyData);
            getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        }
    }
    
    /**
     * Remove the workers created etc.
     * @throws Exception in case of error
     */
    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdDummy1());
    }
    
    private static HttpURLConnection openConnection(String queryString) 
            throws MalformedURLException, IOException {
        final StringBuilder buff = new StringBuilder();
        buff.append("http://localhost:8080/signserver/process");
        if (queryString != null) {
            buff.append("?");
            buff.append(queryString);
        }
        final URL url = new URL(buff.toString());
        return (HttpURLConnection) url.openConnection();
    }
    
    private static HttpURLConnection sendGet(final Map<String, String> fields) 
            throws IOException {
        final StringBuilder buff = new StringBuilder();
        for (Entry<String, String> entry : fields.entrySet()) {
            buff.append(entry.getKey())
                .append("=")
                .append(URLEncoder.encode(entry.getValue(), "UTF-8"))
                .append("&");
        }   
        final String body = buff.toString();
        return openConnection(body);
    }
    
    private static HttpURLConnection sendPostFormUrlencoded(
            final Map<String, String> fields) throws MalformedURLException, IOException {
        final StringBuilder buff = new StringBuilder();
        for (Entry<String, String> entry : fields.entrySet()) {
            buff.append(entry.getKey())
                .append("=")
                .append(URLEncoder.encode(entry.getValue(), "UTF-8"))
                .append("&");
        }   
        final String body = buff.toString();
            
        HttpURLConnection con = openConnection(null);
        con.setRequestMethod("POST");
        con.setAllowUserInteraction(false);
        con.setDoOutput(true);
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        PrintWriter out = new PrintWriter(con.getOutputStream());
        out.print(body);
        out.close();
        return con;
    }
    
    private static HttpURLConnection sendPostMultipartFormData(
            final Map<String, String> fields) throws MalformedURLException, IOException {
        
        final String boundary = 
                "---------------------------1004178514282965110854332084";
        
        HttpURLConnection con = openConnection(null);
        con.setRequestMethod("POST");
        con.setAllowUserInteraction(false);
        con.setDoOutput(true);
        con.setRequestProperty("Content-Type", 
                "multipart/form-data; boundary=" + boundary);
        
        PrintWriter out = new PrintWriter(con.getOutputStream());
        for (Entry<String, String> field : fields.entrySet()) {
            out.print("--");
            out.print(boundary);
            out.print(CRLF);
            out.print("Content-Disposition: form-data; name=\"");
            out.print(field.getKey());
            out.print("\"");
            if (field.getKey().equals("data")) {
                out.print("; filename=\"data\"");
                out.print(CRLF);
                out.print("Content-Type: application/octet-stream");
            }
            out.print(CRLF);
            out.print(CRLF);
            out.print(field.getValue());
            out.print(CRLF);
        }
        out.print("--");
        out.print(boundary);
        out.print("--");
        out.print(CRLF);

        out.close();
        return con;
    }
    
    private static void assertStatusReturned(Map<String, String> fields, 
            int expected) {
        assertStatusReturned(fields, expected, false);
    }
    
    private static void assertStatusReturned(Map<String, String> fields, 
            int expected, boolean skipMultipartTest) {
        // GET
        try {
            HttpURLConnection con = sendGet(fields);
            int response = con.getResponseCode();
            String message = con.getResponseMessage();
            LOG.info("Returned " + response + " " + message);
            assertEquals("status response: " + message, expected, response);
            
            con.disconnect();
        } catch (IOException ex) {
            LOG.error("IOException", ex);
            fail(ex.getMessage());
        }
        
        // POST (url-encoded)
        try {            
            HttpURLConnection con = sendPostFormUrlencoded(fields);
            
            int response = con.getResponseCode();
            String message = con.getResponseMessage();
            LOG.info("Returned " + response + " " + message);
            assertEquals("status response: " + message, expected, response);
            
            con.disconnect();
        } catch (IOException ex) {
            LOG.error("IOException", ex);
            fail(ex.getMessage());
        }
        
        // POST (multipart/form-data)
        if (!skipMultipartTest) {
            try {
                HttpURLConnection con = sendPostMultipartFormData(fields);

                int response = con.getResponseCode();
                String message = con.getResponseMessage();
                LOG.info("Returned " + response + " " + message);
                assertEquals("status response: " + message, expected, response);

                con.disconnect();
            } catch (IOException ex) {
                LOG.error("IOException", ex);
                fail(ex.getMessage());
            }
        }
    }
    
}
