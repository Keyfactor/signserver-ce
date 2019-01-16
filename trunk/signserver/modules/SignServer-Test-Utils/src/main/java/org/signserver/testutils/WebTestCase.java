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
package org.signserver.testutils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.Map.Entry;
import org.apache.log4j.Logger;

/**
 * Abstract test case that can be used by test cases that wants to the HTTP 
 * interface.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class WebTestCase extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(WebTestCase.class);
    
    protected static final Map<String, String> NO_FIELDS = Collections.emptyMap();
    
    private static final String CRLF = "\r\n";

    protected abstract String getServletURL();

    /** Tests that the returned HTTP status code is the expected. */
    protected void assertStatusReturned(Map<String, String> fields,
            int expected) {
        assertStatusReturned(fields, expected, false);
    }

    /** 
     * Tests that the returned HTTP status code is the expected. 
     * Optionally ignoring to test using multipart/form-data "upload".
     */
    protected void assertStatusReturned(Map<String, String> fields,
            int expected, boolean skipMultipartTest) {
        // GET
        try {
            HttpURLConnection con = WebTestCase.sendGet(getServletURL(), fields);
            int response = con.getResponseCode();
            String message = con.getResponseMessage();
            LOG.info("Returned " + response + " " + message);
            
            byte[] body = readBody(con);
            if (expected != response) {
                LOG.info("Returned body: " + new String(body));
            }
            
            assertEquals("GET: status response: " + message, expected, response);

            con.disconnect();
        } catch (IOException ex) {
            LOG.error("IOException", ex);
            fail(ex.getMessage());
        }

        // POST (url-encoded)
        try {
            HttpURLConnection con = WebTestCase.sendPostFormUrlencoded(
                    getServletURL(), fields);

            int response = con.getResponseCode();
            String message = con.getResponseMessage();
            LOG.info("Returned " + response + " " + message);
            assertEquals("POST url-encoded: status response: " + message, expected, response);

            con.disconnect();
        } catch (IOException ex) {
            LOG.error("IOException", ex);
            fail(ex.getMessage());
        }

        // POST (multipart/form-data)
        if (!skipMultipartTest) {
            try {
                HttpURLConnection con = WebTestCase.sendPostMultipartFormData(
                        getServletURL(), fields);

                int response = con.getResponseCode();
                String message = con.getResponseMessage();
                LOG.info("Returned " + response + " " + message);
                assertEquals("POST multipart/form-data: status response: " + message, expected, response);

                con.disconnect();
            } catch (IOException ex) {
                LOG.error("IOException", ex);
                fail(ex.getMessage());
            }
        }
    }
    
    /**
     * Tests that the returned HTTP status code is expected, use the specified HTTP method
     * @see HttpURLConnection#setRequestMethod
     */
    protected void assertStatusReturned(Map<String, String> fields, String method,
    		int expected) {
    	try {
    		HttpURLConnection con = WebTestCase.send(getServletURL(), fields, method);
    		
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
    
    /**
     * Query using the specified fields and HTTP method and returns the status
     * code.
     */
    protected int queryStatusReturned(final Map<String, String> fields, final String method) throws IOException {
        HttpURLConnection con = null;
        try {
            con = WebTestCase.send(getServletURL(), fields, method);

            final int response = con.getResponseCode();
            final String message = con.getResponseMessage();
            LOG.info("Returned " + response + " " + message);
            return response;  
        } finally {
            if (con != null) {
                con.disconnect();
            }
        }
    }

    /**
     * Tests that the returned HTTP status code is not the one passed to the method,
     * use the specified HTTP method.
     * @see HttpURLConnection#setRequestMethod
     */
    protected void assertStatusReturnedNotEqual(Map<String, String> fields, String method,
    		int notExpected) {
    	try {
    		HttpURLConnection con = WebTestCase.send(getServletURL(), fields, method);
    		
    		int response = con.getResponseCode();
    		String message = con.getResponseMessage();
    		LOG.info("Returned " + response + " " + message);
    		assertFalse("status response: " + message, notExpected == response);
    		
    		con.disconnect();
    	} catch (IOException ex) {
    		LOG.error("IOException", ex);
    		fail(ex.getMessage());
    	}
    }
    
    protected static HttpURLConnection openConnection(String baseURL, String queryString)
            throws MalformedURLException, IOException {
        final StringBuilder buff = new StringBuilder();
        buff.append(baseURL);
        if (queryString != null) {
            buff.append("?");
            buff.append(queryString);
        }
        final URL url = new URL(buff.toString());
        return (HttpURLConnection) url.openConnection();
    }
    
    protected static HttpURLConnection getConnectionWithMethod(String baseURL,
    		final Map<String, String> fields, String method) throws IOException {
    	final StringBuilder buff = new StringBuilder();
        for (Entry<String, String> entry : fields.entrySet()) {
            buff.append(entry.getKey()).append("=").append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8.name())).append("&");
        }
        final String body = buff.toString();
        HttpURLConnection con = openConnection(baseURL, body);
        
        con.setRequestMethod(method);
        
        return con;
    }

    protected static HttpURLConnection sendGet(String baseURL,
            final Map<String, String> fields)
            throws IOException {
        return getConnectionWithMethod(baseURL, fields, "GET");
    }
    
    protected static HttpURLConnection send(String baseURL,
    		final Map<String, String> fields, String method) throws IOException {
    	return getConnectionWithMethod(baseURL, fields, method);
    }
    
    protected static byte[] sendAndReadyBody(String baseURL,
    		final Map<String, String> fields) throws IOException {
        return sendAndReadyBody(baseURL, fields, "GET");
    }
    
    protected byte[] sendAndReadyBody(final Map<String, String> fields) throws IOException {
        return sendAndReadyBody(getServletURL(), fields, "GET");
    }
    
    protected static byte[] sendAndReadyBody(String baseURL,
    		final Map<String, String> fields, String method) throws IOException {
        HttpURLConnection conn = null;
        try {
            conn = getConnectionWithMethod(baseURL, fields, method);
            
            LOG.info("Response (" + conn.getResponseCode() + "): " + conn.getResponseMessage());
            return readBody(conn);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        } 
    }
    
    /**
     * Read the body of a response from the connection.
     * @param conn Connection where a response is ready to be read
     * @return returned bytes
     * @throws IOException in case of error reading etc
     */
    private static byte[] readBody(HttpURLConnection conn) throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        InputStream in = null;
        try {
            if (conn.getResponseCode() >= 400) {
                in = conn.getErrorStream();
            } else {
                in = conn.getInputStream();
            }

            int b;
            while ((b = in.read()) != -1) {
                bout.write(b);
            }
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
        return bout.toByteArray();
    }

    protected static HttpURLConnection sendPostFormUrlencoded(final String baseURL,
            final Map<String, String> fields) throws MalformedURLException, IOException {
        return sendPostFormUrlencoded(baseURL, fields, Collections.<String, String>emptyMap());
    }

    public static HttpURLConnection sendPostFormUrlencoded(final String baseURL,
            final Map<String, String> fields, final Map<String, String> headers) throws MalformedURLException, IOException {
        final StringBuilder buff = new StringBuilder();
        for (Entry<String, String> entry : fields.entrySet()) {
            buff.append(entry.getKey()).append("=").append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8.name())).append("&");
        }
        final String body = buff.toString();

        HttpURLConnection con = openConnection(baseURL, null);
        con.setRequestMethod("POST");
        con.setAllowUserInteraction(false);
        con.setDoOutput(true);
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        for (Map.Entry<String, String> header : headers.entrySet()) {
            con.setRequestProperty(header.getKey(), header.getValue());
        }
        try (PrintWriter out = new PrintWriter(con.getOutputStream())) {
            out.print(body);
        }
        return con;
    }

    protected static byte[] sendPostFormUrlencodedReadBody(final String baseURL,
            final Map<String, String> fields) throws MalformedURLException, IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        HttpURLConnection conn = null;
        InputStream in = null;
        try {
            conn = sendPostFormUrlencoded(baseURL, fields);
            
            LOG.info("Response (" + conn.getResponseCode() + "): " + conn.getResponseMessage());
            conn.getResponseCode();
            
            in = conn.getInputStream();
            
            int b;
            while ((b = in.read()) != -1) {
                bout.write(b);
            }
            
            return bout.toByteArray();
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {} // NOPMD
            }
            conn.disconnect();
        }
    }

    protected static HttpURLConnection sendPostMultipartFormData(final String baseURL,
            final Map<String, String> fields) throws MalformedURLException, IOException {
        return sendPostMultipartFormData(baseURL, fields, "data");
    }
    
    protected static HttpURLConnection sendPostMultipartFormData(final String baseURL,
            final Map<String, String> fields, String fileName) throws MalformedURLException, IOException {

        final String boundary =
                "---------------------------1004178514282965110854332084";

        HttpURLConnection con = openConnection(baseURL, null);
        con.setRequestMethod("POST");
        con.setAllowUserInteraction(false);
        con.setDoOutput(true);
        con.setRequestProperty("Content-Type",
                "multipart/form-data; boundary=" + boundary);

        try (PrintWriter out = new PrintWriter(con.getOutputStream())) {
            for (Entry<String, String> field : fields.entrySet()) {
                out.print("--");
                out.print(boundary);
                out.print(CRLF);
                out.print("Content-Disposition: form-data; name=\"");
                out.print(field.getKey());
                out.print("\"");
                if (field.getKey().equals("data")) {
                    out.print("; filename=\"" + fileName + "\"");
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
        }
        return con;
    }
}
