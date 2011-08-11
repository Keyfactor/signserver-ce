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
import java.util.Map;
import java.util.Map.Entry;
import org.apache.log4j.Logger;
import org.signserver.testutils.ModulesTestCase;

/**
 * Abstract test case that can be used by test cases that wants to the HTTP 
 * interface.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class WebTestCase extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SODProcessServletResponseTest.class);
    
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
            assertEquals("status response: " + message, expected, response);

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
            assertEquals("status response: " + message, expected, response);

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
                assertEquals("status response: " + message, expected, response);

                con.disconnect();
            } catch (IOException ex) {
                LOG.error("IOException", ex);
                fail(ex.getMessage());
            }
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

    protected static HttpURLConnection sendGet(String baseURL,
            final Map<String, String> fields)
            throws IOException {
        final StringBuilder buff = new StringBuilder();
        for (Entry<String, String> entry : fields.entrySet()) {
            buff.append(entry.getKey()).append("=").append(URLEncoder.encode(entry.getValue(), "UTF-8")).append("&");
        }
        final String body = buff.toString();
        return openConnection(baseURL, body);
    }

    protected static HttpURLConnection sendPostFormUrlencoded(final String baseURL,
            final Map<String, String> fields) throws MalformedURLException, IOException {
        final StringBuilder buff = new StringBuilder();
        for (Entry<String, String> entry : fields.entrySet()) {
            buff.append(entry.getKey()).append("=").append(URLEncoder.encode(entry.getValue(), "UTF-8")).append("&");
        }
        final String body = buff.toString();

        HttpURLConnection con = openConnection(baseURL, null);
        con.setRequestMethod("POST");
        con.setAllowUserInteraction(false);
        con.setDoOutput(true);
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        PrintWriter out = new PrintWriter(con.getOutputStream());
        out.print(body);
        out.close();
        return con;
    }

    protected static HttpURLConnection sendPostMultipartFormData(final String baseURL,
            final Map<String, String> fields) throws MalformedURLException, IOException {

        final String boundary =
                "---------------------------1004178514282965110854332084";

        HttpURLConnection con = openConnection(baseURL, null);
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
}
