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
package org.signserver.client.cli.defaultimpl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;


/**
 * Signs data groups using the HTTP(s) interface.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class HTTPSODSigner extends AbstractSODSigner {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(HTTPSODSigner.class);

    public static final String CRLF = "\r\n";

    private static final String BASICAUTH_AUTHORIZATION = "Authorization";

    private static final String BASICAUTH_BASIC = "Basic";

    private final String workerName;
    private final int workerId;

    private URL processServlet;

    private String username;
    private String password;
    
    private Map<String, String> metadata;

    public HTTPSODSigner(final URL processServlet,
            final String workerName, final String username,
            final String password,
            final Map<String, String> metadata) {
        this.processServlet = processServlet;
        this.workerName = workerName;
        this.workerId = 0;
        this.username = username;
        this.password = password;
        this.metadata = metadata;
    }
    
    public HTTPSODSigner(final URL processServlet,
            final int workerId, final String username,
            final String password,
            final Map<String, String> metadata) {
        this.processServlet = processServlet;
        this.workerName = null;
        this.workerId = workerId;
        this.username = username;
        this.password = password;
        this.metadata = metadata;
    }

    @Override
    protected void doSign(final Map<Integer,byte[]> dataGroups, final String encoding,
            final OutputStream out) throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException,
                IOException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending sign request "
                    + " containing " + dataGroups.size() + " datagroups"
                    + " to worker " + workerName);
        }

        // Take start time
        final long startTime = System.nanoTime();

        final Response response = sendRequest(processServlet, workerName, 
                dataGroups,  encoding);

        // Take stop time
        final long estimatedTime = System.nanoTime() - startTime;

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Got sign response "
                    + "with signed data of length %d bytes.",
                    response.getData().length));
        }

        // Write the signed data
        out.write(response.getData());

        if (LOG.isInfoEnabled()) {
            LOG.info("Processing took "
                + TimeUnit.NANOSECONDS.toMillis(estimatedTime) + " ms");
        }
    }

    private Response sendRequest(final URL processServlet,
            final String workerName, final Map<Integer, byte[]> data,
            final String encoding) throws IOException {
        
        OutputStream out = null;
        InputStream in = null;
        try {
            final HttpURLConnection conn =
                    (HttpURLConnection) processServlet.openConnection();
            conn.setDoOutput(true);
            conn.setAllowUserInteraction(false);

            if (username != null && password != null) {
                conn.setRequestProperty(BASICAUTH_AUTHORIZATION, 
                        BASICAUTH_BASIC + " "
                        + new String(Base64.encode(new StringBuilder()
                        .append(username).append(":").append(password)
                        .toString().getBytes())));
            }
            
            final StringBuilder sb = new StringBuilder();
            if (workerId == 0) {
                sb.append("workerName=").append(workerName).append("&");
            } else {
                sb.append("workerId=").append(workerId).append("&");
            }
            sb.append("encoding=").append(encoding).append("&");
            for (Map.Entry<Integer, byte[]> entry : data.entrySet()) {
                sb.append("dataGroup").append(entry.getKey()).append("=")
                    .append(URLEncoder.encode(new String(entry.getValue()), StandardCharsets.UTF_8.name()))
                    .append("&");
            }

            if (metadata != null) {
                for (final String key : metadata.keySet()) {
                    final String value = metadata.get(key);
                    
                    sb.append("REQUEST_METADATA.").append(key)
                        .append("=").append(URLEncoder.encode(value, StandardCharsets.UTF_8.name()))
                        .append("&");
                }
            }
            
            conn.setRequestProperty("Content-Type",
                    "application/x-www-form-urlencoded");
            conn.addRequestProperty("Content-Length", String.valueOf(
                    sb.toString().length()));
            
            out = conn.getOutputStream();
            
            out.write(sb.toString().getBytes());
            out.flush();

            // Get the response
            final int responseCode = conn.getResponseCode();
            
            if (responseCode >= 400) {
                in = conn.getErrorStream();
            } else {
                in = conn.getInputStream();
            }

            final ByteArrayOutputStream os = new ByteArrayOutputStream();
            int len;
            final byte[] buf = new byte[1024];
            while ((len = in.read(buf)) > 0) {
                os.write(buf, 0, len);
            }
            os.close();
            
            if (responseCode >= 400) {
                throw new HTTPException(processServlet, responseCode,
                                        conn.getResponseMessage(),
                                        os.toByteArray());
            }

            return new Response(os.toByteArray());
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }
        }

    }

    private static class Response {

        private byte[] data;

        public Response(byte[] data) {
            this.data = data;
        }

        public byte[] getData() {
            return data;
        }        
    }

}
