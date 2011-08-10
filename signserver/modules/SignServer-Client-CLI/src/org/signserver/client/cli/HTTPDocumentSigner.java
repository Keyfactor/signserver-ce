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
package org.signserver.client.cli;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;


/**
 * DocumentSigner using the HTTP protocol.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class HTTPDocumentSigner extends AbstractDocumentSigner {
    public static final String CRLF = "\r\n";

    private static final String BASICAUTH_AUTHORIZATION = "Authorization";

    private static final String BASICAUTH_BASIC = "Basic";

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(HTTPDocumentSigner.class);

    private static final String BOUNDARY = "------------------signserver";

    private String workerName;

    private URL processServlet;

    private String username;

    private String password;

    public HTTPDocumentSigner(final URL processServlet,
            final String workerName, final String username,
            final String password) {
        this.processServlet = processServlet;
        this.workerName = workerName;
        this.username = username;
        this.password = password;
    }

    protected void doSign(final byte[] data, final String encoding,
            final OutputStream out, final Map<String,Object> requestContext)
            throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException,
                IOException {

//        final int requestId = random.nextInt();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending sign request "
                    + " containing data of length " + data.length + " bytes"
                    + " to worker " + workerName);
        }

        // Take start time
        final long startTime = System.nanoTime();

        final Response response = sendRequest(processServlet, workerName, data,
                requestContext);

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
            final String workerName, final byte[] data,
            final Map<String, Object> requestContext) {
        
        OutputStream out = null;
        InputStream in = null;
        try {
            final URLConnection conn = processServlet.openConnection();
            conn.setDoOutput(true);
            conn.setAllowUserInteraction(false);

            if (username != null && password != null) {
                conn.setRequestProperty(BASICAUTH_AUTHORIZATION, 
                        BASICAUTH_BASIC + " "
                        + new String(Base64.encode((username + ":" + password).getBytes())));
            }
            
            final StringBuilder sb = new StringBuilder();
            sb.append("--" + BOUNDARY);
            sb.append(CRLF);
            sb.append("Content-Disposition: form-data; name=\"workerName\"");
            sb.append(CRLF);
            sb.append(CRLF);
            sb.append(workerName);
            sb.append(CRLF);
            sb.append("--" + BOUNDARY);
            sb.append(CRLF);
            sb.append("Content-Disposition: form-data; name=\"datafile\"");
            sb.append("; filename=\"");
            if (requestContext.get("FILENAME") == null) {
                sb.append("noname.dat");
            } else {
                sb.append(requestContext.get("FILENAME"));
            }
            sb.append("\"");
            sb.append(CRLF);
            sb.append("Content-Type: application/octet-stream");
            sb.append(CRLF);
            sb.append("Content-Transfer-Encoding: binary");
            sb.append(CRLF);
            sb.append(CRLF);

            conn.addRequestProperty("Content-Type",
                    "multipart/form-data; boundary=" + BOUNDARY);
            conn.addRequestProperty("Content-Length", String.valueOf(
                    sb.toString().length() + BOUNDARY.length() + 8-1));
            
            out = conn.getOutputStream();
            
            out.write(sb.toString().getBytes());
            out.write(data);
            out.write(("\r\n--" + BOUNDARY + "--\r\n").getBytes());
            out.flush();

            // Get the response
            in = conn.getInputStream();
            final ByteArrayOutputStream os = new ByteArrayOutputStream();
            int len;
            final byte[] buf = new byte[1024];
            while ((len = in.read(buf)) > 0) {
                os.write(buf, 0, len);
            }
            os.close();

            return new Response(os.toByteArray());
        } catch (IOException ex) {
            throw new RuntimeException(ex);
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
