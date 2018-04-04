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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.HttpRetryException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.Map;
import org.apache.log4j.Logger;
import org.apache.commons.io.IOUtils;
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
    static final String DEFAULT_TIMEOUT_LIMIT = "500";

    private static final String BASICAUTH_AUTHORIZATION = "Authorization";

    private static final String BASICAUTH_BASIC = "Basic";

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(HTTPDocumentSigner.class);

    private static final String BOUNDARY = "------------------signserver";

    private final String workerName;
    private final int workerId;

    private URL processServlet;

    private String username;
    private String password;

    /** Password used for changing the PDF if required (user or owner password). */
    private String pdfPassword;
    
    private Map<String, String> metadata;
    private final int timeOutLimit;

    public HTTPDocumentSigner(final URL processServlet,
            final String workerName,
            final String username, final String password,
            final String pdfPassword,
            final Map<String, String> metadata, final int timeOutLimit) {
        this.processServlet = processServlet;
        this.workerName = workerName;
        this.workerId = 0;
        this.username = username;
        this.password = password;
        this.pdfPassword = pdfPassword;
        this.metadata = metadata;
        this.timeOutLimit = timeOutLimit;
    }
    
    public HTTPDocumentSigner(final URL processServlet,
            final int workerId, 
            final String username, final String password,
            final String pdfPassword,
            final Map<String, String> metadata, final int timeOutLimit) {
        this.processServlet = processServlet;
        this.workerName = null;
        this.workerId = workerId;
        this.username = username;
        this.password = password;
        this.pdfPassword = pdfPassword;
        this.metadata = metadata;
        this.timeOutLimit = timeOutLimit;
    }

    @Override
    protected void doSign(final InputStream in, final long size, final String encoding,
            final OutputStream out, final Map<String,Object> requestContext)
            throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException,
                IOException {

//        final int requestId = random.nextInt();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending sign request "
                    + " containing data of length " + size + " bytes"
                    + " to worker " + workerName);
        }
        sendRequest(processServlet, in, size, out, requestContext);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Got sign response");
        }
    }

    private void sendRequest(final URL processServlet,
            final InputStream in,
            final long size,
            final OutputStream out, final Map<String, Object> requestContext) throws IOException {
        
        OutputStream requestOut = null;
        InputStream responseIn = null;
        boolean connectionFailure = false;
        try {
            final HttpURLConnection conn = (HttpURLConnection) processServlet.openConnection();
            conn.setConnectTimeout(timeOutLimit);
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
            
            if (workerName == null) {
                sb.append("Content-Disposition: form-data; name=\"workerId\"");
                sb.append(CRLF);
                sb.append(CRLF);
                sb.append(workerId);
            } else {
                sb.append("Content-Disposition: form-data; name=\"workerName\"");
                sb.append(CRLF);
                sb.append(CRLF);
                sb.append(workerName);
            }
            sb.append(CRLF);
            
            if (pdfPassword != null) {
                sb.append("--" + BOUNDARY).append(CRLF)
                    .append("Content-Disposition: form-data; name=\"pdfPassword\"").append(CRLF)
                    .append(CRLF)
                    .append(pdfPassword).append(CRLF);
            }
            
            if (metadata != null) {
                for (final String key : metadata.keySet()) {
                    final String value = metadata.get(key);
                    
                    sb.append("--" + BOUNDARY).append(CRLF)
                        .append("Content-Disposition: form-data; name=\"REQUEST_METADATA." + key + "\"").append(CRLF)
                        .append(CRLF)
                        .append(value).append(CRLF);
                }
            }

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

            final byte[] preData = sb.toString().getBytes("ASCII");
            final byte[] postData = ("\r\n--" + BOUNDARY + "--\r\n").getBytes("ASCII");
            
            if (size >= 0) {
                final long totalSize = (long) preData.length + size + (long) postData.length;
                conn.setFixedLengthStreamingMode(totalSize);
            }

            // Write the request: preData, data, postData
            requestOut = conn.getOutputStream();
            requestOut.write(preData);
            final long copied = IOUtils.copyLarge(in, requestOut);
            if (copied != size) {
                throw new IOException("Expected file size of " + size + " but only read " + copied + " bytes");
            }
            requestOut.write(postData);
            requestOut.flush();

            // Get the response
            final int responseCode = conn.getResponseCode();
            responseIn = conn.getErrorStream();
            if (responseIn == null) {             
                responseIn = conn.getInputStream();
            }

            // Read the body to the output if OK otherwise to the error message
            if (responseCode < 400) {
                IOUtils.copy(responseIn, out);
            } else {
                final byte[] errorBody = IOUtils.toByteArray(responseIn);
                throw new HTTPException(processServlet, responseCode, conn.getResponseMessage(), errorBody);
            }
        }
        catch (ConnectException | SocketTimeoutException ex) {
            connectionFailure = true;
            LOG.error("Connection Failure occurred ");
            throw ex; //TODO: remove this and try signing on another host 
        }   
        catch (HttpRetryException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(ex.getReason());
            }
            if (ex.responseCode() == 401) {
                throw new HTTPException(processServlet, 401, "Authentication required", null);
            } else {
                throw ex;
            }
        } finally {
            if (requestOut != null) {
                try {
                    requestOut.close();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }
            if (responseIn != null) {
                try {
                    responseIn.close();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }
        }

    }

}
