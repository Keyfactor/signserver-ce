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
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.SignServerException;
import static org.signserver.common.SignServerConstants.X_SIGNSERVER_ERROR_MESSAGE;

/**
 * DocumentSigner using the HTTP protocol.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class HTTPDocumentSigner extends AbstractHTTPDocumentSigner {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(HTTPDocumentSigner.class);

    public HTTPDocumentSigner(final HostManager hostsManager,
            final int port,
            final String baseUrlPath,
            final String servlet,
            final boolean useHTTPS,
            final String workerName,
            final String username,
            final String password,
            final String accessToken,
            final String pdfPassword,
            final Map<String, String> metadata,
            final int timeOutLimit) {
        super(hostsManager, port, baseUrlPath, servlet, useHTTPS, workerName, username, password, accessToken, pdfPassword, metadata, timeOutLimit);
    }

    public HTTPDocumentSigner(final HostManager hostsManager,
            final int port,
            final String baseUrlPath,
            final String servlet,
            final boolean useHTTPS,
            final int workerId,
            final String username, final String password,
            final String accessToken,
            final String pdfPassword,
            final Map<String, String> metadata,
            final int timeOutLimit) {
        super(hostsManager, port, baseUrlPath, servlet, useHTTPS, workerId, username, password, accessToken, pdfPassword, metadata, timeOutLimit);

    }

    @Override
    protected URL createServletURL(String host) throws MalformedURLException, SignServerException {
        if (servlet != null) {
            return new URL(useHTTPS ? "https" : "http", host, port, servlet);
        } else {
            return new URL(useHTTPS ? "https" : "http", host, port, baseUrlPath + "/process");
        }
    }

    @Override
    protected void sendRequest(final URL processServlet,
            final InputStream in,
            final long size,
            final OutputStream out, final Map<String, Object> requestContext) throws IOException {
        
        OutputStream requestOut = null;
        InputStream responseIn = null;        

        // set it false in beginning as signing will be tried with new host
        connectionFailure = false;

        try {
            final HttpURLConnection conn = (HttpURLConnection) processServlet.openConnection();
            
            // only set timeout for connection when provided on command line
            if (timeOutLimit != -1) {
                conn.setConnectTimeout(timeOutLimit);
            }
            
            conn.setDoOutput(true);
            conn.setAllowUserInteraction(false);

            if (username != null && password != null) {
                conn.setRequestProperty(BASICAUTH_AUTHORIZATION, 
                        BASICAUTH_BASIC + " "
                        + new String(Base64.encode((username + ":" + password).getBytes())));
            } else if (accessToken != null) {
                conn.setRequestProperty(BASICAUTH_AUTHORIZATION,
                        BASICAUTH_BEARER + " " + accessToken);
            }
            
            final StringBuilder sb = new StringBuilder();
            sb.append("--" + BOUNDARY);
            sb.append(CRLF);
            
            if (workerName == null && workerId.isPresent()) {
                sb.append("Content-Disposition: form-data; name=\"workerId\"");
                sb.append(CRLF);
                sb.append(CRLF);
                sb.append(workerId.get());
                sb.append(CRLF);
            } else if (workerName != null) {
                sb.append("Content-Disposition: form-data; name=\"workerName\"");
                sb.append(CRLF);
                sb.append(CRLF);
                sb.append(workerName);
                sb.append(CRLF);
            }
            
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
              
                // display customized error message sent from server, if exists, instead of default(ex: Bad Request)
                String clientResponseMessage = conn.getResponseMessage();
                Map<String, List<String>> map = conn.getHeaderFields();
                List<String> errorList = map.get(X_SIGNSERVER_ERROR_MESSAGE);
                if (errorList != null) {
                    clientResponseMessage = errorList.toString();
                }
                
                throw new HTTPException(processServlet, responseCode, clientResponseMessage, errorBody);
            }
        } catch (ConnectException | SocketTimeoutException | UnknownHostException ex) {
            connectionFailure = true;
            LOG.error("Connection failure occurred: " + ex.getMessage());
            throw ex;
        } catch (HTTPException ex) {
            if (ex.getResponseCode() == HttpServletResponse.SC_NOT_FOUND || ex.getResponseCode() == HttpServletResponse.SC_SERVICE_UNAVAILABLE || ex.getResponseCode() == HttpServletResponse.SC_INTERNAL_SERVER_ERROR) {
                connectionFailure = true;
                LOG.error("Connection failure occurred: " + ex.getMessage());
            }
            throw ex;
        } catch (HttpRetryException ex) {
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
                IOUtils.closeQuietly(requestOut);
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
