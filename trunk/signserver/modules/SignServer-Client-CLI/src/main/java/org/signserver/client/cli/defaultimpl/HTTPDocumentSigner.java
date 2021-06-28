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
import java.util.Optional;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import static org.signserver.common.SignServerConstants.X_SIGNSERVER_ERROR_MESSAGE;

/**
 * DocumentSigner using the HTTP protocol.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class HTTPDocumentSigner extends AbstractDocumentSigner {
    public static final String CRLF = "\r\n";   
        
    static final String DEFAULT_LOAD_BALANCING = "NONE";
    
    static final String ROUND_ROBIN_LOAD_BALANCING = "ROUND_ROBIN";    

    private static final String BASICAUTH_AUTHORIZATION = "Authorization";

    private static final String BASICAUTH_BASIC = "Basic";
    private static final String BASICAUTH_BEARER = "Bearer";

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(HTTPDocumentSigner.class);

    private static final String BOUNDARY = "------------------signserver";

    private final String workerName;
    private final Optional<Integer> workerId;

    /** List of host names to try to connect to, or distribute load on for
     *  load balancing
     */
    private final HostManager hostsManager;
    private final int port;
    private final String servlet;
    private final boolean useHTTPS;

    private String username;
    private String password;

    /** Access token when using JWT authentication. */
    private String accessToken;
    
    /** Password used for changing the PDF if required (user or owner password). */
    private String pdfPassword;
    
    private Map<String, String> metadata;
    private final int timeOutLimit;
    
    private boolean connectionFailure;

    public HTTPDocumentSigner(final HostManager hostsManager,
            final int port,
            final String servlet,
            final boolean useHTTPS,
            final String workerName,
            final String username, final String password,
            final String accessToken,
            final String pdfPassword,
            final Map<String, String> metadata, final int timeOutLimit) {        
        this.hostsManager = hostsManager;
        this.port = port;
        this.servlet = servlet;
        this.useHTTPS = useHTTPS;
        this.workerName = workerName;
        this.workerId = Optional.empty();
        this.username = username;
        this.password = password;
        this.accessToken = accessToken;
        this.pdfPassword = pdfPassword;
        this.metadata = metadata;
        this.timeOutLimit = timeOutLimit;
    }
    
    public HTTPDocumentSigner(final HostManager hostsManager,
            final int port,
            final String servlet,
            final boolean useHTTPS,
            final int workerId, 
            final String username, final String password,
            final String accessToken,
            final String pdfPassword,
            final Map<String, String> metadata, final int timeOutLimit) {        
        this.hostsManager = hostsManager;
        this.port = port;
        this.servlet = servlet;
        this.useHTTPS = useHTTPS;
        this.workerName = null;
        this.workerId = Optional.of(workerId);
        this.username = username;
        this.password = password;
        this.accessToken = accessToken;
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

        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending sign request "
                    + " containing data of length " + size + " bytes"
                    + (workerName != null ? " to worker " + workerName : ""));
        }
        
        final String nextHost = hostsManager.getNextHostForRequest();
        if (nextHost == null) {
            throw new SignServerException("No more hosts to try");
        } else {
            internalDoSign(in, size, encoding, out, requestContext, nextHost);
        }
    }
    
    protected void internalDoSign(final InputStream in, final long size, final String encoding,
            final OutputStream out, final Map<String,Object> requestContext, String host)
            throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException,
                IOException {
        
        final URL url = createServletURL(host);
        
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Sending to URL: " + url.toString());
            }

            sendRequest(url, in, size, out, requestContext);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Got sign response");
            }
        } catch (IOException e) {
            if (connectionFailure) {
                hostsManager.removeHost(host);

                // re-try with next host in list
                final String nextHost = hostsManager.getNextHostForRequestWhenFailure();
                if (nextHost == null) {
                    throw new SignServerException("No more hosts to try");
                } else {
                    internalDoSign(in, size, encoding, out, requestContext, nextHost);
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Failed sending request ", e);
                }
                LOG.error("Failed sending request: " + e.getMessage());
                throw e;
            }
        }
    }
    
    private URL createServletURL(String host) throws MalformedURLException, SignServerException {
        return new URL(useHTTPS ? "https" : "http", host, port, servlet);
    }

    private void sendRequest(final URL processServlet,
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
