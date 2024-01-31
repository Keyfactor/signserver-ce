/** ***********************************************************************
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
 ************************************************************************ */
package org.signserver.client.cli.defaultimpl;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.HttpRetryException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.io.IOUtils;
import org.signserver.common.SignServerException;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import static org.signserver.common.SignServerConstants.X_SIGNSERVER_ERROR_MESSAGE;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.signserver.common.RequestContext;



/**
 * DocumentSigner using the REST protocol.
 *
 * @author Hanna Hansson
 * @version $Id$
 */
public class RESTDocumentSigner extends AbstractHTTPDocumentSigner {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(RESTDocumentSigner.class);


    public RESTDocumentSigner(HostManager hostsManager,
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

    public RESTDocumentSigner(final HostManager hostsManager,
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
            return new URL(useHTTPS ? "https" : "http", host, port, baseUrlPath + "/rest/v1/workers/" + workerName + "/process");
        }
    }

    @Override
    protected void sendRequest(final URL processServlet,
            final InputStream in,
            final long size,
            final OutputStream out, final Map<String, Object> requestContext) throws IOException {

        OutputStream requestOut = null;
        InputStream responseIn = null;
        connectionFailure = false;

        try {
            final HttpURLConnection conn = (HttpURLConnection) processServlet.openConnection();

            // only set timeout for connection when provided on command line
            if (timeOutLimit != -1) {
                conn.setConnectTimeout(timeOutLimit);
            }

            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-Keyfactor-Requested-With", "signclient");
            conn.setDoOutput(true);
            conn.setAllowUserInteraction(false);

            if (username != null && password != null) {
                conn.setRequestProperty(BASICAUTH_AUTHORIZATION,
                        BASICAUTH_BASIC + " "
                        + new String(Base64.encode((username + ":" + password).getBytes(StandardCharsets.UTF_8))));
            }
            else if (accessToken != null) {
                conn.setRequestProperty(BASICAUTH_AUTHORIZATION,
                        BASICAUTH_BEARER + " " + accessToken);
            }

            final StringBuilder sb = new StringBuilder();
            JSONObject jsonMain = new JSONObject();

            if (workerName == null && workerId.isPresent()) {
                jsonMain.put("WorkerID", workerId);
            } else if (workerName != null) {
                jsonMain.put("WorkerName", workerName);
            }

            if (metadata != null) {
                JSONObject jsonSub = new JSONObject();
                for (final String key : metadata.keySet()) {
                    final String value = metadata.get(key);
                    jsonSub.put(key, value);
                }
                if (pdfPassword != null) {
                    jsonSub.put(RequestContext.METADATA_PDFPASSWORD, pdfPassword);
                }
                jsonMain.put("metaData", jsonSub);
            }

            if (requestContext.get("FILENAME") == null) {
                jsonMain.put("filename", "noname.dat");
            } else {
                jsonMain.put("filename", requestContext.get("FILENAME"));
            }

            requestOut = conn.getOutputStream();
            jsonMain.put("encoding", "BASE64");
            jsonMain.put("data", Base64.toBase64String(IOUtils.toByteArray(in)));
            sb.append(jsonMain);
            requestOut.write(sb.toString().getBytes("utf-8"));
            requestOut.flush();


            // Get the response
            final int responseCode = conn.getResponseCode();
            responseIn = conn.getErrorStream();
            if (responseIn == null) {
                responseIn = conn.getInputStream();
            }

            if (responseCode < 400) {
                final JSONParser parser = new JSONParser();
                final InputStreamReader reader =
                        new InputStreamReader(responseIn, "UTF-8");

                try {
                    final JSONObject jsonObject = (JSONObject) parser.parse(reader);

                    final Object data = jsonObject.get("data");

                    if (data == null) {
                        throw new IOException("No data in response");
                    } else if (!(data instanceof String)) {
                        throw new IOException("Malformed data");
                    }

                    out.write(Base64.decode((String) data));
                } catch (ParseException ex) {
                    throw new IOException("Error parsing response", ex);
                }
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
