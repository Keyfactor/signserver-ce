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
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.Optional;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.apache.log4j.Logger;

/**
 * Abstract implementation of AbstractDocumentSigner for HTTP and REST.
 *
 * @author Hanna Hansson
 */
public abstract class AbstractHTTPDocumentSigner extends AbstractDocumentSigner {

    public static final String CRLF = "\r\n";

    static final String DEFAULT_LOAD_BALANCING = "NONE";

    static final String ROUND_ROBIN_LOAD_BALANCING = "ROUND_ROBIN";

    static final String BASICAUTH_AUTHORIZATION = "Authorization";

    static final String BASICAUTH_BASIC = "Basic";
    static final String BASICAUTH_BEARER = "Bearer";

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(AbstractHTTPDocumentSigner.class);

    static final String BOUNDARY = "------------------signserver";

    final String workerName;
    final Optional<Integer> workerId;

    /**
     * List of host names to try to connect to, or distribute load on for load
     * balancing
     */
    private final HostManager hostsManager;
    final int port;
    final String baseUrlPath;
    final String servlet;
    final boolean useHTTPS;

    String username;
    String password;

    /**
     * Access token when using JWT authentication.
     */
    String accessToken;

    /**
     * Password used for changing the PDF if required (user or owner password).
     */
    String pdfPassword;

    Map<String, String> metadata;
    final int timeOutLimit;

    boolean connectionFailure;

    public AbstractHTTPDocumentSigner(final HostManager hostsManager,
            final int port,
            final String baseUrlPath,
            final String servlet,
            final boolean useHTTPS,
            final String workerName,
            final String username, final String password,
            final String accessToken,
            final String pdfPassword,
            final Map<String, String> metadata, final int timeOutLimit) {
        this.hostsManager = hostsManager;
        this.port = port;
        this.baseUrlPath = baseUrlPath;
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

    public AbstractHTTPDocumentSigner(final HostManager hostsManager,
            final int port,
            final String baseUrlPath,
            final String servlet,
            final boolean useHTTPS,
            final int workerId,
            final String username, final String password,
            final String accessToken,
            final String pdfPassword,
            final Map<String, String> metadata, final int timeOutLimit) {
        this.hostsManager = hostsManager;
        this.port = port;
        this.baseUrlPath = baseUrlPath;
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
    public void doSign(final InputStream in, final long size, final String encoding,
            final OutputStream out, final Map<String, Object> requestContext)
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
            internalDoSign(in, size, out, requestContext, nextHost);
        }
    }

    public void internalDoSign(final InputStream in, final long size,
            final OutputStream out, final Map<String, Object> requestContext, String host)
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
                    internalDoSign(in, size, out, requestContext, nextHost);
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

    protected abstract URL createServletURL(String host) throws MalformedURLException, SignServerException;

    protected abstract void sendRequest(final URL processServlet,
            final InputStream in,
            final long size,
            final OutputStream out, final Map<String, Object> requestContext) throws IOException;

}
