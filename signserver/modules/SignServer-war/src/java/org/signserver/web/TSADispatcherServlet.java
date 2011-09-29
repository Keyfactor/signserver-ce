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

import org.signserver.server.UsernamePasswordClientCredential;
import org.signserver.server.IWorkerLookup;
import org.signserver.server.DefaultTimeStampSignerLookup;
import org.signserver.server.IClientCredential;
import org.signserver.server.ITimeStampSignerLookup;
import org.signserver.server.CertificateClientCredential;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import javax.ejb.EJBException;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.server.tsa.org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.signserver.common.GenericServletRequest;
import org.signserver.common.GenericServletResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.RequestContext;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.log.ISystemLogger;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.NotGrantedException;
import org.signserver.server.log.SystemLoggerException;
import org.signserver.server.log.SystemLoggerFactory;

/**
 * Servlet for dispatching timestamping requests to the right TimeStampSigner
 * based on some policy.
 *
 * Global properties:
 *
 * TSADISPATCHER_LOOKUPCLASS = Fully qualified name of class with an
 * implementation of IWorkerLookup for deciding of a request is authorized and
 * to which worker.
 *
 * TSADISPATCHER_AUTHREQUIRED = True if the Servlet should request
 * authorization in case it gets a request without client certificate.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class TSADispatcherServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Logger LOG =
            Logger.getLogger(TSADispatcherServlet.class);

    /** Audit logger. */
    private static final ISystemLogger AUDITLOG = SystemLoggerFactory
            .getInstance().getLogger(TSADispatcherServlet.class);
    
    private static final String REQUEST_CONTENT_TYPE
            = "application/timestamp-query";
    private static final String RESPONSE_CONTENT_TYPE
            = "application/timestamp-reply";
    private static final long MAX_REQUEST_SIZE = 10 * 1024 * 1024; // 10 MB
    
    private static final String TSADISPATCHER_LOOKUPCLASS =
            "TSADISPATCHER_LOOKUPCLASS";

    private static final String TSADISPATCHER_AUTHREQUIRED =
            "TSADISPATCHER_AUTHREQUIRED";
    
    private static final String DEFAULT_WORKERLOOKUP_CLASS =
            DefaultTimeStampSignerLookup.class.getName();

    private static final String HTTP_AUTH_BASIC_AUTHORIZATION = "Authorization";

    private static final String HTTP_AUTH_BASIC_WWW_AUTHENTICATE =
            "WWW-Authenticate";
    
    private final Random random = new Random();

    private IWorkerSession.ILocal workersession;
    private IGlobalConfigurationSession.ILocal gCSession;

    private IWorkerLookup workerLookup;
    private String workerLookupClass;

    private String httpAuthBasicRealm = "TSA";
    
    @Override
    public void init(ServletConfig config) {
    }

    /**
     * handles http post
     *
     * @param req servlet request
     * @param res servlet response
     *
     * @throws IOException input/output error
     * @throws ServletException error
     */
    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse res)
            throws IOException, ServletException {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">doPost()");
        }

        // Start time
        final long startTime = System.currentTimeMillis();

        // Transaction ID
        final String transactionID = generateTransactionID();

        // Remote IP
        final String remoteAddr = req.getRemoteAddr();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Received a request with length: "
                    + req.getContentLength() + " from " + remoteAddr);
        }

        // Map of log entries
        final Map<String, String> logMap = new HashMap<String, String>();

        // Put in some log value
        logMap.put(IWorkerLogger.LOG_TIME, String.valueOf(startTime));
        logMap.put(IWorkerLogger.LOG_ID, transactionID);
        logMap.put(IWorkerLogger.LOG_CLIENT_IP, remoteAddr);

        // Pass-through the content to be handled by worker if
        // unknown content-type
        if (LOG.isDebugEnabled()) {
            LOG.debug("Request Content-type: " + req.getContentType());
        }

        if (!REQUEST_CONTENT_TYPE.equals(req.getContentType())) {
            res.sendError(HttpServletResponse.SC_BAD_REQUEST);

            // Auditlog
            logMap.put(IWorkerLogger.LOG_EXCEPTION, "Unexpected content-type");
            try {
                AUDITLOG.log(logMap);
            } catch (SystemLoggerException sle) {
                LOG.error("Audit log failure", sle);
            }
            return;
        }

        
        // Get an input stream and read the bytes from the stream
        final byte[] data;
        int totalLength = 0;
        InputStream in = req.getInputStream();
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        int len = 0;
        byte[] buf = new byte[1024];
        while ((len = in.read(buf)) > 0) {
            os.write(buf, 0, len);

            if ((totalLength += len) > MAX_REQUEST_SIZE) {
                final String error =
                        "Content length exceeds 10MB, not processed: "
                        + req.getContentLength();
                LOG.error(error);

                // Auditlog
                logMap.put(IWorkerLogger.LOG_EXCEPTION, error);
                try {
                    AUDITLOG.log(logMap);
                } catch (SystemLoggerException sle) {
                    LOG.error("Audit log failure", sle);
                }
                throw new ServletException("Error: Maximum request size exceded");
            }
        }
        in.close();
        os.close();
        data = os.toByteArray();

        IClientCredential credential;

        // Client certificate
        Certificate clientCertificate = null;
        Certificate[] certificates = (X509Certificate[])
                req.getAttribute("javax.servlet.request.X509Certificate");
        if (certificates != null) {
            clientCertificate = certificates[0];
        }

        if (clientCertificate instanceof X509Certificate) {
            LOG.debug("Authentication: certificate");

            final X509Certificate cert = (X509Certificate) clientCertificate;
            credential = new CertificateClientCredential(
                    cert.getSerialNumber().toString(16),
                    cert.getIssuerDN().getName());
        } else {

            // Check is client supplied basic-credentials
            final String authorization =
                        req.getHeader(HTTP_AUTH_BASIC_AUTHORIZATION);
            if (authorization == null) {

                if (isAuthenticationRequired()) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Sending back HTTP 401");
                    }
                    res.setHeader(HTTP_AUTH_BASIC_WWW_AUTHENTICATE,
                            "Basic realm=\"" + httpAuthBasicRealm + "\"");
                        res.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                                "Authorization Required");
                    return;
                } else {
                    LOG.debug("Authentication: none");
                    credential = null;
                }
            } else {
                LOG.debug("Authentication: password");

                final String decoded[] = new String(Base64.decode(
                        authorization.split("\\s")[1])).split(":", 2);

                credential = new UsernamePasswordClientCredential(
                    decoded[0], decoded[1]);
            }
        }

        final RequestContext context = new RequestContext(clientCertificate,
                remoteAddr);
        context.put(RequestContext.LOGMAP, logMap);
        context.put(RequestContext.CLIENT_CREDENTIAL, credential);

        // Add HTTP specific log entries
        logMap.put(IWorkerLogger.LOG_REQUEST_FULLURL, getFullURL(req));
        logMap.put(IWorkerLogger.LOG_REQUEST_LENGTH,
                String.valueOf(data.length));

        if (data.length < 1) {
            res.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Malformed request");

            // Auditlog
            logMap.put(IWorkerLogger.LOG_EXCEPTION, "Malformed request");
            try {
                AUDITLOG.log(logMap);
            } catch (SystemLoggerException sle) {
                LOG.error("Audit log failure", sle);
            }
            return;
        }

        // Parse Timestamprequest
        final TimeStampRequest timeStampRequest =
                new TimeStampRequest(data);

        // Add to context
        if (timeStampRequest.getReqPolicy() != null) {
            context.put(ITimeStampSignerLookup.TSA_REQUESTEDPOLICYOID,
                    timeStampRequest.getReqPolicy());
        }

        // Find to which worker the request should be dispatched
        int workerId = 0;
        final String worker = getWorkerLookup().lookupClientAuthorizedWorker(
                credential, context);

        byte[] processedBytes;

        // A null value means that we do not have an authorized mapping for this
        // user given the credentials and the requested policy oid
        if (worker == null) {
            try {
                final TimeStampResponseGenerator gen =
                        new TimeStampResponseGenerator(null, null);
                final TimeStampResponse resp = gen.generateFailResponse(
                        PKIStatus.REJECTION, PKIFailureInfo.badRequest,
                        "not authorized");
                processedBytes = resp.getEncoded();

                // Auditlog
                logMap.put(IWorkerLogger.LOG_CLIENT_AUTHORIZED, "false");
                logMap.put(IWorkerLogger.LOG_EXCEPTION, "not authorized");
                try {
                    AUDITLOG.log(logMap);
                } catch (SystemLoggerException sle) {
                    LOG.error("Audit log failure", sle);
                }
            } catch (TSPException e) {
                final String error = "not authorized + "
                        + "error creating response: " + e.getMessage();
                LOG.error(error, e);

                // Auditlog
                logMap.put(IWorkerLogger.LOG_CLIENT_AUTHORIZED, "false");
                logMap.put(IWorkerLogger.LOG_EXCEPTION, error);
                try {
                    AUDITLOG.log(logMap);
                } catch (SystemLoggerException sle) {
                    LOG.error("Audit log failure", sle);
                }
                throw new ServletException(e);
            }
        } else {
            try {
                workerId = Integer.parseInt(worker);
            } catch (NumberFormatException ignored) {}

            if (workerId < 1) {
                workerId = getWorkerSession().getWorkerId(worker);
            }

            // We have checked authorization
            context.put(RequestContext.DISPATCHER_AUTHORIZED_CLIENT, true);

            // Create a signing request
            final int requestId = random.nextInt();

            GenericServletResponse response = null;
            try {
                response = (GenericServletResponse) getWorkerSession().process(
                        workerId, new GenericServletRequest(requestId, data, req),
                        context);
                
                if (response.getRequestID() != requestId) {
                    throw new ServletException("Error in process operation, "
                        + "response id didn't match request id");
                }
                processedBytes = (byte[]) response.getProcessedData();
            } catch (NotGrantedException ex) { // Purchase not granted
                try {
                    final TimeStampResponseGenerator gen =
                            new TimeStampResponseGenerator(null, null);
                    final TimeStampResponse resp = gen.generateFailResponse(
                            PKIStatus.REJECTION, PKIFailureInfo.badRequest,
                            ex.getMessage());
                    processedBytes = resp.getEncoded();
                } catch (TSPException tspe) {
                    final String error = "Client was not granted purchase + "
                        + tspe.getMessage();
                    LOG.error(error, ex);

                    // Auditlog
                    logMap.put(IWorkerLogger.LOG_EXCEPTION, error);
                    try {
                        AUDITLOG.log(logMap);
                    } catch (SystemLoggerException sle) {
                        LOG.error("Audit log failure", sle);
                    }

                    final ServletException exception =
                            new ServletException(tspe);
                    LOG.error(exception);
                    throw exception;
                }
            } catch (Exception ex) {

                try {
                    final TimeStampResponseGenerator gen =
                            new TimeStampResponseGenerator(null, null);
                    final TimeStampResponse resp = gen.generateFailResponse(
                            PKIStatus.REJECTION, PKIFailureInfo.systemFailure,
                            ex.getMessage());
                    processedBytes = resp.getEncoded();
                } catch (TSPException tspe) {
                    final String error = "Multiple errors processing request: "
                        + ex.getMessage() + ", and: " 
                        + tspe.getMessage();
                    LOG.error(error, ex);

                    // Auditlog
                    logMap.put(IWorkerLogger.LOG_EXCEPTION, error);
                    try {
                        AUDITLOG.log(logMap);
                    } catch (SystemLoggerException sle) {
                        LOG.error("Audit log failure", sle);
                    }

                    final ServletException exception =
                            new ServletException(tspe);
                    LOG.error(exception);
                    throw exception;
                }                
            }
        }

        res.setContentType(RESPONSE_CONTENT_TYPE);
        res.setContentLength(processedBytes.length);
        res.getOutputStream().write(processedBytes);
        res.getOutputStream().close();


        LOG.debug("<doPost()");
    }

    /**
     * handles http get
     *
     * @param req servlet request
     * @param res servlet response
     *
     * @throws IOException input/output error
     * @throws ServletException error
     */
    public void doGet(HttpServletRequest req, HttpServletResponse res) throws java.io.IOException, ServletException {
        LOG.debug(">doGet()");
        doPost(req, res);
        LOG.debug("<doGet()");
    } // doGet

    private IWorkerLookup getWorkerLookup() {

        try {
            String configWorkerLookup = getGlobalConfigurationSession().getGlobalConfiguration().getProperty(
                    GlobalConfiguration.SCOPE_GLOBAL, TSADISPATCHER_LOOKUPCLASS);

            // WorkerLookup not loaded or changed, so update it
            if (workerLookup == null || workerLookupClass == null
                    || (configWorkerLookup != null
                    && !workerLookupClass.equals(configWorkerLookup))) {

                if (configWorkerLookup == null) {
                    configWorkerLookup = DEFAULT_WORKERLOOKUP_CLASS;
                }

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Will load TIMESTAMPSIGNERLOOKUP: "
                            + configWorkerLookup);
                }

                final Class<?> implClass = Class.forName(configWorkerLookup);
                final Object obj = implClass.newInstance();
                workerLookup = (IWorkerLookup) obj;
                workerLookupClass = configWorkerLookup;
            }

            return workerLookup;
        } catch (Exception e) {
            throw new EJBException("Error reading global config", e);
        }
    }

    private static String getFullURL(HttpServletRequest request) {
        StringBuffer str = request.getRequestURL();
        if (request.getQueryString() != null) {
            str.append("?");
            str.append(request.getQueryString());
        }
        return str.toString();
    }

    private boolean isAuthenticationRequired() {
        try {
            final String value = getGlobalConfigurationSession()
                    .getGlobalConfiguration().getProperty(
                        GlobalConfiguration.SCOPE_GLOBAL,
                        TSADISPATCHER_AUTHREQUIRED);

                return value == null ? true : Boolean.valueOf(value);
        } catch (Exception e) {
            throw new EJBException("Error reading global config", e);
        }
    }

    private IWorkerSession.ILocal getWorkerSession() {
        if (workersession == null) {
            try {
                final Context context = new InitialContext();
                workersession = (IWorkerSession.ILocal) context.lookup(
                        IWorkerSession.ILocal.JNDI_NAME);
            } catch (NamingException e) {
                LOG.error(e);
            }
        }

        return workersession;
    }

    private IGlobalConfigurationSession.ILocal getGlobalConfigurationSession() throws Exception {
        if (gCSession == null) {
            final Context context = new InitialContext();
            gCSession = (IGlobalConfigurationSession.ILocal) context.lookup(
                    IGlobalConfigurationSession.ILocal.JNDI_NAME);
        }
        return gCSession;
    }

    private String generateTransactionID() {
        return UUID.randomUUID().toString();
    }
}
