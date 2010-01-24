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
import org.signserver.server.tsa.org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericServletRequest;
import org.signserver.common.GenericServletResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.IWorkerLogger;

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
 * @author Markus Kilas
 * @version $Id$
 */
public class TSADispatcherServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Logger LOG =
            Logger.getLogger(TSADispatcherServlet.class);
    
    private static final String REQUEST_CONTENT_TYPE
            = "application/timestamp-query";
    private static final String RESPONSE_CONTENT_TYPE
            = "application/timestamp-reply";
    private static final long MAX_REQUEST_SIZE = 10 * 1024 * 1024; // 10 MB
    
    private static final String TSADISPATCHER_LOOKUPCLASS =
            "TSADISPATCHER_LOOKUPCLASS";
    
    private static final String DEFAULT_WORKERLOOKUP_CLASS =
            DefaultTimeStampSignerLookup.class.getName();
    
    private final Random random = new Random();

    private IWorkerSession.ILocal workersession;
    private IGlobalConfigurationSession.ILocal gCSession;

    private IWorkerLookup workerLookup;
    private String workerLookupClass;
    

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

        // Pass-through the content to be handled by worker if
        // unknown content-type
        if (LOG.isDebugEnabled()) {
            LOG.debug("Request Content-type: " + req.getContentType());
        }

        if (!REQUEST_CONTENT_TYPE.equals(req.getContentType())) {
            res.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        final String remoteAddr = req.getRemoteAddr();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Received a request with length: "
                    + req.getContentLength() + " from " + remoteAddr);
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
                LOG.error("Content length exceeds 10MB, not processed: "
                        + req.getContentLength());
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
            final X509Certificate cert = (X509Certificate) clientCertificate;
            credential = new CertificateClientCredential(
                    cert.getSerialNumber().toString(16),
                    cert.getIssuerDN().getName());
        } else {
            credential = new UsernamePasswordClientCredential(
                    req.getParameter("username"),
                    req.getParameter("password"));
        }

        final RequestContext context = new RequestContext(clientCertificate,
                remoteAddr);
        final Map<String, String> logMap = new HashMap<String, String>();
        context.put(RequestContext.LOGMAP, logMap);

        // Add HTTP specific log entries
        logMap.put(IWorkerLogger.LOG_REQUEST_FULLURL, getFullURL(req));
        logMap.put(IWorkerLogger.LOG_REQUEST_LENGTH,
                String.valueOf(data.length));

        if (data.length < 1) {
            res.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Malformed request");
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
        final String worker = getWorkerLookup().lockupClientAuthorizedWorker(
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
            } catch (TSPException e) {
                throw new ServletException(e);
            }
        } else {
            try {
                workerId = Integer.parseInt(worker);
            } catch (NumberFormatException ignored) {
            }

            if (workerId < 1) {
                workerId = getWorkerSession().getWorkerId(worker);
            }

            // Create a signing request
            final int requestId = random.nextInt();

            GenericServletResponse response = null;
            try {
                response = (GenericServletResponse) getWorkerSession().process(
                        workerId, new GenericServletRequest(requestId, data, req),
                        context);
            } catch (IllegalRequestException e) {
                throw new ServletException(e);
            } catch (CryptoTokenOfflineException e) {
                throw new ServletException(e);
            } catch (SignServerException e) {
                throw new ServletException(e);
            }

            if (response.getRequestID() != requestId) {
                throw new ServletException("Error in process operation, "
                        + "response id didn't match request id");
            }
            processedBytes = (byte[]) response.getProcessedData();
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
     * @throws
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
}
