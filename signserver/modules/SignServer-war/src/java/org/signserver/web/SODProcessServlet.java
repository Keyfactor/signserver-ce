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
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import javax.ejb.EJB;

import javax.naming.NamingException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.ejbca.util.Base64;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.RequestContext;
import org.signserver.common.SODSignRequest;
import org.signserver.common.SODSignResponse;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerException;
import org.signserver.ejb.interfaces.IWorkerSession;

/**
 * SODProcessServlet is a Servlet that takes data group hashes from a htto post and puts them in a Map for passing
 * to the MRTD SOD Signer. It uses the worker configured by either workerId or workerName parameters from the request, defaulting to workerId 1.
 * 
 * It will create a SODSignRequest that is sent to the worker and expects a SODSignResponse back from the signer.
 * This is not located in the mrtdsod module package because it has to be available at startup to map urls.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class SODProcessServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SODProcessServlet.class);
    
    private static final String CONTENT_TYPE_BINARY = "application/octet-stream";
    private static final String CONTENT_TYPE_TEXT = "text/plain";
    
    private static final String DISPLAYCERT_PROPERTY_NAME = "displayCert";
    private static final String DOWNLOADCERT_PROPERTY_NAME = "downloadCert";
    private static final String WORKERID_PROPERTY_NAME = "workerId";
    private static final String WORKERNAME_PROPERTY_NAME = "workerName";
    private static final String DATAGROUP_PROPERTY_NAME = "dataGroup";
    
    /** Specifies if the fields are encoded in any way */
    private static final String ENCODING_PROPERTY_NAME = "encoding";
    
    /** Default, values will be base64 decoded before use */
    /** if encoding = binary values will not be base64 decoded before use */
    private static final String ENCODING_BINARY = "binary";
    
    /** Request to use a specific LDS version in the SOd. **/
    private static final String LDSVERSION_PROPERTY_NAME = "ldsVersion";
    
    /** Request to put a specific unicode version in the SOd. **/
    private static final String UNICODE_PROPERTY_NAME = "unicodeVersion";
    
    @EJB
    private IWorkerSession.ILocal workersession;

    private IWorkerSession.ILocal getWorkerSession() {
        if (workersession == null) {
            try {
                workersession = ServiceLocator.getInstance().lookupLocal(IWorkerSession.ILocal.class);
            } catch (NamingException e) {
                LOG.error(e);
            }
        }

        return workersession;
    }

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
    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">doPost()");
        }

        int workerId = 1;
        String ldsVersion = null;
        String unicodeVersion = null;

        String name = req.getParameter(WORKERNAME_PROPERTY_NAME);
        if (name != null) {
            LOG.debug("Found a signerName in the request: " + name);
            workerId = getWorkerSession().getWorkerId(name);
        }
        String id = req.getParameter(WORKERID_PROPERTY_NAME);
        if (id != null) {
            LOG.debug("Found a signerId in the request: " + id);
            workerId = Integer.parseInt(id);
        }

        String remoteAddr = req.getRemoteAddr();

        // If the command is to display the signer certificate, print it.
        String displayCert = req.getParameter(DISPLAYCERT_PROPERTY_NAME);
        String downloadCert = req.getParameter(DOWNLOADCERT_PROPERTY_NAME);
        if ((displayCert != null) && (displayCert.length() > 0)) {
            LOG.info("Recieved display cert request for worker " + workerId + ", from ip " + remoteAddr);
            displaySignerCertificate(res, workerId);
        } else if ((downloadCert != null) && (downloadCert.length() > 0)) {
            LOG.info("Recieved download cert request for worker " + workerId + ", from ip " + remoteAddr);
            sendSignerCertificate(res, workerId);
        } else {
            // If the command is to process the signing request, do that.
            LOG.info("Recieved HTTP process request for worker " + workerId + ", from ip " + remoteAddr);

            boolean base64Encoded = true;
            String encoding = req.getParameter(ENCODING_PROPERTY_NAME);
            if (encoding != null && !"".equals(encoding)) {
                if (ENCODING_BINARY.equalsIgnoreCase(encoding)) {
                    base64Encoded = false;
                }
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Base64Encoded=" + base64Encoded);
            }

            // Collect all [dataGroup1, dataGroup2, ..., dataGroupN]
            Map<Integer, byte[]> dataGroups = new HashMap<Integer, byte[]>(16);
            Enumeration en = req.getParameterNames();
            while (en.hasMoreElements()) {
                Object o = en.nextElement();
                if (o instanceof String) {
                    String key = (String) o;
                    if (key.startsWith(DATAGROUP_PROPERTY_NAME)) {
                        try {
                            Integer dataGroupId = new Integer(key.substring(DATAGROUP_PROPERTY_NAME.length()));
                            if ((dataGroupId > -1) && (dataGroupId < 17)) {
                                String dataStr = req.getParameter(key);
                                if ((dataStr != null) && (dataStr.length() > 0)) {
                                    byte[] data = dataStr.getBytes();
                                    if (LOG.isDebugEnabled()) {
                                        LOG.debug("Adding data group " + key);
                                        if (LOG.isTraceEnabled()) {
                                            LOG.trace("with value " + dataStr);
                                        }
                                    }
                                    dataGroups.put(dataGroupId, base64Encoded ? Base64.decode(data) : data);
                                }
                            } else {
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("Ignoring data group " + dataGroupId);
                                }
                            }
                        } catch (NumberFormatException ex) {
                            LOG.warn("Field does not start with \"" + DATAGROUP_PROPERTY_NAME + "\" and ends with a number: \"" + key + "\"");
                        }
                    }
                }
            }

            if (dataGroups.isEmpty()) {
                sendBadRequest(res, "Missing dataGroup fields in request");
                return;
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Received number of dataGroups: " + dataGroups.size());
            }

            // LDS versioning
            ldsVersion = req.getParameter(LDSVERSION_PROPERTY_NAME);
            unicodeVersion = req.getParameter(UNICODE_PROPERTY_NAME);
            if (ldsVersion != null && ldsVersion.trim().isEmpty()) {
                ldsVersion = null;
            }
            if (unicodeVersion != null && unicodeVersion.trim().isEmpty()) {
                unicodeVersion = null;
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Requested versions: LDS=" + ldsVersion
                        + ", Unicode=" + unicodeVersion);
            }

            // Get the client certificate, if any is passed in an https exchange, to be used for client authentication
            Certificate clientCertificate = null;
            Certificate[] certificates = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
            if (certificates != null) {
                clientCertificate = certificates[0];
            }

            Random rand = new Random();
            int requestId = rand.nextInt();

            final SODSignRequest signRequest = new SODSignRequest(requestId,
                    dataGroups, ldsVersion, unicodeVersion);
            SODSignResponse response = null;
            try {
                final RequestContext context = new RequestContext((X509Certificate) clientCertificate, remoteAddr);
                final String xForwardedFor = req.getHeader(RequestContext.X_FORWARDED_FOR);
                
                if (xForwardedFor != null) {
                    context.put(RequestContext.X_FORWARDED_FOR, xForwardedFor);
                }
                
                response = (SODSignResponse) getWorkerSession().process(workerId, signRequest, context);

                if (response.getRequestID() != requestId) {
                    LOG.error("Response ID " + response.getRequestID()
                            + " not matching request ID " + requestId);
                    res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                            "Error in process operation, response id didn't match request id");
                    return;
                }
                byte[] processedBytes = (byte[]) response.getProcessedData();

                res.setContentType(CONTENT_TYPE_BINARY);
                res.setContentLength(processedBytes.length);
                res.getOutputStream().write(processedBytes);
                res.getOutputStream().close();
            } catch (NoSuchWorkerException ex) {
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Worker Not Found");
            } catch (IllegalRequestException e) {
                res.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
            } catch (CryptoTokenOfflineException e) {
                res.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, e.getMessage());
            } catch (SignServerException e) {
                res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
            }
        }

        LOG.debug("<doPost()");
    } //doPost

    private void displaySignerCertificate(final HttpServletResponse response,
            final int workerId) throws IOException {
        LOG.debug(">displaySignerCertificate()");
        Certificate cert = null;
        try {
            cert = getWorkerSession().getSignerCertificate(workerId);
        } catch (CryptoTokenOfflineException ignored) {
        }
        response.setContentType(CONTENT_TYPE_TEXT);
        if (cert == null) {
            response.getWriter().print(
                    "No signing certificate found for worker with id "
                    + workerId);
        } else {
            response.getWriter().print(cert);
        }
        LOG.debug("<displaySignerCertificate()");
    }

    private void sendSignerCertificate(final HttpServletResponse response,
            final int workerId) throws IOException {
        LOG.debug(">sendSignerCertificate()");
        Certificate cert = null;
        try {
            cert = getWorkerSession().getSignerCertificate(workerId);
        } catch (CryptoTokenOfflineException ignored) {
        }
        try {
            if (cert == null) {
                response.getWriter().print(
                        "No signing certificate found for worker with id "
                        + workerId);
            } else {
                byte[] bytes;
                bytes = cert.getEncoded();
                response.setContentType(CONTENT_TYPE_BINARY);
                response.setHeader("Content-Disposition", "filename=cert.crt");
                response.setContentLength(bytes.length);
                response.getOutputStream().write(bytes);
                response.getOutputStream().close();
            }
        } catch (CertificateEncodingException e) {
            LOG.error("Error encoding certificate: ", e);
            response.getWriter().print("Error encoding certificate: "
                    + e.getMessage());
        }
        LOG.debug("<sendSignerCertificate()");
    }

    /**
     * Handles http get.
     *
     * @param req servlet request
     * @param res servlet response
     *
     * @throws IOException input/output error
     * @throws ServletException error
     */
    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse res) throws java.io.IOException, ServletException {
        LOG.debug(">doGet()");
        doPost(req, res);
        LOG.debug("<doGet()");
    } // doGet

    private static void sendBadRequest(HttpServletResponse res, String message)
            throws IOException {
        LOG.info("Bad request: " + message);
        res.sendError(HttpServletResponse.SC_BAD_REQUEST, message);
    }
}
