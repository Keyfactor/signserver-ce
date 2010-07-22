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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.ejb.EJB;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileItemFactory;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericServletRequest;
import org.signserver.common.GenericServletResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.CertificateClientCredential;
import org.signserver.server.IClientCredential;
import org.signserver.server.IWorkerLogger;
import org.signserver.server.UsernamePasswordClientCredential;



/**
 * GenericProcessServlet is a general Servlet passing on it's request info to the worker configured by either
 * workerId or workerName parameters.
 * 
 * It will create a GenericServletRequest that is sent to the worker and expects a GenericServletResponse
 * sent back to the client.
 * 
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class GenericProcessServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final String FORM_URL_ENCODED = "application/x-www-form-urlencoded";
    private static final String METHOD_GET = "GET";

    private static final Logger LOG = Logger.getLogger(
            GenericProcessServlet.class);

    private static final String WORKERID_PROPERTY_NAME = "workerId";
    private static final String WORKERNAME_PROPERTY_NAME = "workerName";
    private static final String DATA_PROPERTY_NAME = "data";
    private static final String ENCODING_PROPERTY_NAME = "encoding";
    private static final String ENCODING_BASE64 = "base64";
    private static final long MAX_UPLOAD_SIZE = 100 * 1024 * 1024; // 100MB (100*1024*1024);

    private static final String HTTP_AUTH_BASIC_AUTHORIZATION = "Authorization";

    private static final String HTTP_AUTH_BASIC_WWW_AUTHENTICATE =
            "WWW-Authenticate";

    private final Random random = new Random();

    @EJB
    private IWorkerSession.ILocal workersession;

    private IWorkerSession.ILocal getWorkerSession() {
        if (workersession == null) {
            try {
                Context context = new InitialContext();
                workersession = (org.signserver.ejb.interfaces.IWorkerSession.ILocal) context.lookup(IWorkerSession.ILocal.JNDI_NAME);
            } catch (NamingException e) {
                LOG.error(e);
            }
        }

        return workersession;
    }

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
    public void doPost(HttpServletRequest req, HttpServletResponse res)
            throws IOException, ServletException {
        LOG.debug(">doPost()");

        int workerId = 1;
        byte[] data = null;
        String fileName = null;

        if (ServletFileUpload.isMultipartContent(req)) {
            final FileItemFactory factory = new DiskFileItemFactory();
            final ServletFileUpload upload = new ServletFileUpload(factory);

            // Limit the maximum size of input
            upload.setSizeMax(MAX_UPLOAD_SIZE);

            try {
                final List<FileItem> items = upload.parseRequest(req);
                final Iterator iter = items.iterator();
                FileItem fileItem = null;
                while (iter.hasNext()) {
                    final FileItem item = (FileItem) iter.next();

                    if (item.isFormField()) {
                        if (WORKERNAME_PROPERTY_NAME.equals(item.getFieldName())) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Found a signerName in the request: "
                                        + item.getString());
                            }
                            workerId = getWorkerSession().getWorkerId(item.getString());
                        } else if (WORKERID_PROPERTY_NAME.equals(item.getFieldName())) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Found a signerId in the request: "
                                        + item.getString());
                            }
                            try {
                                workerId = Integer.parseInt(item.getString());
                            } catch (NumberFormatException ignored) {}
                        }
                    } else {
                        // We only care for one upload at a time right now
                        if (fileItem == null) {
                            fileItem = item;
                        }
                    }
                }

                if (fileItem == null) {
                    throw new ServletException("Missing file content in upload");
                }

                fileName = fileItem.getName();
                data = fileItem.get();

            } catch (FileUploadException ex) {
                throw new ServletException("Upload failed", ex);
            }
        } else {

            String name = req.getParameter(WORKERNAME_PROPERTY_NAME);
            if(name != null){
                if(LOG.isDebugEnabled()) {
                    LOG.debug("Found a signerName in the request: "+name);
                }
                workerId = getWorkerSession().getWorkerId(name);
            }
            String id = req.getParameter(WORKERID_PROPERTY_NAME);
            if(id != null){
                if(LOG.isDebugEnabled()) {
                    LOG.debug("Found a signerId in the request: "+id);
                }
                workerId = Integer.parseInt(id);
            }

            if(METHOD_GET.equalsIgnoreCase(req.getMethod()) ||
                    (req.getContentType() != null && req.getContentType().contains(FORM_URL_ENCODED))) {
                LOG.debug("Request is FORM_URL_ENCODED");

                if(req.getParameter(DATA_PROPERTY_NAME) == null) {
                    throw new ServletException("Missing field 'data' in request");
                }
                data = req.getParameter(DATA_PROPERTY_NAME).getBytes();

                String encoding = req.getParameter(ENCODING_PROPERTY_NAME);
                if(encoding != null && !"".equals(encoding)) {
                    if(ENCODING_BASE64.equalsIgnoreCase(encoding)) {
                        LOG.info("Decoding base64 data");
                        data = org.ejbca.util.Base64.decode(data);
                    } else {
                        throw new ServletException("Unknown encoding for the 'data' field: " + encoding);
                    }
                }
            } else {
                // Pass-through the content to be handled by worker if
                // unknown content-type
                if(LOG.isDebugEnabled()) {
                    LOG.debug("Request Content-type: " + req.getContentType());
                }

                // Get an input stream and read the bytes from the stream
                InputStream in = req.getInputStream();
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                int len = 0;
                byte[] buf = new byte[1024];
                while ((len = in.read(buf)) > 0) {
                    os.write(buf, 0, len);
                }
                in.close();
                os.close();
                data = os.toByteArray();
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Received a request with length: "
                    + req.getContentLength());
        }

        // Limit the maximum size of input
        if (data.length > MAX_UPLOAD_SIZE) {
            LOG.error("Content length exceeds 100MB, not processed: " + req.getContentLength());
            throw new ServletException("Error. Maximum content lenght is 100MB.");
        }

        processRequest(req, res, workerId, data, fileName);

        LOG.debug("<doPost()");
    } //doPost

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

    private void processRequest(HttpServletRequest req, HttpServletResponse res, int workerId, byte[] data, String fileName) throws java.io.IOException, ServletException {
        LOG.debug("Using signerId: " + workerId);

        final String remoteAddr = req.getRemoteAddr();
        LOG.info("Recieved HTTP process request for worker " + workerId + ", from ip " + remoteAddr);

        // Client certificate
        Certificate clientCertificate = null;
        Certificate[] certificates = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
        if (certificates != null) {
            clientCertificate = certificates[0];
        }

        final RequestContext context = new RequestContext(clientCertificate,
                remoteAddr);

        IClientCredential credential;

        if (clientCertificate instanceof X509Certificate) {
            final X509Certificate cert = (X509Certificate) clientCertificate;
            LOG.debug("Authentication: certificate");
            credential = new CertificateClientCredential(
                    cert.getSerialNumber().toString(16),
                    cert.getIssuerDN().getName());
        } else {
            // Check is client supplied basic-credentials
            final String authorization =
                        req.getHeader(HTTP_AUTH_BASIC_AUTHORIZATION);
            if (authorization != null) {
                LOG.debug("Authentication: password");

                final String decoded[] = new String(Base64.decode(
                        authorization.split("\\s")[1])).split(":", 2);

                credential = new UsernamePasswordClientCredential(
                    decoded[0], decoded[1]);
            } else {
                LOG.debug("Authentication: none");
                credential = null;
            }
        }
        context.put(RequestContext.CLIENT_CREDENTIAL, credential);

        
        final Map<String,String> logMap = new HashMap<String, String>();
        context.put(RequestContext.LOGMAP, logMap);

        // Add HTTP specific log entries
        logMap.put(IWorkerLogger.LOG_REQUEST_FULLURL, req.getRequestURL()
                .append("?").append(req.getQueryString()).toString());
        logMap.put(IWorkerLogger.LOG_REQUEST_LENGTH,
                String.valueOf(data.length));
        logMap.put(IWorkerLogger.LOG_FILENAME, fileName);
        logMap.put(IWorkerLogger.LOG_XFORWARDEDFOR,
                req.getHeader("X-Forwarded-For"));

        // Store filename for use by archiver etc
        if (fileName != null) {
            fileName = stripPath(fileName);
        }
        context.put(RequestContext.FILENAME, fileName);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Received bytes of length: " + data.length);
        }

        final int requestId = random.nextInt();
        
        GenericServletResponse response = null;
        try {
            response = (GenericServletResponse) getWorkerSession().process(workerId,
                    new GenericServletRequest(requestId, data, req), context);
        } catch(AuthorizationRequiredException e) {
            LOG.debug("Sending back HTTP 401");

            final String httpAuthBasicRealm = "SignServer Worker " + workerId;

            res.setHeader(HTTP_AUTH_BASIC_WWW_AUTHENTICATE,
                    "Basic realm=\"" + httpAuthBasicRealm + "\"");
                res.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                        "Authorization Required");
            return;
        } catch (IllegalRequestException e) {
            throw new ServletException(e);
        } catch (CryptoTokenOfflineException e) {
            throw new ServletException(e);
        } catch (SignServerException e) {
            throw new ServletException(e);
        }

        if (response.getRequestID() != requestId) {
            throw new ServletException("Error in process operation, response id didn't match request id");
        }
        byte[] processedBytes = (byte[]) response.getProcessedData();

        res.setContentType(response.getContentType());
        if(fileName != null) {
            res.setHeader("Content-Disposition", "attachment; filename=\"" + fileName + "\"");
        }
        res.setContentLength(processedBytes.length);
        res.getOutputStream().write(processedBytes);
        res.getOutputStream().close();
    }

    /**
     * @param fileName The original filename.
     * @return The filename with file path removed.
     */
    static String stripPath(String fileName) {
        if (fileName.contains("\\")) {
            fileName = fileName.substring(fileName.lastIndexOf("\\") + 1);
        }
        if (fileName.contains("/")) {
            fileName = fileName.substring(fileName.lastIndexOf("/") + 1);
        }
        return fileName;
    }
}
