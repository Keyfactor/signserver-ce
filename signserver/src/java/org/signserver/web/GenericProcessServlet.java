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
import java.util.Iterator;
import java.util.List;
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
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericServletRequest;
import org.signserver.common.GenericServletResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.ejb.interfaces.IWorkerSession;



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

    private static Logger log = Logger.getLogger(GenericProcessServlet.class);

    private static final String WORKERID_PROPERTY_NAME = "workerId";
    private static final String WORKERNAME_PROPERTY_NAME = "workerName";
    private static final String DATA_PROPERTY_NAME = "data";
    private static final String ENCODING_PROPERTY_NAME = "encoding";
    private static final String ENCODING_BASE64 = "base64";
    private static final long MAX_UPLOAD_SIZE = 100 * 1024 * 1024; // 100MB (100*1024*1024);

    @EJB
    private IWorkerSession.ILocal workersession;

    private IWorkerSession.ILocal getWorkerSession() {
        if (workersession == null) {
            try {
                Context context = new InitialContext();
                workersession = (org.signserver.ejb.interfaces.IWorkerSession.ILocal) context.lookup(IWorkerSession.ILocal.JNDI_NAME);
            } catch (NamingException e) {
                log.error(e);
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
        log.debug(">doPost()");

        int workerId = 1;
        byte[] data = null;
        String fileName = null;

        if (ServletFileUpload.isMultipartContent(req)) {
            FileItemFactory factory = new DiskFileItemFactory();
            ServletFileUpload upload = new ServletFileUpload(factory);

            // Limit the maximum size of input
            upload.setSizeMax(MAX_UPLOAD_SIZE);

            try {
                List<FileItem> items = upload.parseRequest(req);
                Iterator iter = items.iterator();
                while (iter.hasNext()) {
                    FileItem item = (FileItem) iter.next();

                    if (item.isFormField()) {
                        if (WORKERNAME_PROPERTY_NAME.equals(item.getFieldName())) {
                            log.debug("Found a signerName in the request: " + item.getString());
                            workerId = getWorkerSession().getWorkerId(item.getString());
                        } else if (WORKERID_PROPERTY_NAME.equals(item.getFieldName())) {
                            log.debug("Found a signerId in the request: " + item.getString());
                            try {
                                workerId = Integer.parseInt(item.getString());
                            } catch (NumberFormatException ignored) {}
                        }
                    } else {
                        fileName = item.getName();
                        data = item.get();
                        
                        // We only care for one upload at a time right now
                        break;
                    }
                }
            } catch (FileUploadException ex) {
                throw new ServletException("Upload failed", ex);
            }
        } else {

            String name = req.getParameter(WORKERNAME_PROPERTY_NAME);
            if(name != null){
                if(log.isDebugEnabled()) {
                    log.debug("Found a signerName in the request: "+name);
                }
                workerId = getWorkerSession().getWorkerId(name);
            }
            String id = req.getParameter(WORKERID_PROPERTY_NAME);
            if(id != null){
                if(log.isDebugEnabled()) {
                    log.debug("Found a signerId in the request: "+id);
                }
                workerId = Integer.parseInt(id);
            }

            if(METHOD_GET.equalsIgnoreCase(req.getMethod()) ||
                    (req.getContentType() != null && req.getContentType().contains(FORM_URL_ENCODED))) {
                log.info("Request is FORM_URL_ENCODED");

                if(req.getParameter(DATA_PROPERTY_NAME) == null) {
                    throw new ServletException("Missing field 'data' in request");
                }
                data = req.getParameter(DATA_PROPERTY_NAME).getBytes();

                String encoding = req.getParameter(ENCODING_PROPERTY_NAME);
                if(encoding != null && !"".equals(encoding)) {
                    if(ENCODING_BASE64.equalsIgnoreCase(encoding)) {
                        log.info("Decoding base64 data");
                        data = org.ejbca.util.Base64.decode(data);
                    } else {
                        throw new ServletException("Unknown encoding for the 'data' field: " + encoding);
                    }
                }
            } else {
                log.info("Request Content-type: " + req.getContentType());

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

        // Limit the maximum size of input
        log.debug("Received a request with length: " + req.getContentLength());
        if (data.length > MAX_UPLOAD_SIZE) {
            log.error("Content length exceeds 100MB, not processed: " + req.getContentLength());
            throw new ServletException("Error. Maximum content lenght is 100MB.");
        }

        processRequest(req, res, workerId, data, fileName);

        log.debug("<doPost()");
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
        log.debug(">doGet()");
        doPost(req, res);
        log.debug("<doGet()");
    } // doGet

    private void processRequest(HttpServletRequest req, HttpServletResponse res, int workerId, byte[] data, String fileName) throws java.io.IOException, ServletException {
        log.debug("Using signerId: " + workerId);

        String remoteAddr = req.getRemoteAddr();
        log.info("Recieved HTTP process request for worker " + workerId + ", from ip " + remoteAddr);

        //
        Certificate clientCertificate = null;
        Certificate[] certificates = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
        if (certificates != null) {
            clientCertificate = certificates[0];
        }

        log.debug("Received bytes of length: " + data.length);

        Random rand = new Random();
        int requestId = rand.nextInt();

        GenericServletResponse response = null;
        try {
            response = (GenericServletResponse) getWorkerSession().process(workerId,
                    new GenericServletRequest(requestId, data, req),
                    new RequestContext((X509Certificate) clientCertificate,
                            remoteAddr));
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
}
