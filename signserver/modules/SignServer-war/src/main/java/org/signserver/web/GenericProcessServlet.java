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
import java.io.StringReader;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.ejb.EJB;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
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
import org.ejbca.util.CertTools;
import org.signserver.common.*;
import org.signserver.common.util.PropertiesConstants;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.CertificateClientCredential;
import org.signserver.server.IClientCredential;
import org.signserver.server.UsernamePasswordClientCredential;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;
import org.signserver.validationservice.common.Validation;

/**
 * GenericProcessServlet is a general Servlet passing on it's request info to the worker configured by either
 * workerId or workerName parameters.
 * 
 * It will create a GenericServletRequest that is sent to the worker and expects a GenericServletResponse
 * sent back to the client.
 *
 * @author Philip Vendil
 * @author Markus Kilås
 * @version $Id$
 */
public class GenericProcessServlet extends HttpServlet {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            GenericProcessServlet.class);
    
    private static final long serialVersionUID = 1L;
    private static final String FORM_URL_ENCODED = "application/x-www-form-urlencoded";
    private static final String METHOD_GET = "GET";    
    private static final String WORKERID_PROPERTY_NAME = "workerId";
    private static final String WORKERNAME_PROPERTY_NAME = "workerName";
    private static final String WORKERNAME_PROPERTY_OVERRIDE = "workerNameOverride";
    private static final String DATA_PROPERTY_NAME = "data";
    private static final String ENCODING_PROPERTY_NAME = "encoding";
    private static final String ENCODING_BASE64 = "base64";
    private static final long MAX_UPLOAD_SIZE = 100 * 1024 * 1024; // 100MB (100*1024*1024);
    private static final String HTTP_AUTH_BASIC_AUTHORIZATION = "Authorization";
    private static final String HTTP_AUTH_BASIC_WWW_AUTHENTICATE =
            "WWW-Authenticate";
    private static final String PDFPASSWORD_PROPERTY_NAME = "pdfPassword";

    private static final String PROCESS_TYPE_PROPERTY_NAME = "processType";
    private static final String CERT_PURPOSES_PROPERTY_NAME = "certPurposes";
    
    private static final String REQUEST_METADATA_PROPERTY_NAME = "REQUEST_METADATA";
    
    private enum ProcessType {
        signDocument,
        validateDocument,
        validateCertificate
    };
    
    private final Random random = new Random();
    
    // metadata properties set via the REQUEST_METADATA= syntax
    private Properties requestMetadata;
    // metadata set with REQUEST_METADATA.name=value overriding the above
    private Properties overrideRequestMetadata;

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

    /**
     * Handles http post.
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
        LOG.debug(">doPost()");

        int workerId = 1;
        byte[] data = null;
        String fileName = null;
        String pdfPassword = null;
        boolean workerRequest = false;

        if (LOG.isDebugEnabled()) {
            LOG.debug("Received a request with length: "
                    + req.getContentLength());
        }

        final String workerNameOverride =
        		(String) req.getAttribute(WORKERNAME_PROPERTY_OVERRIDE);
     
        if (workerNameOverride != null) {
        	workerId = getWorkerSession().getWorkerId(workerNameOverride);
        	workerRequest = true;
        }

        ProcessType processType = ProcessType.signDocument;
        
        requestMetadata = new Properties();
        overrideRequestMetadata = new Properties();
        
        if (ServletFileUpload.isMultipartContent(req)) {
            final FileItemFactory factory = new DiskFileItemFactory();
            final ServletFileUpload upload = new ServletFileUpload(factory);

            // Limit the maximum size of input
            upload.setSizeMax(MAX_UPLOAD_SIZE);

            try {
                final List items = upload.parseRequest(req);
                final Iterator iter = items.iterator();
                FileItem fileItem = null;
                String encoding = null;
                while (iter.hasNext()) {
                    final Object o = iter.next();
                    if (o instanceof FileItem) {
                        final FileItem item = (FileItem) o;

                        if (item.isFormField()) {
                            if (!workerRequest) {
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
                                    } catch (NumberFormatException ignored) {
                                    }
                                }
                            }
                            
                            final String itemFieldName = item.getFieldName();

                            if (PDFPASSWORD_PROPERTY_NAME.equals(itemFieldName)) {
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("Found a pdfPassword in the request.");
                                }
                                pdfPassword = item.getString("ISO-8859-1");
                            } else if (PROCESS_TYPE_PROPERTY_NAME.equals(itemFieldName)) {
                                final String processTypeAttribute = item.getString("ISO-8859-1");
                                
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("Found process type in the request: " + processTypeAttribute);
                                }
                                
                                if (processTypeAttribute != null) {
                                    try {
                                        processType = ProcessType.valueOf(processTypeAttribute);
                                    } catch (IllegalArgumentException e) {
                                        sendBadRequest(res, "Illegal process type: " + processTypeAttribute);
                                        return;
                                    }
                                } else {
                                    processType = ProcessType.signDocument;
                                }
                            } else if (ENCODING_PROPERTY_NAME.equals(itemFieldName)) {
                                encoding = item.getString("ISO-8859-1");
                            } else if (REQUEST_METADATA_PROPERTY_NAME.equals(itemFieldName) ||
                                    (itemFieldName != null &&
                                     itemFieldName.length() > REQUEST_METADATA_PROPERTY_NAME.length() + 1 &&
                                     itemFieldName.startsWith(REQUEST_METADATA_PROPERTY_NAME + "."))) {
                                try {
                                    handleMetaDataProperty(itemFieldName, item.getString("ISO-8859-1"));
                                } catch (IOException e) {
                                    sendBadRequest(res, "Malformed properties given using REQUEST_METADATA.");
                                }
                            }
                        } else {
                            // We only care for one upload at a time right now
                            if (fileItem == null) {
                                fileItem = item;
                            }
                        }
                    }
                }

                if (fileItem == null) {
                    sendBadRequest(res, "Missing file content in upload");
                    return;
                } else {
                    fileName = fileItem.getName();
                    data = fileItem.get();

                    if (encoding != null && !encoding.isEmpty()) {
                        if (ENCODING_BASE64.equalsIgnoreCase(encoding)) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Decoding base64 data");
                            }
                            data = Base64.decode(data);
                        } else {
                            sendBadRequest(res,
                                    "Unknown encoding for the 'data' field: "
                                    + encoding);
                            return;
                        }
                    }
                }
            } catch (FileUploadException ex) {
                throw new ServletException("Upload failed", ex);
            }
        } else {
            if (!workerRequest) {
                String name = req.getParameter(WORKERNAME_PROPERTY_NAME);
                if (name != null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Found a signerName in the request: " + name);
                    }
                    workerId = getWorkerSession().getWorkerId(name);
                }
                String id = req.getParameter(WORKERID_PROPERTY_NAME);
                if (id != null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Found a signerId in the request: " + id);
                    }
                    workerId = Integer.parseInt(id);
                }
            }
        	
            final Enumeration<String> params = req.getParameterNames();
            
            while (params.hasMoreElements()) {
                final String property = params.nextElement();
                if (PDFPASSWORD_PROPERTY_NAME.equals(property)) {
                    pdfPassword = (String) req.getParameter(PDFPASSWORD_PROPERTY_NAME);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Found a pdfPassword in the request.");
                    }
                } else if (REQUEST_METADATA_PROPERTY_NAME.equals(property) ||
                        (property.length() > REQUEST_METADATA_PROPERTY_NAME.length() + 1 &&
                         property.startsWith(REQUEST_METADATA_PROPERTY_NAME + "."))) {
                   try {
                       handleMetaDataProperty(property, req.getParameter(property));
                   } catch (IOException e) {
                       sendBadRequest(res, "Malformed properties given using REQUEST_METADATA.");
                   }
               }
            }
            
            
            
            final String processTypeAttribute = (String) req.getParameter(PROCESS_TYPE_PROPERTY_NAME);
            
            if (processTypeAttribute != null) {
                try {
                    processType = ProcessType.valueOf(processTypeAttribute);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Found process type in the request: " + processType.name());
                    }
                } catch (IllegalArgumentException e) {
                    sendBadRequest(res, "Illegal process type: " + processTypeAttribute);
                    return;
                }
            } else {
                processType = ProcessType.signDocument;
            }

            if (METHOD_GET.equalsIgnoreCase(req.getMethod())
                    || (req.getContentType() != null && req.getContentType().contains(FORM_URL_ENCODED))) {
                LOG.debug("Request is FORM_URL_ENCODED");

                if (req.getParameter(DATA_PROPERTY_NAME) == null) {
                    sendBadRequest(res, "Missing field 'data' in request");
                    return;
                }
                data = req.getParameter(DATA_PROPERTY_NAME).getBytes();

                String encoding = req.getParameter(ENCODING_PROPERTY_NAME);
                if (encoding != null && !encoding.isEmpty()) {
                    if (ENCODING_BASE64.equalsIgnoreCase(encoding)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Decoding base64 data");
                        }
                        data = Base64.decode(data);
                    } else {
                        sendBadRequest(res,
                                "Unknown encoding for the 'data' field: "
                                + encoding);
                        return;
                    }
                }
            } else {
                // Pass-through the content to be handled by worker if
                // unknown content-type
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Request Content-type: " + req.getContentType());
                }

                // Get an input stream and read the bytes from the stream
                InputStream in = req.getInputStream();
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                int len;
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
            LOG.debug("Request of type: " + processType.name());
        }
        
        // Limit the maximum size of input
        if (data.length > MAX_UPLOAD_SIZE) {
            LOG.error("Content length exceeds 100MB, not processed: " + req.getContentLength());
            res.sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                    "Maximum content length is 100 MB");
        } else {
            processRequest(req, res, workerId, data, fileName, pdfPassword, processType);
        }

        LOG.debug("<doPost()");
    } //doPost

    private void handleMetaDataProperty(final String propertyFieldName, final String propertyValue) throws IOException {
        if (propertyFieldName.length() == REQUEST_METADATA_PROPERTY_NAME.length()) {
            requestMetadata.load(new StringReader(propertyValue));
        } else {
            final String propertyName = propertyFieldName.substring(REQUEST_METADATA_PROPERTY_NAME.length() + 1);
            
            overrideRequestMetadata.setProperty(propertyName, propertyValue);
        }
    }
    
    private Properties mergeMetadataProperties() {
        requestMetadata.putAll(overrideRequestMetadata);
        return requestMetadata;
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

    private void processRequest(final HttpServletRequest req, final HttpServletResponse res, final int workerId, final byte[] data,
            String fileName, final String pdfPassword, final ProcessType processType) throws java.io.IOException, ServletException {
        final String remoteAddr = req.getRemoteAddr();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Recieved HTTP process request for worker " + workerId + ", from ip " + remoteAddr);
        }

        // Client certificate
        Certificate clientCertificate = null;
        Certificate[] certificates = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");
        if (certificates != null) {
            clientCertificate = certificates[0];
        }

        // Create request context and meta data
        final RequestContext context = new RequestContext(clientCertificate,
                remoteAddr);
        RequestMetadata metadata = RequestMetadata.getInstance(context);

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

        // Create log map
        LogMap logMap = LogMap.getInstance(context);

        final String xForwardedFor = req.getHeader(RequestContext.X_FORWARDED_FOR);
        
        // Add HTTP specific log entries
        logMap.put(IWorkerLogger.LOG_REQUEST_FULLURL, req.getRequestURL().append("?").append(req.getQueryString()).toString());
        logMap.put(IWorkerLogger.LOG_REQUEST_LENGTH,
                String.valueOf(data.length));
        logMap.put(IWorkerLogger.LOG_FILENAME, fileName);
        logMap.put(IWorkerLogger.LOG_XFORWARDEDFOR, xForwardedFor);
        logMap.put(IWorkerLogger.LOG_WORKER_NAME,
                getWorkerSession().getCurrentWorkerConfig(workerId).getProperty(PropertiesConstants.NAME));

        if (xForwardedFor != null) {
            context.put(RequestContext.X_FORWARDED_FOR, xForwardedFor);
        }
        
        // Store filename for use by archiver etc
        if (fileName != null) {
            fileName = stripPath(fileName);
        }
        context.put(RequestContext.FILENAME, fileName);
        context.put(RequestContext.RESPONSE_FILENAME, fileName);

        // PDF Password
        if (pdfPassword != null) {
            metadata.put(RequestContext.METADATA_PDFPASSWORD, pdfPassword);
        }
        
        final Properties mergedMetadata = mergeMetadataProperties();
       
        for (final Object key : mergedMetadata.keySet()) {
            final String propertyKey = (String) key;
            final String propertyValue = (String) mergedMetadata.get(key);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("Adding additional metadata: " + propertyKey + ": " + propertyValue);
            }
            
            metadata.put(propertyKey, propertyValue);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Received bytes of length: " + data.length);
        }

        final int requestId = random.nextInt();

        try {
            String responseText;
            
            switch (processType) {
            case signDocument:
                final GenericServletResponse servletResponse =
                    (GenericServletResponse) getWorkerSession().process(new AdminInfo("Client user", null, null), workerId,
                        new GenericServletRequest(requestId, data, req), context);
               
                if (servletResponse.getRequestID() != requestId) { // TODO: Is this possible to get at all?
                    LOG.error("Response ID " + servletResponse.getRequestID()
                            + " not matching request ID " + requestId);
                    res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                            "Request and response ID missmatch");
                    return;
                }
                
                byte[] processedBytes = (byte[]) servletResponse.getProcessedData();

                res.setContentType(servletResponse.getContentType());
                Object responseFileName = context.get(RequestContext.RESPONSE_FILENAME);
                if (responseFileName instanceof String) {
                    res.setHeader("Content-Disposition", "attachment; filename=\"" + responseFileName + "\"");
                }
                res.setContentLength(processedBytes.length);
                res.getOutputStream().write(processedBytes);
                break;
            case validateDocument:
                final GenericValidationResponse validationResponse =
                    (GenericValidationResponse) getWorkerSession().process(new AdminInfo("Client user", null, null), workerId, 
                            new GenericValidationRequest(requestId, data), context);
                    
                responseText = validationResponse.isValid() ? "VALID" : "INVALID";
                
                if (LOG.isDebugEnabled()) {
                    final Validation validation = validationResponse.getCertificateValidation();
                    
                    if (validation != null) {
                        LOG.debug("Cert validation status: " + validationResponse.getCertificateValidation().getStatusMessage());
                    }
                }
                
                res.setContentType("text/plain");
                res.setContentLength(responseText.getBytes().length);
                res.getOutputStream().write(responseText.getBytes());
                break;
            case validateCertificate:
                final Certificate cert;
                try {
                    cert = CertTools.getCertfromByteArray(data);
                
                    final String certPurposes = req.getParameter(CERT_PURPOSES_PROPERTY_NAME);
                    final ValidateResponse certValidationResponse =
                            (ValidateResponse) getWorkerSession().process(new AdminInfo("Client user", null, null), workerId,
                                    new ValidateRequest(cert, certPurposes), context);
                    final Validation validation = certValidationResponse.getValidation();
                    
                    final StringBuilder sb = new StringBuilder(validation.getStatus().name());
                    
                    sb.append(";");
                    
                    final String validPurposes = certValidationResponse.getValidCertificatePurposes();
                    
                    if (validPurposes != null) {
                        sb.append(certValidationResponse.getValidCertificatePurposes());
                    }
                    sb.append(";");
                    sb.append(certValidationResponse.getValidation().getStatusMessage());
                    sb.append(";");
                    sb.append(certValidationResponse.getValidation().getRevokationReason());
                    sb.append(";");
                    
                    final Date revocationDate = certValidationResponse.getValidation().getRevokedDate();
                    
                    if (revocationDate != null) {
                        sb.append(certValidationResponse.getValidation().getRevokedDate().getTime());
                    }

                    responseText = sb.toString();
                    
                    res.setContentType("text/plain");
                    res.setContentLength(responseText.getBytes().length);
                    res.getOutputStream().write(responseText.getBytes());
                } catch (CertificateException e) {
                    LOG.error("Invalid certificate: " + e.getMessage());
                    sendBadRequest(res, "Invalid certificate: " + e.getMessage());
                    return;
                }
                break;
            };
            
            res.getOutputStream().close();
            
        } catch (AuthorizationRequiredException e) {
            LOG.debug("Sending back HTTP 401: " + e.getLocalizedMessage());

            final String httpAuthBasicRealm = "SignServer Worker " + workerId;

            res.setHeader(HTTP_AUTH_BASIC_WWW_AUTHENTICATE,
                    "Basic realm=\"" + httpAuthBasicRealm + "\"");
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "Authorization Required");
        } catch (AccessDeniedException e) {
            LOG.debug("Sending back HTTP 403: " + e.getLocalizedMessage());
            res.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
        } catch (NoSuchWorkerException ex) {
            res.sendError(HttpServletResponse.SC_NOT_FOUND, "Worker Not Found");
        } catch (IllegalRequestException e) {
            res.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
        } catch (CryptoTokenOfflineException e) {
            res.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, e.getMessage());
        } catch (ServiceUnavailableException e) {
            res.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, e.getMessage());
        } catch (SignServerException e) {
            res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        }
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

    private static void sendBadRequest(HttpServletResponse res, String message)
            throws IOException {
        LOG.info("Bad request: " + message);
        res.sendError(HttpServletResponse.SC_BAD_REQUEST, message);
    }
}
