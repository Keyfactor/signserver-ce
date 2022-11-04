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

import org.signserver.web.common.ServletUtils;
import org.signserver.server.data.impl.BinaryFileUpload;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadBase;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;
import org.cesecore.util.CertTools;
import org.signserver.common.*;
import org.signserver.ejb.interfaces.ProcessSessionLocal;
import org.signserver.server.CredentialUtils;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.CertificateValidationRequest;
import org.signserver.common.data.CertificateValidationResponse;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.DocumentValidationRequest;
import org.signserver.common.data.DocumentValidationResponse;
import org.signserver.common.data.LegacyResponse;
import org.signserver.common.data.Response;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.data.impl.DataFactory;
import org.signserver.server.data.impl.DataUtils;
import org.signserver.server.data.impl.UploadConfig;
import org.signserver.server.log.Loggable;
import org.signserver.validationservice.common.Validation;
import javax.servlet.http.Cookie;
import org.signserver.common.RequestContext;
import static org.signserver.common.SignServerConstants.X_SIGNSERVER_ERROR_MESSAGE;


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
public class GenericProcessServlet extends AbstractProcessServlet {

    private static final Logger LOG = Logger.getLogger(GenericProcessServlet.class);

    private static final long serialVersionUID = 1L;
    private static final String FORM_URL_ENCODED = "application/x-www-form-urlencoded";
    private static final String METHOD_GET = "GET";
    private static final String WORKERID_PROPERTY_NAME = "workerId";
    private static final String WORKERNAME_PROPERTY_NAME = "workerName";
    private static final String DATA_PROPERTY_NAME = "data";
    private static final String ENCODING_PROPERTY_NAME = "encoding";
    private static final String ENCODING_BASE64 = "base64";
    private static final String PDFPASSWORD_PROPERTY_NAME = "pdfPassword";

    private static final String PROCESS_TYPE_PROPERTY_NAME = "processType";
    private static final String CERT_PURPOSES_PROPERTY_NAME = "certPurposes";
    private static final String HTTP_MAX_UPLOAD_SIZE = "HTTP_MAX_UPLOAD_SIZE";

    private enum ProcessType {
        signDocument,
        validateDocument,
        validateCertificate
    };

    @EJB
    private ProcessSessionLocal processSession;

    @EJB
    private GlobalConfigurationSessionLocal globalSession;

    private DataFactory dataFactory;

    // UploadConfig cache
    private static final long UPLOAD_CONFIG_CACHE_TIME = 2000;
    private final Object uploadConfigSync = new Object();
    private UploadConfig cachedUploadConfig;
    private long uploadConfigNextUpdate;

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

        WorkerIdentifier wi = null;
        CloseableReadableData data = null;
        String fileName = null;
        String pdfPassword = null;
        boolean workerRequest = false;

        if (LOG.isDebugEnabled()) {
            LOG.debug("Received a request with length: "
                    + req.getContentLength());
        }

        final String workerNameOverride =
                        (String) req.getAttribute(ServletUtils.WORKERNAME_PROPERTY_OVERRIDE);

        if (workerNameOverride != null) {
            wi = new WorkerIdentifier(workerNameOverride);
            workerRequest = true;
        }

        ProcessType processType = ProcessType.signDocument;
        final MetaDataHolder metadataHolder = new MetaDataHolder();

        final UploadConfig uploadConfig = getUploadConfig();
        final DiskFileItemFactory factory = new DiskFileItemFactory();
        factory.setSizeThreshold(uploadConfig.getSizeThreshold());
        factory.setRepository(uploadConfig.getRepository());

        List<FileItem> itemsToDelete = null;
        try {

            if (ServletFileUpload.isMultipartContent(req)) {
                final ServletFileUpload upload = new ServletFileUpload(factory);
                upload.setSizeMax(uploadConfig.getMaxUploadSize());

                try {
                    final List<FileItem> items = upload.parseRequest(req);
                    itemsToDelete = items;
                    final Iterator<FileItem> iter = items.iterator();
                    //FileItem fileItem = null;
                    String encoding = null;
                    while (iter.hasNext()) {
                        final FileItem item = iter.next();

                        if (item.isFormField()) {
                            if (!workerRequest) {
                                if (WORKERNAME_PROPERTY_NAME.equals(item.getFieldName())) {
                                    if (LOG.isDebugEnabled()) {
                                        LOG.debug("Found a signerName in the request: "
                                                + item.getString());
                                    }
                                    wi = new WorkerIdentifier(item.getString());
                                } else if (WORKERID_PROPERTY_NAME.equals(item.getFieldName())) {
                                    if (LOG.isDebugEnabled()) {
                                        LOG.debug("Found a signerId in the request: "
                                                + item.getString());
                                    }
                                    try {
                                        wi = new WorkerIdentifier(Integer.parseInt(item.getString()));
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
                                    } catch (IllegalArgumentException e) { // NOPMD
                                        sendBadRequest(res, "Illegal process type.");
                                        return;
                                    }
                                } else {
                                    processType = ProcessType.signDocument;
                                }
                            } else if (ENCODING_PROPERTY_NAME.equals(itemFieldName)) {
                                encoding = item.getString("ISO-8859-1");
                            } else if (isFieldMatchingMetaData(itemFieldName)) {
                                try {
                                    metadataHolder.handleMetaDataProperty(itemFieldName,
                                            item.getString("ISO-8859-1"));
                                } catch (IOException e) {
                                    sendBadRequest(res, "Malformed properties given using REQUEST_METADATA.");
                                    return;
                                }
                            }
                        } else {
                            // We only care for one upload at a time right now
                            if (data == null) {
                                data = dataFactory.createReadableData(item, uploadConfig.getRepository());
                                fileName = item.getName();
                            } else {
                                LOG.error("Only one upload at a time supported!");
                                // Make sure any temporary files are removed
                                try {
                                    item.delete();
                                } catch (Throwable ignored) {} // NOPMD
                            }
                        }
                    }

                    if (data == null) {
                        sendBadRequest(res, "Missing file content in upload");
                        return;
                    }

                    // Special handling of base64 encoded data. Note: no large file support for this
                    if (encoding != null && !encoding.isEmpty()) {
                        // Read in all data and base64 decode it
                        byte[] bytes = data.getAsByteArray();
                        if (bytes.length > 0) {
                            try {
                                bytes = Base64.decode(bytes);
                            } catch (DecoderException ex) {
                                sendBadRequest(res, "Incorrect base64 data");
                                return;
                            } finally {
                                data.close();
                            }
                        }

                        // Now put the decoded data
                        try {
                            data = dataFactory.createReadableData(bytes, uploadConfig.getMaxUploadSize(), uploadConfig.getRepository());
                        } catch (FileUploadBase.SizeLimitExceededException ex) {
                            LOG.error(HTTP_MAX_UPLOAD_SIZE + " exceeded: " + ex.getLocalizedMessage());
                            res.sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                                "Maximum content length is " + uploadConfig.getMaxUploadSize() + " bytes");
                            return;
                        } catch (FileUploadException ex) {
                            throw new ServletException("Upload failed", ex);
                        }
                    }
                } catch (FileUploadBase.SizeLimitExceededException ex) {
                    LOG.error(HTTP_MAX_UPLOAD_SIZE + " exceeded: " + ex.getLocalizedMessage(), ex);
                    res.sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                        "Maximum content length is " + uploadConfig.getMaxUploadSize() + " bytes");
                    return;
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
                        wi = new WorkerIdentifier(name);
                    }
                    String id = req.getParameter(WORKERID_PROPERTY_NAME);
                    if (id != null) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Found a signerId in the request: " + id);
                        }
                        wi = new WorkerIdentifier(Integer.parseInt(id));
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
                    } else if (isFieldMatchingMetaData(property)) {
                       try {
                           metadataHolder.handleMetaDataProperty(property,
                                   req.getParameter(property));
                       } catch (IOException e) {
                           sendBadRequest(res, "Malformed properties given using REQUEST_METADATA.");
                           return;
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
                    } catch (IllegalArgumentException e) { // NOPMD
                        sendBadRequest(res, "Illegal process type.");
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
                    byte[] bytes = req.getParameter(DATA_PROPERTY_NAME).getBytes(StandardCharsets.US_ASCII);

                    String encoding = req.getParameter(ENCODING_PROPERTY_NAME);
                    if (encoding != null && !encoding.isEmpty()) {
                        if (ENCODING_BASE64.equalsIgnoreCase(encoding)) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Decoding base64 data");
                            }
                            if (bytes.length > 0) {
                                try {
                                    bytes = Base64.decode(bytes);
                                } catch (DecoderException ex) {
                                    sendBadRequest(res, "Incorrect base64 data");
                                    return;
                                }
                            }
                        } else {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Unknown encoding: " + encoding);
                            }
                            sendBadRequest(res,
                                    "Unknown encoding for the 'data' field.");
                            return;
                        }
                    }

                    try {
                        data = dataFactory.createReadableData(bytes, uploadConfig.getMaxUploadSize(), uploadConfig.getRepository());
                    } catch (FileUploadBase.SizeLimitExceededException ex) {
                        LOG.error(HTTP_MAX_UPLOAD_SIZE + " exceeded: " + ex.getLocalizedMessage());
                        res.sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                            "Maximum content length is " + uploadConfig.getMaxUploadSize() + " bytes");
                        return;
                    } catch (FileUploadException ex) {
                        throw new ServletException("Upload failed", ex);
                    }
                } else {
                    // Pass-through the content to be handled by worker if
                    // unknown content-type
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Request Content-type: " + req.getContentType());
                    }

                    final BinaryFileUpload upload = new BinaryFileUpload(req.getInputStream(), req.getContentType(), factory);
                    upload.setSizeMax(uploadConfig.getMaxUploadSize());

                    try {
                        data = dataFactory.createReadableData(upload.parseTheRequest(), uploadConfig.getRepository());
                    } catch (FileUploadBase.SizeLimitExceededException ex) {
                        LOG.error(HTTP_MAX_UPLOAD_SIZE + " exceeded: " + ex.getLocalizedMessage());
                        res.sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                            "Maximum content length is " + uploadConfig.getMaxUploadSize() + " bytes");
                        return;
                    } catch (FileUploadException ex) {
                        throw new ServletException("Upload failed", ex);
                    }
                }
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Request of type: " + processType.name());
            }

            // Limit the maximum size of input
            if (data.getLength() > uploadConfig.getMaxUploadSize()) {
                LOG.error("Content length exceeds " + uploadConfig.getMaxUploadSize() + ", not processed: " + req.getContentLength());
                res.sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                        "Maximum content length is " + uploadConfig.getMaxUploadSize() + " bytes");
            } else {
                if (wi == null) {
                    res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing worker name or ID");
                } else {
                    processRequest(req, res, wi, data, uploadConfig, fileName, pdfPassword, processType,
                        metadataHolder);
                }
            }
        } finally {
            // Remove the temporary file (if any)
            if (data != null) {
                try {
                    data.close();
                } catch (IOException ex) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Unable to remove temporary upload file", ex);
                    }
                    LOG.error("Unable to remove temporary upload file: " + ex.getLocalizedMessage());
                }
            } else if (itemsToDelete != null) { // Clean up any files in case we failed before setting 'data'
                for (FileItem fileItem : itemsToDelete) {
                    try {
                        fileItem.delete();
                    } catch (Throwable e) {
                        // ignore it
                    }
                }
            }
        }

        LOG.debug("<doPost()");
    } //doPost

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


    @Override
    public void init() throws ServletException {
        dataFactory = DataUtils.createDataFactory();
    }

    private void processRequest(final HttpServletRequest req, final HttpServletResponse res, final WorkerIdentifier wi, final CloseableReadableData data, final UploadConfig uploadConfig,
            final String fileName, final String pdfPassword, final ProcessType processType,
            final MetaDataHolder metadataHolder) throws java.io.IOException, ServletException {
        final String remoteAddr = req.getRemoteAddr();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Received HTTP process request for worker " + wi + ", from IP " + remoteAddr);
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

        //extract ALL cookies from client request
        //so that other DSS components could work with them!
        Cookie[] cookies = req.getCookies();
        context.put(RequestContext.REQUEST_COOKIES, cookies);

        // Add credentials to the context
        CredentialUtils.addToRequestContext(context, req, clientCertificate);

        // Create log map
        LogMap logMap = LogMap.getInstance(context);

        final String xForwardedFor = req.getHeader(RequestContext.X_FORWARDED_FOR);

        // Add HTTP specific log entries
        logMap.put(IWorkerLogger.LOG_REQUEST_FULLURL, new Loggable() {
            @Override
            public String toString() {
                return req.getRequestURL().append("?").append(req.getQueryString()).toString();
            }
        });
        logMap.put(IWorkerLogger.LOG_REQUEST_LENGTH, String.valueOf(data.getLength()));
        logMap.put(IWorkerLogger.LOG_FILENAME, fileName);
        logMap.put(IWorkerLogger.LOG_XFORWARDEDFOR, xForwardedFor);

        if (xForwardedFor != null) {
            context.put(RequestContext.X_FORWARDED_FOR, xForwardedFor);
        }

        // Add and log the X-SignServer-Custom-1 header if available
        final String xCustom1 = req.getHeader(RequestContext.X_SIGNSERVER_CUSTOM_1);
        if (xCustom1 != null && !xCustom1.isEmpty()) {
            context.put(RequestContext.X_SIGNSERVER_CUSTOM_1, xCustom1);
        }
        logMap.put(IWorkerLogger.LOG_XCUSTOM1, xCustom1);

        // Store filename for use by archiver etc
        String strippedFileName = fileName;
        if (fileName != null) {
            strippedFileName = stripPath(fileName);
        }
        context.put(RequestContext.FILENAME, strippedFileName);
        context.put(RequestContext.RESPONSE_FILENAME, strippedFileName);

        // PDF Password
        if (pdfPassword != null) {
            metadata.put(RequestContext.METADATA_PDFPASSWORD, pdfPassword);
        }

        addRequestMetaData(metadataHolder, metadata);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Received bytes of length: " + data.getLength());
        }

        final Integer qosPriority = (Integer) req.getAttribute(RequestContext.QOS_PRIORITY);
        if (qosPriority != null) {
            context.put(RequestContext.QOS_PRIORITY, qosPriority);
        }

        final int requestId = ThreadLocalRandom.current().nextInt();

        try (CloseableWritableData responseData = dataFactory.createWritableData(data, uploadConfig.getRepository())) {
            String responseText;

            switch (processType) {
                case signDocument: {
                    final Response response = processSession.process(new AdminInfo("Client user", null, null), wi,
                            new SignatureRequest(requestId, data, responseData), context);


                    Object responseFileName = context.get(RequestContext.RESPONSE_FILENAME);
                    if (responseFileName instanceof String) {
                        res.setHeader("Content-Disposition", "attachment; filename=\"" + responseFileName + "\"");
                    }

                    if (response instanceof SignatureResponse) {
                        SignatureResponse sigResponse = (SignatureResponse) response;
                        ReadableData readable = sigResponse.getResponseData().toReadableData();

                        res.setContentType(sigResponse.getContentType());

                        //EE7:res.setContentLengthLong()
                        res.addHeader("Content-Length", String.valueOf(readable.getLength()));

                        IOUtils.copyLarge(readable.getAsInputStream(), res.getOutputStream());
                    } else if (response instanceof LegacyResponse) {
                        LegacyResponse legResponse = (LegacyResponse) response;
                        byte[] processedBytes = (byte[]) ((GenericSignResponse) legResponse.getLegacyResponse()).getProcessedData();
                        res.setContentLength(processedBytes.length);
                        res.getOutputStream().write(processedBytes);
                    } else {
                        throw new SignServerException("Unexpected response type: " + response);
                    }

                    break;
                }
                case validateDocument: {
                    final DocumentValidationResponse validationResponse = (DocumentValidationResponse) processSession.process(new AdminInfo("Client user", null, null), wi,
                                new DocumentValidationRequest(requestId, data), context);

                    responseText = validationResponse.isValid() ? "VALID" : "INVALID";

                    if (LOG.isDebugEnabled()) {
                        if (validationResponse.getCertificateValidationResponse() != null) {
                            final Validation validation = validationResponse.getCertificateValidationResponse().getValidation();
                            if (validation != null) {
                                LOG.debug("Cert validation status: " + validation.getStatusMessage());
                            }
                        }
                    }

                    res.setContentType("text/plain");
                    res.setContentLength(responseText.getBytes().length);
                    res.getOutputStream().write(responseText.getBytes());
                    break;
                }
                case validateCertificate: {
                    final Certificate cert;
                    try {
                        cert = CertTools.getCertfromByteArray(data.getAsByteArray());

                        final String certPurposes = req.getParameter(CERT_PURPOSES_PROPERTY_NAME);
                        final CertificateValidationResponse certValidationResponse = (CertificateValidationResponse) processSession.process(new AdminInfo("Client user", null, null), wi,
                                        new CertificateValidationRequest(cert, certPurposes), context);

                        final Validation validation = certValidationResponse.getValidation();

                        final StringBuilder sb = new StringBuilder(validation.getStatus().name());

                        sb.append(";");

                        final String validPurposes = certValidationResponse.getValidCertificatePurposesString();

                        if (validPurposes != null) {
                            sb.append(certValidationResponse.getValidCertificatePurposesString());
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
                }
            }

            res.getOutputStream().close();

        } catch (AuthorizationRequiredException e) {
            LOG.debug("Sending back HTTP 401: " + e.getLocalizedMessage());

            final String httpAuthBasicRealm = "SignServer Worker " + wi;

            res.setHeader(CredentialUtils.HTTP_AUTH_BASIC_WWW_AUTHENTICATE,
                    "Basic realm=\"" + httpAuthBasicRealm + "\"");
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "Authorization Required");
        } catch (AccessDeniedException e) {
            LOG.debug("Sending back HTTP 403: " + e.getLocalizedMessage());
            res.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
        } catch (NoSuchWorkerException ex) {
            res.sendError(HttpServletResponse.SC_NOT_FOUND, "Worker Not Found");
        } catch (IllegalRequestException e) {
            res.setHeader(X_SIGNSERVER_ERROR_MESSAGE, e.getMessage());
            res.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
        } catch (CryptoTokenOfflineException | ServiceUnavailableException e) {
            res.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, e.getMessage());
        } catch (NotGrantedException e) {
            res.sendError(HttpServletResponse.SC_FORBIDDEN, e.getMessage());
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

    /**
     * @return The cached UploadConfig or a new one if the cache expired
     */
    private UploadConfig getUploadConfig() {
        synchronized (uploadConfigSync) {
            final long now = System.currentTimeMillis();
            if (cachedUploadConfig == null || now > uploadConfigNextUpdate) {
                cachedUploadConfig = UploadConfig.create(globalSession);
                uploadConfigNextUpdate = now + UPLOAD_CONFIG_CACHE_TIME;
            }
            return cachedUploadConfig;
        }
    }
}
