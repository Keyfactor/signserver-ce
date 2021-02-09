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
package org.signserver.protocol.ws.server;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebService;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.apache.commons.fileupload.FileUploadBase;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.log4j.Logger;
import org.signserver.common.CompileTimeSettings;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GenericValidationRequest;
import org.signserver.common.GenericValidationResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestAndResponseManager;
import org.signserver.common.RequestContext;
import org.signserver.common.SODSignRequest;
import org.signserver.common.SODSignResponse;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatus;
import org.signserver.common.data.CertificateValidationRequest;
import org.signserver.common.data.CertificateValidationResponse;
import org.signserver.common.data.DocumentValidationRequest;
import org.signserver.common.data.DocumentValidationResponse;
import org.signserver.common.data.LegacyRequest;
import org.signserver.common.data.LegacyResponse;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SODRequest;
import org.signserver.common.data.SODResponse;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.ejb.interfaces.ProcessSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.healthcheck.HealthCheckUtils;
import org.signserver.protocol.ws.Certificate;
import org.signserver.protocol.ws.ProcessRequestWS;
import org.signserver.protocol.ws.ProcessResponseWS;
import org.signserver.protocol.ws.WorkerStatusWS;
import org.signserver.server.CredentialUtils;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.data.impl.DataFactory;
import org.signserver.server.data.impl.DataUtils;
import org.signserver.server.data.impl.UploadConfig;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;
import org.signserver.server.nodb.FileBasedDatabaseManager;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;

/**
 * Legacy SignServerWS interface.
 *
 * @author Philip Vendil
 * @version $Id$
 */
@WebService(serviceName = "SignServerWSService", targetNamespace = "gen.ws.protocol.signserver.org")
public class SignServerWS {

    private static final Logger LOG = Logger.getLogger(SignServerWS.class);

    /**
     * Defines all workers.
     */
    public static final String ALL_WORKERS = "ALLWORKERS";

    @Resource
    private WebServiceContext wsContext;

    @EJB
    private GlobalConfigurationSessionLocal globalSession;

    @EJB
    private WorkerSessionLocal workerSession;

    @EJB
    private ProcessSessionLocal processSession;

    /** EntityManager is conditionally injected from web.xml. */
    private EntityManager em;

    private String checkDBString = "Select count(*) from signerconfigdata";

    private int minimumFreeMemory = 1;

    private DataFactory dataFactory;

    @PostConstruct
    protected void init() {
        dataFactory = DataUtils.createDataFactory();
    }

    /**
     * Method used to return the status of a worker at SignServer.
     *
     * @param workerIdOrName id or name of the worker that should report it's status or 0 for all workers.
     * @return returns the status of the given workerID or name, "ALLWORKERS" will return all workers.
     * available workers will report.
     * @throws InvalidWorkerIdException if the given worker id  doesn't exist.
     */
    @WebMethod(operationName="getStatus")
    public Collection<WorkerStatusWS> getStatus(
            @WebParam(name = "arg0") final String workerIdOrName
    ) throws InvalidWorkerIdException {
        LOG.debug("WS getStatus called");
        final ArrayList<WorkerStatusWS> returnValues = new ArrayList<>();
        final LinkedList<String> errors = new LinkedList<>();
        //
        if (FileBasedDatabaseManager.getInstance().isUsed()) {
            errors.addAll(FileBasedDatabaseManager.getInstance().getFatalErrors());
        } else {
            errors.addAll(HealthCheckUtils.checkDB(em, getCheckDBString()));
        }
        if (errors.isEmpty()) {
            errors.addAll(HealthCheckUtils.checkMemory(getMinimumFreeMemory()));
        }
        //
        if (!workerIdOrName.equalsIgnoreCase(ALL_WORKERS)) {
            // Specified WorkerId
            if (errors.isEmpty()) {
                errors.addAll(checkSigner(WorkerIdentifier.createFromIdOrName(workerIdOrName)));
            }
            WorkerStatusWS response = new WorkerStatusWS();
            response.setWorkerName(workerIdOrName);
            appendErrorsIfAny(errors, response);
            returnValues.add(response);
        } else {
            // All Workers
            List<Integer> signers = getWorkerSession().getAllWorkers();
            for (int next : signers) {
                if (errors.isEmpty()) {
                    errors.addAll(checkSigner(new WorkerIdentifier(next)));
                }
                WorkerStatusWS resp = new WorkerStatusWS();
                resp.setWorkerName("" + next);
                appendErrorsIfAny(errors, resp);
                returnValues.add(resp);
            }
        }
        return returnValues;
    }

    private List<String> checkSigner(WorkerIdentifier wi) throws InvalidWorkerIdException {
        final LinkedList<String> result = new LinkedList<>();
        final WorkerStatus status = getWorkerSession().getStatus(wi);
        for (String error : status.getFatalErrors()) {
            result.add("Worker " + status.getWorkerId() + ": " + error + "\n");
        }
        return result;
    }

    /**
     *
     * @param workerIdOrName id or name of the worker that should report it's status or 0 for all workers.
     * @param requests collection of sign requests to process
     * @return a collection of corresponding responses.
     * @throws InvalidWorkerIdException if the name of id couldn't be found.
     * @throws IllegalRequestException if the request isn't correct.
     * @throws CryptoTokenOfflineException if the signing token isn't online.
     * @throws SignServerException if some other error occurred server side during process.
     */
    @WebMethod(operationName="process")
    public Collection<ProcessResponseWS> process(
            @WebParam(name = "arg0") final String workerIdOrName,
            @WebParam(name = "arg1") final Collection<ProcessRequestWS> requests
    ) throws InvalidWorkerIdException, IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        LOG.debug("WS process called");
        final ArrayList<ProcessResponseWS> returnValues = new ArrayList<>();
        final HttpServletRequest servletRequest = getHttpServletRequest();
        final String requestIP = getRequestIP();
        final X509Certificate clientCertificate = getClientCertificate();
        final RequestContext requestContext = new RequestContext(clientCertificate, requestIP);
        // Add credentials to the context
        CredentialUtils.addToRequestContext(requestContext, servletRequest, clientCertificate);
        final LogMap logMap = LogMap.getInstance(requestContext);
        final String xForwardedFor = servletRequest.getHeader(RequestContext.X_FORWARDED_FOR);
        // Add HTTP specific log entries
        logMap.put(IWorkerLogger.LOG_REQUEST_FULLURL, new Loggable() {
            @Override
            public String toString() {
                return servletRequest.getRequestURL().append("?")
                        .append(servletRequest.getQueryString()).toString();
            }
        });
        //
        logMap.put(IWorkerLogger.LOG_REQUEST_LENGTH, new Loggable() {
            @Override
            public String toString() {
                return servletRequest.getHeader("Content-Length");
            }
        });
        //
        logMap.put(IWorkerLogger.LOG_XFORWARDEDFOR, new Loggable() {
            @Override
            public String toString() {
                return xForwardedFor;
            }
        });
        if (xForwardedFor != null) {
            requestContext.put(RequestContext.X_FORWARDED_FOR, xForwardedFor);
        }
        // Add and log the X-SignServer-Custom-1 header if available
        final String xCustom1 = servletRequest.getHeader(RequestContext.X_SIGNSERVER_CUSTOM_1);
        if (xCustom1 != null && !xCustom1.isEmpty()) {
            requestContext.put(RequestContext.X_SIGNSERVER_CUSTOM_1, xCustom1);
        }
        logMap.put(IWorkerLogger.LOG_XCUSTOM1, xCustom1);
        //
        final WorkerIdentifier wi = WorkerIdentifier.createFromIdOrName(workerIdOrName);
        final ArrayList<Certificate> signerCertificateChain = getSignerCertificateChain(wi);
        //
        for (ProcessRequestWS next : requests) {
            ProcessRequest req;
            try {
                req = RequestAndResponseManager.parseProcessRequest(next.getRequestData());
            } catch (IOException e1) {
                LOG.error("Error parsing process request", e1);
                throw new IllegalRequestException(e1.getMessage());
            }
            //
            Map<String, String> metadata = next.getRequestMetadata();
            if (metadata == null) {
                requestContext.remove(RequestContext.REQUEST_METADATA);
            } else {
                requestContext.put(RequestContext.REQUEST_METADATA, metadata);
                final String fileName = metadata.get(RequestContext.FILENAME);
                if (fileName != null) {
                    requestContext.put(RequestContext.FILENAME, fileName);
                    logMap.put(IWorkerLogger.LOG_FILENAME, new Loggable() {
                        @Override
                        public String toString() {
                            return fileName;
                        }
                    });
                }
            }
            if (wi.hasName()) {
                logMap.put(IWorkerLogger.LOG_WORKER_NAME, new Loggable() {
                    @Override
                    public String toString() {
                        return wi.getName();
                    }
                });
            }
            if (wi.hasId()) {
                logMap.put(IWorkerLogger.LOG_WORKER_ID, new Loggable() {
                    @Override
                    public String toString() {
                        return String.valueOf(wi.getId());
                    }
                });
            }
            // TODO: Duplicated in SignServerWS, AdminWS, ProcessSessionBean (remote)
            CloseableReadableData requestData = null;
            CloseableWritableData responseData = null;
            int requestID;
            try {
                final Request req2;
                // Use the new request types with large file support for
                // GenericSignRequest and GenericValidationRequest
                if (req instanceof GenericSignRequest) {
                    byte[] data = ((GenericSignRequest) req).getRequestData();
                    requestID = ((GenericSignRequest) req).getRequestID();
                    // Upload handling (Note: close in finally clause)
                    UploadConfig uploadConfig = UploadConfig.create(globalSession);
                    requestData = dataFactory.createReadableData(
                            data,
                            uploadConfig.getMaxUploadSize(),
                            uploadConfig.getRepository()
                    );
                    responseData = dataFactory.createWritableData(requestData, uploadConfig.getRepository());
                    req2 = new SignatureRequest(requestID, requestData, responseData);
                } else if (req instanceof GenericValidationRequest) {
                    byte[] data = ((GenericValidationRequest) req).getRequestData();
                    requestID = ((GenericValidationRequest) req).getRequestID();
                    // Upload handling (Note: close in finally clause)
                    UploadConfig uploadConfig = UploadConfig.create(globalSession);
                    requestData = dataFactory.createReadableData(
                            data,
                            uploadConfig.getMaxUploadSize(),
                            uploadConfig.getRepository()
                    );
                    req2 = new DocumentValidationRequest(requestID, requestData);
                } else if (req instanceof ValidateRequest) {
                    final ValidateRequest vr = (ValidateRequest) req;
                    // Upload handling
                    req2 = new CertificateValidationRequest(vr.getCertificate(), vr.getCertPurposesString());
                } else if (req instanceof SODSignRequest) {
                    SODSignRequest sodReq = (SODSignRequest) req;
                    req2 = new SODRequest(
                            sodReq.getRequestID(),
                            sodReq.getDataGroupHashes(),
                            sodReq.getLdsVersion(),
                            sodReq.getUnicodeVersion(),
                            responseData
                    );
                } else {
                    // Passthroughs for all legacy requests
                    req2 = new LegacyRequest(req);
                }

                final Response resp = getProcessSession().process(
                        new AdminInfo("Client user", null, null),
                        wi, req2, requestContext);
                final ProcessResponse processResponse;
                //
                if (resp instanceof SignatureResponse) {
                    SignatureResponse sigResp = (SignatureResponse) resp;
                    processResponse = new GenericSignResponse(
                            sigResp.getRequestID(),
                            responseData.toReadableData().getAsByteArray(),
                            sigResp.getSignerCertificate(),
                            sigResp.getArchiveId(),
                            sigResp.getArchivables()
                    );
                } else if (resp instanceof DocumentValidationResponse) {
                    DocumentValidationResponse docResp = (DocumentValidationResponse) resp;
                    processResponse = new GenericValidationResponse(
                            docResp.getRequestID(),
                            docResp.isValid(),
                            convert(docResp.getCertificateValidationResponse()),
                            requestData.getAsByteArray()
                    );
                } else if (resp instanceof CertificateValidationResponse) {
                    CertificateValidationResponse certResp = (CertificateValidationResponse) resp;
                    processResponse = new ValidateResponse(
                            certResp.getValidation(),
                            certResp.getValidCertificatePurposes()
                    );
                } else if (resp instanceof SODResponse) {
                    SODResponse sodResp = (SODResponse) resp;
                    processResponse = new SODSignResponse(
                            sodResp.getRequestID(),
                            responseData.toReadableData().getAsByteArray(),
                            sodResp.getSignerCertificate(),
                            sodResp.getArchiveId(),
                            sodResp.getArchivables()
                    );
                } else if (resp instanceof LegacyResponse) {
                    processResponse = ((LegacyResponse) resp).getLegacyResponse();
                } else {
                    throw new SignServerException("Unexpected response type: " + resp);
                }
                //
                ProcessResponseWS wsResponse = new ProcessResponseWS();
                if (processResponse instanceof GenericSignResponse) {
                    GenericSignResponse sigResp = (GenericSignResponse) processResponse;
                    wsResponse.setRequestID(sigResp.getRequestID());
                    try {
                        wsResponse.setWorkerCertificate(new Certificate(sigResp.getSignerCertificate()));
                        wsResponse.setWorkerCertificateChain(signerCertificateChain);
                    } catch (CertificateEncodingException e) {
                        LOG.error(e);
                    }
                }
                //
                try {
                    wsResponse.setResponseData(RequestAndResponseManager.serializeProcessResponse(processResponse));
                } catch (IOException e1) {
                    LOG.error("Error parsing process response", e1);
                    throw new SignServerException(e1.getMessage());
                }

                returnValues.add(wsResponse);
            } catch (FileUploadBase.SizeLimitExceededException ex) {
                LOG.error("Maximum content length exceeded: " + ex.getLocalizedMessage());
                throw new IllegalRequestException("Maximum content length exceeded");
            } catch (FileUploadException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Upload failed", ex);
                }
                throw new IllegalRequestException("Upload failed: " + ex.getLocalizedMessage());
            } catch (IOException ex) {
                throw new SignServerException("IO error", ex);
            } finally {
                if (requestData != null) {
                    try {
                        requestData.close();
                    } catch (IOException ex) {
                        LOG.error("Unable to remove temporary upload file: " + ex.getLocalizedMessage());
                    }
                }
                if (responseData != null) {
                    try {
                        responseData.close();
                    } catch (IOException ex) {
                        LOG.error("Unable to remove temporary response file: " + ex.getLocalizedMessage());
                    }
                }
            }
        }
        return returnValues;
    }

    private ArrayList<Certificate> getSignerCertificateChain(WorkerIdentifier wi) throws InvalidWorkerIdException {
        try {
            WorkerStatus ws = getWorkerSession().getStatus(wi);
            Collection<java.security.cert.Certificate> signerCertificateChain =
                    ws.getActiveSignerConfig().getSignerCertificateChain();

            if (signerCertificateChain != null) {
                final ArrayList<Certificate> returnValues = new ArrayList<>();
                for (java.security.cert.Certificate certificate : signerCertificateChain) {
                    returnValues.add(new Certificate(certificate));
                }
                return returnValues;
            }
        } catch (CertificateEncodingException e) {
            LOG.error(e);
        }
        return null;
    }

    private X509Certificate getClientCertificate() {
        final HttpServletRequest request = getHttpServletRequest();
        X509Certificate[] certificates =
                (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        if (certificates != null) {
            return certificates[0];
        }
        return null;
    }

    private String getRequestIP() {
        return getHttpServletRequest().getRemoteAddr();
    }

    private int getMinimumFreeMemory() {
        final String minMemory = getCompileTimeSetting(CompileTimeSettings.HEALTHECK_MINIMUMFREEMEMORY);
        if (minMemory != null) {
            try {
                minimumFreeMemory = Integer.parseInt(minMemory.trim());
            } catch (NumberFormatException e) {
                LOG.error("Error: SignServerWS badly configured, setting 'healthcheck.minimumfreememory' should only " +
                        "contain integers");
            }
        }
        return minimumFreeMemory;
    }

    private String getCheckDBString() {
        final String dbString = getCompileTimeSetting(CompileTimeSettings.HEALTHECK_CHECKDBSTRING);
        if (dbString != null) {
            checkDBString = dbString;
        }
        return checkDBString;
    }

    private WorkerSessionLocal getWorkerSession() {
        return workerSession;
    }

    private ProcessSessionLocal getProcessSession() {
        return processSession;
    }

    private ValidateResponse convert(CertificateValidationResponse from) {
        if (from != null) {
            return new ValidateResponse(from.getValidation(), from.getValidCertificatePurposes());
        }
        return null;
    }

    private HttpServletRequest getHttpServletRequest() {
        final MessageContext msgContext = wsContext.getMessageContext();
        return (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
    }

    private String getCompileTimeSetting(final String property) {
        return CompileTimeSettings.getInstance().getProperty(property);
    }

    private void appendErrorsIfAny(final LinkedList<String> errors, final WorkerStatusWS response) {
        if (errors.isEmpty()) {
            response.setOverallStatus(WorkerStatusWS.OVERALLSTATUS_ALLOK);
        } else {
            final StringBuilder buff = new StringBuilder();
            for (final String error : errors) {
                buff.append(error).append("\n");
            }
            response.setOverallStatus(WorkerStatusWS.OVERALLSTATUS_ERROR);
            response.setErrormessage(buff.toString());
        }
    }
}
