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
import java.util.*;
import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.jws.WebService;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import org.apache.commons.fileupload.FileUploadBase;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.common.data.CertificateValidationRequest;
import org.signserver.common.data.CertificateValidationResponse;
import org.signserver.common.data.Request;
import org.signserver.common.data.SODRequest;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.ejb.interfaces.ProcessSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.healthcheck.HealthCheckUtils;
import org.signserver.protocol.ws.*;
import org.signserver.server.CredentialUtils;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.DocumentValidationRequest;
import org.signserver.common.data.DocumentValidationResponse;
import org.signserver.common.data.LegacyRequest;
import org.signserver.common.data.LegacyResponse;
import org.signserver.common.data.Response;
import org.signserver.common.data.SODResponse;
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
 * Implementor of the ISignServerWS interface.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
@Stateless
@WebService(wsdlLocation = "META-INF/wsdl/SignServerWSService.wsdl",
targetNamespace = "gen.ws.protocol.signserver.org")
public class SignServerWS implements ISignServerWS {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SignServerWS.class);
    
    @Resource
    private WebServiceContext wsContext;
    
    private static final String HTTP_AUTH_BASIC_AUTHORIZATION = "Authorization";
    
    @EJB
    private GlobalConfigurationSessionLocal globalSession;
    
    @EJB
    private WorkerSessionLocal workersession;
    
    @EJB
    private ProcessSessionLocal processSession;
    
    /** EntityManager is conditionally injected from ejb-jar.xml. */
    private EntityManager em;
    
    private String checkDBString = "Select count(*) from signerconfigdata";

    private int minimumFreeMemory = 1;
    
    private DataFactory dataFactory;
    
    @PostConstruct
    protected void init() {
        dataFactory = DataUtils.createDataFactory();
    }
    
    @Override
    public Collection<WorkerStatusWS> getStatus(String workerIdOrName)
            throws InvalidWorkerIdException {
        LOG.debug("WS getStatus called");
        ArrayList<WorkerStatusWS> retval = new ArrayList<>();

        final LinkedList<String> errors = new LinkedList<>();

        if (FileBasedDatabaseManager.getInstance().isUsed()) {
            errors.addAll(FileBasedDatabaseManager.getInstance().getFatalErrors());
        } else {
            errors.addAll(HealthCheckUtils.checkDB(em, getCheckDBString()));
        }
        if (errors.isEmpty()) {            
            errors.addAll(HealthCheckUtils.checkMemory(getMinimumFreeMemory()));
        }

        if (!workerIdOrName.equalsIgnoreCase(ISignServerWS.ALLWORKERS)) {
            // Specified WorkerId
            if (errors.isEmpty()) {
                errors.addAll(checkSigner(WorkerIdentifier.createFromIdOrName(workerIdOrName)));
            }
            WorkerStatusWS resp = new WorkerStatusWS();
            resp.setWorkerName(workerIdOrName);
            if (errors.isEmpty()) {
                resp.setOverallStatus(WorkerStatusWS.OVERALLSTATUS_ALLOK);
            } else {
                final StringBuilder buff = new StringBuilder();
                for (final String error : errors) {
                    buff.append(error).append("\n");
                }
                resp.setOverallStatus(WorkerStatusWS.OVERALLSTATUS_ERROR);
                resp.setErrormessage(buff.toString());
            }
            retval.add(resp);
        } else {
            // All Workers
            List<Integer> signers = getWorkerSession().getAllWorkers();
            for (int next : signers) {
                if (errors.isEmpty()) {
                    errors.addAll(checkSigner(new WorkerIdentifier(next)));
                }

                WorkerStatusWS resp = new WorkerStatusWS();
                resp.setWorkerName("" + next);
                if (errors.isEmpty()) {
                    resp.setOverallStatus(WorkerStatusWS.OVERALLSTATUS_ALLOK);
                } else {
                    final StringBuilder buff = new StringBuilder();
                    for (final String error : errors) {
                        buff.append(error).append("\n");
                    }
                    resp.setOverallStatus(WorkerStatusWS.OVERALLSTATUS_ERROR);
                    resp.setErrormessage(buff.toString());
                }
                retval.add(resp);
            }
        }
        return retval;
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
     * @see  org.signserver.protocol.ws.ISignServerWS#process(String, Collection)
     */
    @Override
    public Collection<ProcessResponseWS> process(String workerIdOrName,
            Collection<ProcessRequestWS> requests)
            throws InvalidWorkerIdException, IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        ArrayList<ProcessResponseWS> retval = new ArrayList<>();

        final HttpServletRequest servletRequest =
                (HttpServletRequest) wsContext.getMessageContext().get(MessageContext.SERVLET_REQUEST);
        String requestIP = getRequestIP();
        X509Certificate clientCertificate = getClientCertificate();
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
                
        logMap.put(IWorkerLogger.LOG_REQUEST_LENGTH, new Loggable() {
            @Override
            public String toString() {
                return servletRequest.getHeader("Content-Length");
            }
        });
                
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

        final WorkerIdentifier wi = WorkerIdentifier.createFromIdOrName(workerIdOrName);

        ArrayList<Certificate> signerCertificateChain = getSignerCertificateChain(wi);

        for (ProcessRequestWS next : requests) {
            ProcessRequest req;
            try {
                req = RequestAndResponseManager.parseProcessRequest(next.getRequestData());
            } catch (IOException e1) {
                LOG.error("Error parsing process request", e1);
                throw new IllegalRequestException(e1.getMessage());
            }
            
            Map<String, String> metadata = next.getRequestMetadata();
            if (metadata == null) {
                requestContext.remove(RequestContext.REQUEST_METADATA);
            } else {
                requestContext.put(RequestContext.REQUEST_METADATA, metadata);
            }
            
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
            Integer requestID = null;
            try {
                final Request req2;
                
                // Use the new request types with large file support for
                // GenericSignRequest and GenericValidationRequest
                if (req instanceof GenericSignRequest) {
                    byte[] data = ((GenericSignRequest) req).getRequestData();
                    requestID = ((GenericSignRequest) req).getRequestID();
                    
                    // Upload handling (Note: close in finally clause)
                    UploadConfig uploadConfig = UploadConfig.create(globalSession);
                    requestData = dataFactory.createReadableData(data, uploadConfig.getMaxUploadSize(), uploadConfig.getRepository());
                    responseData = dataFactory.createWritableData(requestData, uploadConfig.getRepository());
                    req2 = new SignatureRequest(requestID, requestData, responseData);
                } else if (req instanceof GenericValidationRequest) {
                    byte[] data = ((GenericValidationRequest) req).getRequestData();
                    requestID = ((GenericValidationRequest) req).getRequestID();
                    
                    // Upload handling (Note: close in finally clause)
                    UploadConfig uploadConfig = UploadConfig.create(globalSession);
                    requestData = dataFactory.createReadableData(data, uploadConfig.getMaxUploadSize(), uploadConfig.getRepository());
                    req2 = new DocumentValidationRequest(requestID, requestData);
                } else if (req instanceof ValidateRequest) {
                    final ValidateRequest vr = (ValidateRequest) req;

                    // Upload handling
                    req2 = new CertificateValidationRequest(vr.getCertificate(), vr.getCertPurposesString());
                } else if (req instanceof SODSignRequest) {
                    SODSignRequest sodReq = (SODSignRequest) req;
                    req2 = new SODRequest(sodReq.getRequestID(), sodReq.getDataGroupHashes(), sodReq.getLdsVersion(), sodReq.getUnicodeVersion(), responseData);
                } else {
                    // Passthrough for all legacy requests
                    req2 = new LegacyRequest(req);
                }

                final Response resp = getProcessSession().process(new AdminInfo("Client user", null, null),
                        wi, req2, requestContext);
                final ProcessResponse processResponse;
                
                if (resp instanceof SignatureResponse) {
                    SignatureResponse sigResp = (SignatureResponse) resp;
                    processResponse = new GenericSignResponse(sigResp.getRequestID(), responseData.toReadableData().getAsByteArray(), sigResp.getSignerCertificate(), sigResp.getArchiveId(), sigResp.getArchivables());
                } else if (resp instanceof DocumentValidationResponse) {
                    DocumentValidationResponse docResp = (DocumentValidationResponse) resp;
                    processResponse = new GenericValidationResponse(docResp.getRequestID(), docResp.isValid(), convert(docResp.getCertificateValidationResponse()), requestData.getAsByteArray());
                } else if (resp instanceof CertificateValidationResponse) {
                    CertificateValidationResponse certResp = (CertificateValidationResponse) resp;
                    processResponse = new ValidateResponse(certResp.getValidation(), certResp.getValidCertificatePurposes());
                } else if (resp instanceof SODResponse) {
                    SODResponse sodResp = (SODResponse) resp;
                    processResponse = new SODSignResponse(sodResp.getRequestID(), responseData.toReadableData().getAsByteArray(), sodResp.getSignerCertificate(), sodResp.getArchiveId(), sodResp.getArchivables());
                } else if (resp instanceof LegacyResponse) {
                    processResponse = ((LegacyResponse) resp).getLegacyResponse();
                } else {
                    throw new SignServerException("Unexpected response type: " + resp);
                }
                
                ProcessResponseWS wsresp = new ProcessResponseWS();
                
                if (processResponse instanceof GenericSignResponse) {
                    GenericSignResponse sigResp = (GenericSignResponse) processResponse;
                    wsresp.setRequestID(sigResp.getRequestID());
                    try {
                        wsresp.setWorkerCertificate(new Certificate(sigResp.getSignerCertificate()));
                        wsresp.setWorkerCertificateChain(signerCertificateChain);
                    } catch (CertificateEncodingException e) {
                        LOG.error(e);
                    }
                }
                
                try {
                    wsresp.setResponseData(RequestAndResponseManager.serializeProcessResponse(processResponse));
                } catch (IOException e1) {
                    LOG.error("Error parsing process response", e1);
                    throw new SignServerException(e1.getMessage());
                }

                retval.add(wsresp);
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
        return retval;
    }

    private ArrayList<Certificate> getSignerCertificateChain(WorkerIdentifier wi) throws InvalidWorkerIdException {
        ArrayList<Certificate> retval = null;
        try {
            WorkerStatus ws = getWorkerSession().getStatus(wi);
            Collection<java.security.cert.Certificate> signerCertificateChain =
                    ws.getActiveSignerConfig().getSignerCertificateChain();

            if (signerCertificateChain != null) {
                retval = new ArrayList<>();
                for (Iterator<java.security.cert.Certificate> iterator = signerCertificateChain.iterator(); iterator.hasNext();) {
                    retval.add(new Certificate(iterator.next()));
                }
            }
        } catch (CertificateEncodingException e) {
            LOG.error(e);
        }
        return null;
    }

    private X509Certificate getClientCertificate() {
        MessageContext msgContext = wsContext.getMessageContext();
        HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
        X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

        if (certificates != null) {
            return certificates[0];
        }
        return null;
    }

    private String getRequestIP() {
        MessageContext msgContext = wsContext.getMessageContext();
        HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);

        return request.getRemoteAddr();
    }

    private int getMinimumFreeMemory() {
        final String minMemory = CompileTimeSettings.getInstance().getProperty(
                CompileTimeSettings.HEALTHECK_MINIMUMFREEMEMORY);
        if (minMemory != null) {
            try {
                minimumFreeMemory = Integer.parseInt(minMemory.trim());
            } catch (NumberFormatException e) {
                LOG.error("Error: SignServerWS badly configured, setting healthcheck.minimumfreememory should only contain integers");
            }
        }
        return minimumFreeMemory;
    }

    private String getCheckDBString() {
        final String dbString = CompileTimeSettings.getInstance().getProperty(
                CompileTimeSettings.HEALTHECK_CHECKDBSTRING);
        if (dbString != null) {
            checkDBString = dbString;
        }
        return checkDBString;
    }

    private WorkerSessionLocal getWorkerSession() {
        return workersession;
    }
    
    private ProcessSessionLocal getProcessSession() {
        return processSession;
    }

    private ValidateResponse convert(CertificateValidationResponse from) {
        if (from == null) {
            return null;
        } else {
            return new ValidateResponse(from.getValidation(), from.getValidCertificatePurposes());
        }
    }

}
