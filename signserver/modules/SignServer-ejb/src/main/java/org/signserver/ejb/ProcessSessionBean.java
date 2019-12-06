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
package org.signserver.ejb;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.UUID;
import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.naming.NamingException;
import javax.persistence.EntityManager;
import org.apache.commons.fileupload.FileUploadBase;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.log4j.Logger;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericPropertiesRequest;
import org.signserver.common.GenericPropertiesResponse;
import org.signserver.common.GenericServletResponse;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericValidationRequest;
import org.signserver.common.GenericValidationResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.SODSignRequest;
import org.signserver.common.SODSignResponse;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.data.DocumentValidationRequest;
import org.signserver.common.data.CertificateValidationRequest;
import org.signserver.common.data.CertificateValidationResponse;
import org.signserver.common.data.DocumentValidationResponse;
import org.signserver.common.data.LegacyRequest;
import org.signserver.common.data.LegacyResponse;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SODRequest;
import org.signserver.common.data.SODResponse;
import org.signserver.ejb.interfaces.DispatcherProcessSessionLocal;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.ejb.worker.impl.WorkerManagerSingletonBean;
import org.signserver.server.entities.FileBasedKeyUsageCounterDataService;
import org.signserver.server.entities.IKeyUsageCounterDataService;
import org.signserver.server.entities.KeyUsageCounterDataService;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.nodb.FileBasedDatabaseManager;
import org.signserver.ejb.interfaces.ProcessSessionLocal;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.server.UsernamePasswordClientCredential;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.ejb.interfaces.ProcessTransactionSessionLocal;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.data.impl.DataFactory;
import org.signserver.server.data.impl.DataUtils;
import org.signserver.server.data.impl.TemporarlyWritableData;
import org.signserver.server.data.impl.UploadConfig;
import org.signserver.statusrepo.StatusRepositorySessionLocal;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;

/**
 * Session Bean handling the worker process requests.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ProcessSessionBean implements ProcessSessionRemote, ProcessSessionLocal {

    /** Log4j instance for this class. */
    private static final Logger LOG = Logger.getLogger(WorkerSessionBean.class);
    
    private IKeyUsageCounterDataService keyUsageCounterDataService;

    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    
    @EJB
    private WorkerManagerSingletonBean workerManagerSession;
    
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;
    
    @EJB
    ProcessTransactionSessionLocal processTransSession;
    
    @Resource
    private SessionContext ctx;
    
    EntityManager em;

    private WorkerProcessImpl processImpl;
    private final AllServicesImpl servicesImpl = new AllServicesImpl();
    private DataFactory dataFactory;
    private ProcessSessionLocal session;

    @PostConstruct
    public void create() {
        dataFactory = DataUtils.createDataFactory();

        if (em == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No EntityManager injected. Running without database.");
            }
            keyUsageCounterDataService = new FileBasedKeyUsageCounterDataService(FileBasedDatabaseManager.getInstance());
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("EntityManager injected. Running with database.");
            }
            keyUsageCounterDataService = new KeyUsageCounterDataService(em);
        }
        processImpl = new WorkerProcessImpl(em, keyUsageCounterDataService, workerManagerSession, logSession);

        session = ctx.getBusinessObject(ProcessSessionLocal.class);
        
        // XXX The lookups will fail on GlassFish V2
        // When we no longer support GFv2 we can refactor this code
        InternalProcessSessionLocal internalSession = null;
        DispatcherProcessSessionLocal dispatcherSession = null;
        StatusRepositorySessionLocal statusSession = null;
        try {
            internalSession = ServiceLocator.getInstance().lookupLocal(InternalProcessSessionLocal.class);
            dispatcherSession = ServiceLocator.getInstance().lookupLocal(DispatcherProcessSessionLocal.class);
            statusSession = ServiceLocator.getInstance().lookupLocal(StatusRepositorySessionLocal.class);
        } catch (NamingException ex) {
            LOG.error("Lookup services failed. This is expected on GlassFish V2: " + ex.getExplanation());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Lookup services failed", ex);
            }
        }
        try {
            // Add all services
            servicesImpl.putAll(em,
                    ServiceLocator.getInstance().lookupLocal(WorkerSessionLocal.class),
                    session,
                    globalConfigurationSession,
                    logSession,
                    internalSession, dispatcherSession, statusSession,
                    keyUsageCounterDataService);
        } catch (NamingException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Lookup services failed", ex);
            }
        }
    }
    
    // Note: This is the remote interface
    @Override
    public ProcessResponse process(final WorkerIdentifier wi,
            final ProcessRequest request, final RemoteRequestContext remoteContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {
        
        // XXX This is somewhat duplicated in SignSeverWS and other places
        CloseableReadableData requestData = null;
        CloseableWritableData responseData = null;
        try {
            final Request req2;
            
            // Use the new request types with large file support for
            // GenericSignRequest and GenericValidationRequest
            if (request instanceof GenericSignRequest) {
                byte[] data = ((GenericSignRequest) request).getRequestData();
                int requestID = ((GenericSignRequest) request).getRequestID();

                // Upload handling
                UploadConfig uploadConfig = UploadConfig.create(globalConfigurationSession);
                requestData = dataFactory.createReadableData(data, uploadConfig.getMaxUploadSize(), uploadConfig.getRepository());
                responseData = dataFactory.createWritableData(requestData, uploadConfig.getRepository());
                req2 = new SignatureRequest(requestID, requestData, responseData);
            } else if (request instanceof GenericValidationRequest) {
                byte[] data = ((GenericValidationRequest) request).getRequestData();
                int requestID = ((GenericValidationRequest) request).getRequestID();

                // Upload handling
                UploadConfig uploadConfig = UploadConfig.create(globalConfigurationSession);
                requestData = dataFactory.createReadableData(data, uploadConfig.getMaxUploadSize(), uploadConfig.getRepository());
                req2 = new DocumentValidationRequest(requestID, requestData);
            } else if (request instanceof ValidateRequest) {
                final ValidateRequest vr = (ValidateRequest) request;

                // Upload handling
                req2 = new CertificateValidationRequest(vr.getCertificate(), vr.getCertPurposesString());
            } else if (request instanceof SODSignRequest) {
                SODSignRequest sod = (SODSignRequest) request;
                responseData = new TemporarlyWritableData(false, new UploadConfig().getRepository());
                req2 = new SODRequest(sod.getRequestID(), sod.getDataGroupHashes(), sod.getLdsVersion(), sod.getUnicodeVersion(), responseData);
            } else if (request instanceof GenericPropertiesRequest) {
                GenericPropertiesRequest prop = (GenericPropertiesRequest) request;
                
                try (ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
                    prop.getProperties().store(bout, null);
                
                    // Upload handling
                    UploadConfig uploadConfig = UploadConfig.create(globalConfigurationSession);
                    requestData = dataFactory.createReadableData(bout.toByteArray(), uploadConfig.getMaxUploadSize(), uploadConfig.getRepository());
                    responseData = dataFactory.createWritableData(requestData, uploadConfig.getRepository());
                    req2 = new SignatureRequest(prop.hashCode(), requestData, responseData);

                } catch (IOException ex) {
                    throw new SignServerException("IO error", ex);
                }
            } else {
                // Passthrough for all legacy requests
                req2 = new LegacyRequest(request);
            }
            
            ProcessResponse result;
            Response response = process(wi, req2, remoteContext, servicesImpl);
            
            if (response instanceof SODResponse) {
                SODResponse sigResp = (SODResponse) response;
                result = new SODSignResponse(sigResp.getRequestID(), responseData.toReadableData().getAsByteArray(), sigResp.getSignerCertificate(), sigResp.getArchiveId(), sigResp.getArchivables());
            } else if (response instanceof SignatureResponse) {
                SignatureResponse sigResp = (SignatureResponse) response;
                if (request instanceof GenericPropertiesRequest) { // Still support old-style GenericPropertiesRequest/Response
                    Properties properties = new Properties();
                    try (InputStream in = responseData.toReadableData().getAsInputStream()) {
                        properties.load(in);
                    } catch (IOException ex) {
                        throw new SignServerException("IO error", ex);
                    }
                    result = new GenericPropertiesResponse(properties);
                } else {
                    result = new GenericServletResponse(sigResp.getRequestID(), responseData.toReadableData().getAsByteArray(), sigResp.getSignerCertificate(), sigResp.getArchiveId(), sigResp.getArchivables(), sigResp.getContentType());
                }
            } else if (response instanceof LegacyResponse) {
                // Passthrough for all other
                result = ((LegacyResponse) response).getLegacyResponse();
            } else if (response instanceof DocumentValidationResponse) {
                DocumentValidationResponse docResp = (DocumentValidationResponse) response;
                CertificateValidationResponse cvr = docResp.getCertificateValidationResponse();
                result = new GenericValidationResponse(docResp.getRequestID(), docResp.isValid(), cvr == null ? null : new ValidateResponse(cvr.getValidation(), cvr.getValidCertificatePurposes()));
            } else if (response instanceof CertificateValidationResponse) {
                CertificateValidationResponse certResp = (CertificateValidationResponse) response;
                
                result = new ValidateResponse(certResp.getValidation(), certResp.getValidCertificatePurposes());
            } else {
                throw new SignServerException("Unexpected response type: " + response);
            }
            
            return result;

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
    
    private Response process(WorkerIdentifier wi, Request request, RemoteRequestContext remoteContext, AllServicesImpl servicesImpl) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        // Create a new RequestContext at server-side
        final RequestContext requestContext = new RequestContext(true);

        if (remoteContext != null) {
            // Put metadata from the request
            RequestMetadata metadata = remoteContext.getMetadata();
            if (metadata != null) {
                RequestMetadata.getInstance(requestContext).putAll(remoteContext.getMetadata());
            }

            // Put username/password
            if (remoteContext.getUsername() != null) {
                UsernamePasswordClientCredential credential = new UsernamePasswordClientCredential(remoteContext.getUsername(), remoteContext.getPassword());
                requestContext.put(RequestContext.CLIENT_CREDENTIAL, credential);
                requestContext.put(RequestContext.CLIENT_CREDENTIAL_PASSWORD, credential);
            }
        }
        
        // Put transaction ID
        requestContext.put(RequestContext.TRANSACTION_ID, UUID.randomUUID().toString());

        // Put services
        requestContext.setServices(servicesImpl);
        return process(new AdminInfo("Client user", null, null), wi, request, requestContext);
    }
    
    
    
    
    @Override
    public Response process(final AdminInfo adminInfo, final WorkerIdentifier wi,
            final Request request, final RequestContext requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {
        requestContext.setServices(servicesImpl);
        if (LOG.isDebugEnabled()) {
            LOG.debug(">process: " + wi);
        }
        
        if (SessionUtils.needsTransaction(workerManagerSession, wi)) {
            // use separate transaction bean to avoid deadlock
            return processTransSession.processWithTransaction(adminInfo, wi, request, requestContext);
        } else {
            return processImpl.process(adminInfo, wi, request, requestContext);
        }
    }        
    
}
