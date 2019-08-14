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
package org.signserver.admin.web.ejb;

import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import org.apache.commons.fileupload.FileUploadBase;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionLocal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.Elem;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.clauses.Order;
import org.signserver.admin.common.auth.AdminAuthHelper;
import org.signserver.admin.common.query.QueryCondition;
import org.signserver.admin.common.query.QueryOrdering;
import org.signserver.admin.common.query.QueryUtil;
import org.signserver.common.AbstractCertReqData;
import org.signserver.common.ArchiveMetadata;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericPropertiesRequest;
import org.signserver.common.GenericPropertiesResponse;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GenericValidationRequest;
import org.signserver.common.GenericValidationResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ICertReqData;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.QueryException;
import org.signserver.common.RequestAndResponseManager;
import org.signserver.common.RequestContext;
import org.signserver.common.SODSignRequest;
import org.signserver.common.SODSignResponse;
import org.signserver.common.SignServerException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerConfig;
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
import org.signserver.server.CertificateClientCredential;
import org.signserver.server.IClientCredential;
import org.signserver.server.cryptotokens.TokenSearchResults;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.data.impl.DataFactory;
import org.signserver.server.data.impl.DataUtils;
import org.signserver.server.data.impl.UploadConfig;
import org.signserver.server.log.AdminInfo;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;

/**
 * Facade for EJB calls from the admin web.
 * 
 * @author Markus Kilås
 * @version $Id: AdminWebSessionBean.java 7596 2016-11-28 16:00:36Z netmackan $
 */
@Stateless
public class AdminWebSessionBean {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AdminWebSessionBean.class);
    
    @EJB
    private GlobalConfigurationSessionLocal global;
    
    @EJB
    private WorkerSessionLocal worker;
    
    @EJB
    private ProcessSessionLocal process;
    
    @EJB
    private SecurityEventsAuditorSessionLocal auditor;

    private DataFactory dataFactory;

    private AdminAuthHelper auth;

    @PostConstruct
    public void init() {
        dataFactory = DataUtils.createDataFactory();
        auth = new AdminAuthHelper(global);
    }

    public WorkerConfig getCurrentWorkerConfig(final X509Certificate adminCertificate, final int workerId) throws AdminNotAuthorizedException {
        auth.requireAdminAuthorization(adminCertificate, "getCurrentWorkerConfig",
                String.valueOf(workerId));
        return worker.getCurrentWorkerConfig(workerId);
    }

    public Properties getProperties(final X509Certificate adminCertificate,
                                     final int workerId)
            throws AdminNotAuthorizedException {
        auth.requireAdminAuthorization(adminCertificate, "exportWorkerConfig",
                String.valueOf(workerId));
        return worker.exportWorkerConfig(workerId);
    }
    
    public WorkerStatus getStatus(final X509Certificate adminCertificate, final WorkerIdentifier wi) throws AdminNotAuthorizedException, InvalidWorkerIdException {
        auth.requireAdminAuthorization(adminCertificate, "getStatus", wi.toString());
        return worker.getStatus(wi);
    }
    
    public boolean isTokenActive(final X509Certificate adminCertificate, final WorkerIdentifier wi) throws InvalidWorkerIdException, AuthorizationDeniedException, AdminNotAuthorizedException {
        auth.requireAdminAuthorization(adminCertificate, "isTokenActive", wi.toString());
        return worker.isTokenActive(wi);
    }

    public List<Integer> getAllWorkers(final X509Certificate adminCertificate) throws AdminNotAuthorizedException {
        auth.requireAdminAuthorization(adminCertificate, "getAllWorkers");
        return worker.getAllWorkers();
    }
    
    public List<String> getAllWorkerNames(final X509Certificate adminCertificate) throws AdminNotAuthorizedException {
        auth.requireAdminAuthorization(adminCertificate, "getAllWorkerNames");
        return worker.getAllWorkerNames();
    }
    
    public int getWorkerIdByName(final X509Certificate adminCertificate, String workerName) throws AdminNotAuthorizedException, InvalidWorkerIdException {
        auth.requireAdminAuthorization(adminCertificate, "getWorkerId", workerName);
        return worker.getWorkerId(workerName);
    }
    
    public void activateSigner(final X509Certificate adminCertificate, WorkerIdentifier signerId, String authenticationCode)
            throws AdminNotAuthorizedException, CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException, InvalidWorkerIdException {
        auth.requireAdminAuthorization(adminCertificate, "activateSigner", String.valueOf(signerId));
        
        worker.activateSigner(signerId, authenticationCode);
    }
    
    public boolean deactivateSigner(final X509Certificate adminCertificate, final WorkerIdentifier signerId) throws AdminNotAuthorizedException, CryptoTokenOfflineException,
            InvalidWorkerIdException, AdminNotAuthorizedException {
        auth.requireAdminAuthorization(adminCertificate, "deactivateSigner", String.valueOf(signerId));
        
        return worker.deactivateSigner(signerId);
    }
    
    public String generateSignerKey(
            final X509Certificate adminCertificate, 
            final WorkerIdentifier signerId,
            final String keyAlgorithm,
            final String keySpec,
            final String alias,
            final String authCode)
            throws AdminNotAuthorizedException, CryptoTokenOfflineException, InvalidWorkerIdException,
            AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(adminCertificate, "generateSignerKey", String.valueOf(signerId),
                keyAlgorithm, keySpec, alias);
        
        return worker.generateSignerKey(adminInfo, signerId, keyAlgorithm, keySpec, alias,
                authCode == null ? null : authCode.toCharArray());
    }
    
    public Collection<KeyTestResult> testKey(
            final X509Certificate adminCertificate,
            final int signerId,
            final String alias,
            final String authCode)
            throws AdminNotAuthorizedException, CryptoTokenOfflineException,
            InvalidWorkerIdException, KeyStoreException,
            AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(adminCertificate, "testKey", String.valueOf(signerId), alias);

        // Workaround for KeyTestResult first placed in wrong package
        final Collection<KeyTestResult> results;
        Collection<?> res = worker.testKey(adminInfo, new WorkerIdentifier(signerId), alias, authCode == null ? null : authCode.toCharArray());
        if (res.size() < 1) {
            results = new LinkedList<>();
        } else {
            results = new LinkedList<>();
            for (Object o : res) {
                if (o instanceof KeyTestResult) {
                    results.add((KeyTestResult) o);
                }
            }
        }

        return results;
    }
    
    public AbstractCertReqData getPKCS10CertificateRequestForAlias(
            final X509Certificate adminCertificate,
            final int signerId,
            final PKCS10CertReqInfo certReqInfo,
            final boolean explicitEccParameters,
            final String keyAlias)
                throws CryptoTokenOfflineException, InvalidWorkerIdException,
                    AdminNotAuthorizedException {
        
        final AdminInfo adminInfo = auth.requireAdminAuthorization(adminCertificate, "getPKCS10CertificateRequestForKey",
                String.valueOf(signerId));
        
        final ICertReqData data = worker.getCertificateRequest(adminInfo, new WorkerIdentifier(signerId),
                certReqInfo, explicitEccParameters, keyAlias);
        if (!(data instanceof AbstractCertReqData)) {
            throw new RuntimeException("Unsupported cert req data");
        }
        return (AbstractCertReqData) data;
    }

    public void uploadSignerCertificate(final X509Certificate adminCertificate,
            final int signerId,
            final byte[] signerCert,
            final String scope)
            throws IllegalRequestException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(adminCertificate, "uploadSignerCertificate", String.valueOf(signerId));
        
        try {
            worker.uploadSignerCertificate(adminInfo, signerId, signerCert, scope);
        } catch (CertificateException ex) {
            // Log stacktrace and only pass on description to client
            LOG.error("Unable to parse certificate", ex);
            throw new IllegalRequestException("Unable to parse certificate");
        }
    }

    public void uploadSignerCertificateChain(final X509Certificate adminCertificate,
            final int signerId,
            final List<byte[]> signerCerts,
            final String scope)
                throws IllegalRequestException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(adminCertificate, "uploadSignerCertificateChain", String.valueOf(signerId));
        
        try {
            worker.uploadSignerCertificateChain(adminInfo, signerId, signerCerts, scope);
        } catch (CertificateException ex) {
            // Log stacktrace and only pass on description to client
            LOG.error("Unable to parse certificate", ex);
            throw new IllegalRequestException("Unable to parse certificate");
        }
    }

    public void importCertificateChain(
            final X509Certificate adminCertificate,
            final int workerId,
            final List<byte[]> certChain,
            final String alias,
            final String authCode)
            throws CryptoTokenOfflineException, CertificateException,
                   OperationUnsupportedException, AdminNotAuthorizedException {
        final AdminInfo adminInfo =
                auth.requireAdminAuthorization(adminCertificate, "importCertificateChain",
                                          String.valueOf(workerId), String.valueOf(alias));
        worker.importCertificateChain(adminInfo, new WorkerIdentifier(workerId), certChain, alias,
                                      authCode == null ? null : authCode.toCharArray());
    }

    public Date getSigningValidityNotBefore(
            final X509Certificate adminCertificate,
            final int workerId)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        auth.requireAdminAuthorization(adminCertificate, "getSigningValidityNotBefore", 
                String.valueOf(workerId));
        
        return worker.getSigningValidityNotBefore(new WorkerIdentifier(workerId));
    }
    
    public Date getSigningValidityNotAfter(
            final X509Certificate adminCertificate,
            final int workerId)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        auth.requireAdminAuthorization(adminCertificate, "getSigningValidityNotAfter",
                String.valueOf(workerId));
        
        return worker.getSigningValidityNotAfter(new WorkerIdentifier(workerId));
    }
    
    public long getKeyUsageCounterValue(
            final X509Certificate adminCertificate,
            final int workerId)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        auth.requireAdminAuthorization(adminCertificate, "getKeyUsageCounterValue",
                String.valueOf(workerId));

        return worker.getKeyUsageCounterValue(new WorkerIdentifier(workerId));
    }
    
    public Collection<byte[]> process(
            final X509Certificate adminCertificate,
            final String workerIdOrName,
            Collection<byte[]> requests)
            throws InvalidWorkerIdException, IllegalRequestException,
            CryptoTokenOfflineException, SignServerException,
            AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(adminCertificate, "process", workerIdOrName);

        final Collection<byte[]> result = new LinkedList<>();

        final X509Certificate clientCertificate = adminCertificate;
        
        // Requests from authenticated administrators are considered to come 
        // from the local host and is set to null. This is also the same as 
        // when requests are over EJB calls.
        final String ipAddress = null;

        final RequestContext requestContext = new RequestContext(
                clientCertificate, ipAddress);

        IClientCredential credential;
        final X509Certificate cert = (X509Certificate) clientCertificate;
        LOG.debug("Authentication: certificate");
        credential = new CertificateClientCredential(
                cert.getSerialNumber().toString(16),
                cert.getIssuerDN().getName());
        requestContext.put(RequestContext.CLIENT_CREDENTIAL, credential);

        for (byte[] requestBytes : requests) {
            final ProcessRequest req;
            try {
                req = RequestAndResponseManager.parseProcessRequest(
                        requestBytes);
            } catch (IOException ex) {
                LOG.error("Error parsing process request", ex);
                throw new IllegalRequestException(
                        "Error parsing process request", ex);
            }
            
            // TODO: Duplicated in SignServerWS, AdminWS, ProcessSessionBean (remote)
            CloseableReadableData requestData = null;
            CloseableWritableData responseData = null;
            try {
                final Request req2;
                boolean propertiesRequest = false;
                
                // Use the new request types with large file support for
                // GenericSignRequest and GenericValidationRequest
                if (req instanceof GenericSignRequest) {
                    byte[] data = ((GenericSignRequest) req).getRequestData();
                    int requestID = ((GenericSignRequest) req).getRequestID();
                    
                    // Upload handling (Note: close in finally clause)
                    UploadConfig uploadConfig = UploadConfig.create(global);
                    requestData = dataFactory.createReadableData(data, uploadConfig.getMaxUploadSize(), uploadConfig.getRepository());
                    responseData = dataFactory.createWritableData(requestData, uploadConfig.getRepository());
                    req2 = new SignatureRequest(requestID, requestData, responseData);
                } else if (req instanceof GenericValidationRequest) {
                    byte[] data = ((GenericValidationRequest) req).getRequestData();
                    int requestID = ((GenericValidationRequest) req).getRequestID();
                    
                    // Upload handling (Note: close in finally clause)
                    UploadConfig uploadConfig = UploadConfig.create(global);
                    requestData = dataFactory.createReadableData(data, uploadConfig.getMaxUploadSize(), uploadConfig.getRepository());
                    req2 = new DocumentValidationRequest(requestID, requestData);
                } else if (req instanceof ValidateRequest) {
                    ValidateRequest vr = (ValidateRequest) req;
                    req2 = new CertificateValidationRequest(vr.getCertificate(), vr.getCertPurposesString());
                } else if (req instanceof SODSignRequest) {
                    SODSignRequest sodReq = (SODSignRequest) req;
                    req2 = new SODRequest(sodReq.getRequestID(), sodReq.getDataGroupHashes(), sodReq.getLdsVersion(), sodReq.getUnicodeVersion(), responseData);
                } else if (req instanceof GenericPropertiesRequest) {
                    GenericPropertiesRequest propReq = (GenericPropertiesRequest) req;
                    propertiesRequest = true;
                    
                    // Upload handling (Note: close in finally clause)
                    UploadConfig uploadConfig = UploadConfig.create(global);
                    ByteArrayOutputStream bout = new ByteArrayOutputStream();
                    propReq.getProperties().store(bout, null);
                    requestData = dataFactory.createReadableData(bout.toByteArray(), uploadConfig.getMaxUploadSize(), uploadConfig.getRepository());
                    responseData = dataFactory.createWritableData(requestData, uploadConfig.getRepository());
                    req2 = new SignatureRequest(propReq.hashCode(), requestData, responseData);
                } else {
                    // Passthrough for all legacy requests
                    req2 = new LegacyRequest(req);
                }

                Response resp = process.process(adminInfo, WorkerIdentifier.createFromIdOrName(workerIdOrName), req2, requestContext);
    
                ProcessResponse processResponse;
                if (resp instanceof SignatureResponse && responseData != null) {
                    SignatureResponse sigResp = (SignatureResponse) resp;
                    if (propertiesRequest) {
                        Properties properties = new Properties();
                        properties.load(responseData.toReadableData().getAsInputStream());
                        processResponse = new GenericPropertiesResponse(properties);
                    } else {
                        processResponse = new GenericSignResponse(sigResp.getRequestID(), responseData.toReadableData().getAsByteArray(), sigResp.getSignerCertificate(), sigResp.getArchiveId(), sigResp.getArchivables());
                    }
                } else if (resp instanceof DocumentValidationResponse && responseData != null) {
                    DocumentValidationResponse docResp = (DocumentValidationResponse) resp;
                    processResponse = new GenericValidationResponse(docResp.getRequestID(), docResp.isValid(), convert(docResp.getCertificateValidationResponse()), responseData.toReadableData().getAsByteArray());
                } else if (resp instanceof CertificateValidationResponse) {
                    CertificateValidationResponse certResp = (CertificateValidationResponse) resp;
                    processResponse = new ValidateResponse(certResp.getValidation(), certResp.getValidCertificatePurposes());
                } else if (resp instanceof SODResponse && responseData != null) {
                    SODResponse sodResp = (SODResponse) resp;
                    processResponse = new SODSignResponse(sodResp.getRequestID(), responseData.toReadableData().getAsByteArray(), sodResp.getSignerCertificate(), sodResp.getArchiveId(), sodResp.getArchivables());
                } else if (resp instanceof LegacyResponse) {
                    processResponse = ((LegacyResponse) resp).getLegacyResponse();
                } else {
                    throw new SignServerException("Unexpected response type: " + resp);
                }
                
                try {
                    result.add(RequestAndResponseManager.serializeProcessResponse(processResponse));
                } catch (IOException ex) {
                    LOG.error("Error serializing process response", ex);
                    throw new IllegalRequestException(
                            "Error serializing process response", ex);
                }                
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
        return result;
    }

    public boolean removeKey(
            final X509Certificate adminCertificate,
            final int signerId,
            final String alias)
            throws CryptoTokenOfflineException,
            InvalidWorkerIdException, KeyStoreException,
            SignServerException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(adminCertificate, "removeKey", String.valueOf(signerId), alias);

        return worker.removeKey(adminInfo, new WorkerIdentifier(signerId), alias);
    }

    public boolean removeGlobalProperty(
            final X509Certificate adminCertificate,
            final String scope,
            final String key)
            throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(adminCertificate, "removeGlobalProperty", key);

        return global.removeProperty(adminInfo, scope, key);
    }
    
    public GlobalConfiguration getGlobalConfiguration(final X509Certificate adminCertificate)
            throws AdminNotAuthorizedException {
        auth.requireAdminAuthorization(adminCertificate, "getGlobalConfiguration");

        return global.getGlobalConfiguration();
    }

    public Collection<AuthorizedClient> getAuthorizedClients(
            final X509Certificate adminCertificate,
            final int workerId)
            throws AdminNotAuthorizedException {
        auth.requireAdminAuthorization(adminCertificate, "getAuthorizedClients",
                String.valueOf(workerId));
        
        return worker.getAuthorizedClients(workerId);
    }
    
    public Collection<CertificateMatchingRule> getAuthorizedClientsGen2(
            final X509Certificate adminCertificate,
            final int workerId)
            throws AdminNotAuthorizedException {
        auth.requireAdminAuthorization(adminCertificate, "getAuthorizedClientsGen2",
                String.valueOf(workerId));
        
        return worker.getAuthorizedClientsGen2(workerId);
    }
    
    
    public void addAuthorizedClient(
            final X509Certificate adminCertificate,
            final int workerId,
            final AuthorizedClient authClient)
            throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(adminCertificate, "addAuthorizedClient", 
                String.valueOf(workerId), authClient.getCertSN(),
                authClient.getIssuerDN());
        
        worker.addAuthorizedClient(adminInfo, workerId, authClient);
    }
    
    public void addAuthorizedClientGen2(
            final X509Certificate adminCertificate,
            final int workerId,
            final CertificateMatchingRule authClient)
            throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(adminCertificate, "addAuthorizedClientGen2", authClient.toString());
        
        worker.addAuthorizedClientGen2(adminInfo, workerId, authClient);
    }

    public boolean removeAuthorizedClient(
            final X509Certificate adminCertificate,
            final int workerId,
            final AuthorizedClient authClient) 
            throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(adminCertificate, "removeAuthorizedClient",
                String.valueOf(workerId), authClient.getCertSN(),
                authClient.getIssuerDN());
        
        return worker.removeAuthorizedClient(adminInfo, workerId, authClient);
    }
    
    public boolean removeAuthorizedClientGen2(
            final X509Certificate adminCertificate,
            final int workerId,
            final CertificateMatchingRule authClient) 
            throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(adminCertificate, "removeAuthorizedClientGen2",authClient.toString());
        
        return worker.removeAuthorizedClientGen2(adminInfo, workerId, authClient);
    }
    
    public void setGlobalProperty(
            final X509Certificate adminCertificate,
            final String scope,
            final String key,
            final String value)
            throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(adminCertificate, "setGlobalProperty", key);
        
        global.setProperty(adminInfo, scope, key, value);
    }
    
    public int getWorkerId(
            final X509Certificate adminCertificate,
            final String workerName)
            throws AdminNotAuthorizedException {
        auth.requireAdminAuthorization(adminCertificate, "getWorkerId", workerName);

        try {
            return worker.getWorkerId(workerName);
        } catch (InvalidWorkerIdException ex) {
            return 0;
        }
    }
    
    public Certificate getSignerCertificate(
            final X509Certificate adminCertificate,
            final int signerId)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        auth.requireAdminAuthorization(adminCertificate, "getSignerCertificate",
                String.valueOf(signerId));
        
        return worker.getSignerCertificate(new WorkerIdentifier(signerId));
    }
    
    public List<Certificate> getSignerCertificateChain(
            final X509Certificate adminCertificate,
            final int signerId)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        auth.requireAdminAuthorization(adminCertificate, "getSignerCertificateChain",
                String.valueOf(signerId));
        
        return worker.getSignerCertificateChain(new WorkerIdentifier(signerId));
    }

    public TokenSearchResults queryTokenEntries(
            final X509Certificate adminCertificate,
            int workerId, int startIndex, int max, final List<QueryCondition> conditions, final List<QueryOrdering> orderings, boolean includeData) throws OperationUnsupportedException, CryptoTokenOfflineException, QueryException, InvalidWorkerIdException, AuthorizationDeniedException, SignServerException, AdminNotAuthorizedException {
        try {
            final AdminInfo adminInfo = auth.requireAdminAuthorization(adminCertificate, "queryTokenEntries", String.valueOf(workerId), String.valueOf(startIndex), String.valueOf(max));
            final List<Elem> elements = QueryUtil.toElements(conditions);
            final QueryCriteria qc = QueryCriteria.create();
            
            for (QueryOrdering order : orderings) {
                qc.add(new Order(order.getColumn(), Order.Value.valueOf(order.getOrder().name())));
            }
            
            if (!elements.isEmpty()) {
                qc.add(QueryUtil.andAll(elements, 0));
            }
            
            return worker.searchTokenEntries(adminInfo, new WorkerIdentifier(workerId), startIndex, max, qc, includeData, Collections.<String, Object>emptyMap());
        } catch (InvalidAlgorithmParameterException ex) {
            throw new SignServerException("Crypto token expects supported parameters", ex);
        } catch (UnsupportedCryptoTokenParameter ex) {
            throw new SignServerException("Crypto token expects parameters", ex);
        }
    }
    
    public List<? extends AuditLogEntry> queryAuditLog(
            final X509Certificate adminCertificate,
            int startIndex, int max, final List<QueryCondition> conditions, final List<QueryOrdering> orderings) throws SignServerException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAuditorAuthorization(adminCertificate, "queryAuditLog", String.valueOf(startIndex), String.valueOf(max));
        
        // For now we only query one of the available audit devices
        Set<String> devices = auditor.getQuerySupportingLogDevices();
        if (devices.isEmpty()) {
            throw new SignServerException("No log devices available for querying");
        }
        final String device = devices.iterator().next();

        final List<Elem> elements = QueryUtil.toElements(conditions);
        final QueryCriteria qc = QueryCriteria.create();
        
        for (QueryOrdering order : orderings) {
            qc.add(new Order(order.getColumn(), Order.Value.valueOf(order.getOrder().name())));
        }
        
        if (!elements.isEmpty()) {
            qc.add(QueryUtil.andAll(elements, 0));
        }
        
        try {
            return worker.selectAuditLogs(adminInfo, startIndex, max, qc, device);
        } catch (AuthorizationDeniedException ex) {
            throw new AdminNotAuthorizedException(ex.getMessage());
        }
    }

    public List<ArchiveMetadata> queryArchive(
            final X509Certificate adminCertificate,
            int startIndex,
            int max,
            final List<QueryCondition> conditions,
            final List<QueryOrdering> orderings,
            final boolean includeData)
                    throws SignServerException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireArchiveAuditorAuthorization(adminCertificate, "queryArchive", String.valueOf(startIndex), String.valueOf(max));

        final List<Elem> elements = QueryUtil.toElements(conditions);
        final QueryCriteria qc = QueryCriteria.create();

        for (QueryOrdering order : orderings) {
            qc.add(new Order(order.getColumn(), Order.Value.valueOf(order.getOrder().name())));
        }

        if (!elements.isEmpty()) {
            qc.add(QueryUtil.andAll(elements, 0));
        }

        try {
            return worker.searchArchive(adminInfo, startIndex,
                    max, qc, includeData);
        } catch (AuthorizationDeniedException ex) {
            throw new AdminNotAuthorizedException(ex.getMessage());
        }
    }

    public List<ArchiveMetadata> queryArchiveWithIds(
            final X509Certificate adminCertificate,
            List<String> uniqueIds,
            boolean includeData)
            throws SignServerException, AdminNotAuthorizedException {
        final AdminInfo adminInfo =
                auth.requireArchiveAuditorAuthorization(adminCertificate, "queryArchiveWithIds");

        try {
            return worker.searchArchiveWithIds(adminInfo, uniqueIds, includeData);
        } catch (AuthorizationDeniedException ex) {
            throw new AdminNotAuthorizedException(ex.getMessage());
        }
    }

    // Add all method calls needed from WorkerSessionLocal here and
    // make sure to call auth.requireAdminAuthorization() first (see AdminWS)
    // ...

    private ValidateResponse convert(CertificateValidationResponse from) {
        return new ValidateResponse(from.getValidation(), from.getValidCertificatePurposes());
    }

    public void setWorkerProperty(X509Certificate adminCertificate, Integer workerId, String key, String value) throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(adminCertificate, "setWorkerProperty",
                String.valueOf(workerId), key);

        worker.setWorkerProperty(adminInfo, workerId, key, value);
    }
    
    public boolean removeWorkerProperty(X509Certificate adminCertificate,
            final int workerId,
            final String key)
            throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(adminCertificate, "removeWorkerProperty",
                String.valueOf(workerId), key);
        
        return worker.removeWorkerProperty(adminInfo, workerId, key);
    }

    public void reloadConfiguration(X509Certificate adminCertificate, Integer workerId) throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(adminCertificate, "reloadConfiguration",
                String.valueOf(workerId));

        worker.reloadConfiguration(adminInfo, workerId);
    }
    
    public List<String> getCertificateIssues(X509Certificate adminCertificate, int workerId, List<Certificate> certificateChain) throws InvalidWorkerIdException, AdminNotAuthorizedException {
        auth.requireAdminAuthorization(adminCertificate, "getCertificateIssues",
                String.valueOf(workerId));
        return worker.getCertificateIssues(workerId, certificateChain);
    }

    /**
     * Checks if key generation is disabled in the deployment configuration.
     * @return true if key generation has been disabled globally.
     */
    public boolean isKeyGenerationDisabled() {
        return worker.isKeyGenerationDisabled();
    }

}
