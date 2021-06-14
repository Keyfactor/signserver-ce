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
package org.signserver.test.utils.mock;

import java.math.BigInteger;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.ArchiveMetadata;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.QueryException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerType;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.server.IProcessable;
import org.signserver.server.SignServerContext;
import org.signserver.server.cryptotokens.TokenSearchResults;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.log.LogMap;

/**
 * Mocked WorkerSession.
 *
 * @author Markus Kilås
 * $version $Id$
 */
public class WorkerSessionMock implements WorkerSessionLocal,
        WorkerSessionRemote, InternalProcessSessionLocal/*, ProcessSessionRemote*/ {

    private static final Logger LOG = Logger.getLogger(WorkerSessionMock.class);

    private final HashMap<Integer, Worker> workers = new HashMap<>();

    private RequestContext lastRequestContext;

    @Override
    public String generateSignerKey(AdminInfo adminInfo, WorkerIdentifier signerId,
            String keyAlgorithm, String keySpec, String alias, char[] authCode)
                    throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Collection<KeyTestResult> testKey(AdminInfo adminInfo, WorkerIdentifier signerId,
            String alias, char[] authCode) throws CryptoTokenOfflineException,
            InvalidWorkerIdException, KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setWorkerProperty(AdminInfo adminInfo, int workerId,
            String key, String value) {
        final Worker worker = workers.get(workerId);
        if (worker == null) {
            LOG.error("No such worker: " + workerId);
        } else {
            worker.getConfig().setProperty(key, value);
        }
    }

    @Override
    public boolean removeWorkerProperty(AdminInfo adminInfo, int workerId,
            String key) {
        final boolean result;
        final Worker worker = workers.get(workerId);
        if (worker == null) {
            LOG.error("No such worker: " + workerId);
            result = false;
        } else {
            result = worker.getConfig().removeProperty(key);
        }
        return result;
    }

    @Override
    public void addAuthorizedClient(AdminInfo adminInfo, int signerId,
            AuthorizedClient authClient) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    @Override
    public void addAuthorizedClientGen2(AdminInfo adminInfo, int signerId,
            CertificateMatchingRule authClient) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean removeAuthorizedClient(AdminInfo adminInfo, int signerId,
            AuthorizedClient authClient) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    @Override
    public boolean removeAuthorizedClientGen2(AdminInfo adminInfo, int signerId,
            CertificateMatchingRule authClient) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ICertReqData getCertificateRequest(AdminInfo adminInfo,
            WorkerIdentifier signerId, ISignerCertReqInfo certReqInfo,
            boolean explicitEccParameters, boolean defaultKey)
                    throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ICertReqData getCertificateRequest(AdminInfo adminInfo,
            WorkerIdentifier signerId, ISignerCertReqInfo certReqInfo,
            boolean explicitEccParameters) throws CryptoTokenOfflineException,
            InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void uploadSignerCertificate(AdminInfo adminInfo, int signerId,
            byte[] signerCert, String scope) throws CertificateException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void uploadSignerCertificateChain(AdminInfo adminInfo, int signerId, List<byte[]> signerCerts, String scope)
                    throws CertificateException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Response process(final AdminInfo adminInfo, WorkerIdentifier workerId, Request request,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        lastRequestContext = requestContext;
        Worker worker = workers.get(workerId.getId());
        if (worker == null) {
            throw new CryptoTokenOfflineException("No such worker: "
                    + workerId);
        }
        // Put in an empty log map if none exists yet
        LogMap.getInstance(requestContext);
        if (requestContext.get(RequestContext.TRANSACTION_ID) == null) {
           requestContext.put(RequestContext.TRANSACTION_ID, UUID.randomUUID().toString());
        }
        RequestMetadata.getInstance(requestContext);
        
        return worker.getProcessable().processData(request, requestContext);
    }   
        
    @Override
    public WorkerStatus getStatus(WorkerIdentifier workerId) throws
            InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean isTokenActive(WorkerIdentifier workerId) throws InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int getWorkerId(String workerName) throws InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void reloadConfiguration(int workerId) {
        reloadConfiguration(new AdminInfo("Mock user", null, null), workerId);
    }

    @Override
    public void reloadConfiguration(final AdminInfo adminInfo, int workerId) {
        final Worker worker = workers.get(workerId);
        if (worker == null) {
            LOG.error("No such worker: " + workerId);
        } else {
            worker.getProcessable().init(workerId, worker.getConfig(),
                    new SignServerContext(), null);
        }
    }

    @Override
    public void activateSigner(WorkerIdentifier signerId, String authenticationCode)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean deactivateSigner(WorkerIdentifier signerId) throws
            CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public WorkerConfig getCurrentWorkerConfig(int signerId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    @Override
    public Properties exportWorkerConfig(int signerId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setWorkerProperty(int workerId, String key, String value) {
        setWorkerProperty(null, workerId, key, value);
    }

    @Override
    public boolean removeWorkerProperty(int workerId, String key) {
        return removeWorkerProperty(null, workerId, key);
    }

    @Override
    public Collection<AuthorizedClient> getAuthorizedClients(int signerId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    @Override
    public Collection<CertificateMatchingRule> getAuthorizedClientsGen2(int signerId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void addAuthorizedClient(int signerId, AuthorizedClient authClient) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    @Override
    public void addAuthorizedClientGen2(int signerId, CertificateMatchingRule authClient) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean removeAuthorizedClient(int signerId,
            AuthorizedClient authClient) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    @Override
    public boolean removeAuthorizedClientGen2(int signerId,
            CertificateMatchingRule authClient) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ICertReqData getCertificateRequest(WorkerIdentifier signerId,
            ISignerCertReqInfo certReqInfo, final boolean explicitEccParameters)
            throws CryptoTokenOfflineException,
            InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ICertReqData getCertificateRequest(WorkerIdentifier signerId,
            ISignerCertReqInfo certReqInfo, final boolean explicitEccParameters,
            boolean defaultKey) throws CryptoTokenOfflineException,
            InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ICertReqData getCertificateRequest(AdminInfo adminInfo, WorkerIdentifier signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, String keyAlias) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ICertReqData getCertificateRequest(WorkerIdentifier signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, String keyAlias) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Certificate getSignerCertificate(WorkerIdentifier signerId) throws
            CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<Certificate> getSignerCertificateChain(WorkerIdentifier signerId) throws
            CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Date getSigningValidityNotAfter(WorkerIdentifier workerId) throws
            CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Date getSigningValidityNotBefore(WorkerIdentifier workerId) throws
            CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public long getKeyUsageCounterValue(WorkerIdentifier workerId) throws
            CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean removeKey(AdminInfo adminInfo, WorkerIdentifier signerId, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException, SignServerException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean removeKey(WorkerIdentifier signerId, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException, SignServerException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String generateSignerKey(WorkerIdentifier signerId, String keyAlgorithm,
            String keySpec, String alias, char[] authCode) throws
            CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Collection<KeyTestResult> testKey(WorkerIdentifier signerId, String alias,
            char[] authCode) throws CryptoTokenOfflineException,
            InvalidWorkerIdException, KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void uploadSignerCertificate(int signerId,
            byte[] signerCert, String scope) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void uploadSignerCertificateChain(int signerId, List<byte[]> signerCerts, String scope) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int genFreeWorkerId() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<ArchiveDataVO> findArchiveDataFromArchiveId(int signerId,
            String archiveId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<ArchiveDataVO> findArchiveDatasFromRequestIP(int signerId,
            String requestIP) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<ArchiveDataVO> findArchiveDatasFromRequestCertificate(
            int signerId, BigInteger serialNumber, String issuerDN) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void setupWorker(int workerId, String cryptoToken, WorkerConfig config,
            IProcessable worker) {
        config.setProperty(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, cryptoToken);
        workers.put(workerId, new Worker(worker, config));
    }

    @Override
    public byte[] getSignerCertificateBytes(WorkerIdentifier signerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<byte[]> getSignerCertificateChainBytes(WorkerIdentifier signerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<Integer> getWorkers(WorkerType workerType) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<Integer> getAllWorkers() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<? extends AuditLogEntry> selectAuditLogs(AdminInfo adminInfo, int startIndex, int max, QueryCriteria criteria, String logDeviceId) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<? extends AuditLogEntry> selectAuditLogs(int startIndex, int max, QueryCriteria criteria, String logDeviceId) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<ArchiveMetadata> searchArchive(int startIndex, int max,
            QueryCriteria criteria, final boolean includeData) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<ArchiveMetadata> searchArchive(AdminInfo adminInfo,
            int startIndex, int max, QueryCriteria criteria,
            final boolean includeData) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<ArchiveMetadata> searchArchiveWithIds(AdminInfo adminInfo,
        List<String> uniqueIds, boolean includeData) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<ArchiveMetadata> searchArchiveWithIds(List<String> uniqueIds,
        boolean includeData) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] getKeystoreData(AdminInfo adminInfo, int signerId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setKeystoreData(AdminInfo adminInfo, int signerId, byte[] keystoreData) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void importCertificateChain(WorkerIdentifier signerId, List<byte[]> signerCerts, String alias, char[] authenticationCode) throws CryptoTokenOfflineException, CertificateException, IllegalArgumentException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void importCertificateChain(AdminInfo adminInfo, WorkerIdentifier signerId, List<byte[]> signerCerts, String alias, char[] authenticationCode) throws CryptoTokenOfflineException, CertificateException, OperationUnsupportedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public TokenSearchResults searchTokenEntries(AdminInfo adminInfo, WorkerIdentifier workerId, int startIndex, int max, QueryCriteria qc, boolean includeData, Map<String, Object> params) throws OperationUnsupportedException, CryptoTokenOfflineException, QueryException, InvalidWorkerIdException, AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public TokenSearchResults searchTokenEntries(WorkerIdentifier workerId, int startIndex, int max, QueryCriteria qc, boolean includeData, Map<String, Object> params) throws OperationUnsupportedException, CryptoTokenOfflineException, QueryException, InvalidWorkerIdException, AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<Certificate> getSigningCertificateChain(AdminInfo adminInfo, WorkerIdentifier signerId, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<Certificate> getSignerCertificateChain(WorkerIdentifier signerId, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<String> getAllWorkerNames() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public RequestContext getLastRequestContext() {
        return lastRequestContext;
    }

    @Override
    public List<String> getCertificateIssues(int workerId, List<Certificate> certificateChain) throws InvalidWorkerIdException {
        return new ArrayList<>();
    }

    @Override
    public boolean isKeyGenerationDisabled() {
        return false;
    }

    @Override
    public void updateWorkerProperties(AdminInfo adminInfo, int workerId,
                                       Map<String, String> propertiesAndValues,
                                       List<String> propertiesToRemove) {
        throw new UnsupportedOperationException("Not supported yet."); 
    }

    @Override
    public void updateWorkerProperties(int workerId,
                                       Map<String, String> propertiesAndValues,
                                       List<String> propertiesToRemove) {
        throw new UnsupportedOperationException("Not supported yet."); 
    }

    private static class Worker {
        private final IProcessable processable;
        private final WorkerConfig config;

        public Worker(IProcessable processable, WorkerConfig config) {
            this.processable = processable;
            this.config = config;
        }

        public WorkerConfig getConfig() {
            return config;
        }

        public IProcessable getProcessable() {
            return processable;
        }

    }
}
