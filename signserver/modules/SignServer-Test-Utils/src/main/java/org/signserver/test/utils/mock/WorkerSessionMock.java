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

import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.IProcessable;
import org.signserver.server.SignServerContext;
import org.signserver.server.WorkerContext;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.log.LogMap;

/**
 *
 * @author Markus Kilås
 * $version $Id$
 */
public class WorkerSessionMock implements IWorkerSession.ILocal,
        IWorkerSession.IRemote {

    private static final Logger LOG = Logger.getLogger(WorkerSessionMock.class);
    
    private GlobalConfigurationSessionMock globalConfig;

    private HashMap<Integer, Worker> workers
            = new HashMap<Integer, Worker>();

    public WorkerSessionMock(GlobalConfigurationSessionMock globalConfig) {
        this.globalConfig = globalConfig;
    }
    
    @Override
    public String generateSignerKey(AdminInfo adminInfo, int signerId,
            String keyAlgorithm, String keySpec, String alias, char[] authCode)
                    throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Collection<KeyTestResult> testKey(AdminInfo adminInfo, int signerId,
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
    public boolean removeAuthorizedClient(AdminInfo adminInfo, int signerId,
            AuthorizedClient authClient) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ICertReqData getCertificateRequest(AdminInfo adminInfo,
            int signerId, ISignerCertReqInfo certReqInfo,
            boolean explicitEccParameters, boolean defaultKey)
                    throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ICertReqData getCertificateRequest(AdminInfo adminInfo,
            int signerId, ISignerCertReqInfo certReqInfo,
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
    public void uploadSignerCertificateChain(AdminInfo adminInfo, int signerId,
            Collection<byte[]> signerCerts, String scope)
                    throws CertificateException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ProcessResponse process(int workerId, ProcessRequest request,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        return process(new AdminInfo("Mock user", null, null), workerId, request, requestContext);
    }
    
    @Override
    public ProcessResponse process(final AdminInfo adminInfo, int workerId, ProcessRequest request,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        Worker worker = workers.get(workerId);
        if (worker == null) {
            throw new CryptoTokenOfflineException("No such worker: "
                    + workerId);
        }
        // Put in an empty log map if none exists yet
        LogMap.getInstance(requestContext);
        if (requestContext.get(RequestContext.TRANSACTION_ID) == null) {
           requestContext.put(RequestContext.TRANSACTION_ID, UUID.randomUUID().toString());
        }
        return worker.getProcessable().processData(request, requestContext);
    }

    @Override
    public WorkerStatus getStatus(int workerId) throws
            InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int getWorkerId(String workerName) {
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
                    new WorkerContext() {}, null);
        }
    }

    @Override
    public void activateSigner(int signerId, String authenticationCode)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean deactivateSigner(int signerId) throws
            CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public WorkerConfig getCurrentWorkerConfig(int signerId) {
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
    public void addAuthorizedClient(int signerId, AuthorizedClient authClient) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean removeAuthorizedClient(int signerId,
            AuthorizedClient authClient) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ICertReqData getCertificateRequest(int signerId, 
            ISignerCertReqInfo certReqInfo, final boolean explicitEccParameters)
            throws CryptoTokenOfflineException,
            InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ICertReqData getCertificateRequest(int signerId, 
            ISignerCertReqInfo certReqInfo, final boolean explicitEccParameters, 
            boolean defaultKey) throws CryptoTokenOfflineException,
            InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Certificate getSignerCertificate(int signerId) throws
            CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<Certificate> getSignerCertificateChain(int signerId) throws
            CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Date getSigningValidityNotAfter(int workerId) throws
            CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Date getSigningValidityNotBefore(int workerId) throws
            CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public long getKeyUsageCounterValue(int workerId) throws
            CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean removeKey(AdminInfo adminInfo, int signerId, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException, SignServerException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean removeKey(int signerId, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException, SignServerException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    @Override
    public String generateSignerKey(int signerId, String keyAlgorithm, 
            String keySpec, String alias, char[] authCode) throws
            CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Collection<KeyTestResult> testKey(int signerId, String alias, 
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
    public void uploadSignerCertificateChain(int signerId,
            Collection<byte[]> signerCerts, String scope) {
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
        globalConfig.setProperty(GlobalConfiguration.SCOPE_GLOBAL,
                    GlobalConfiguration.WORKERPROPERTY_BASE + workerId
                    + GlobalConfiguration.OLD_CRYPTOTOKENPROPERTY_BASE
                    + GlobalConfiguration.CRYPTOTOKENPROPERTY_CLASSPATH,
                    cryptoToken);

        workers.put(workerId, new Worker(worker, config));
    }

    @Override
    public byte[] getSignerCertificateBytes(int signerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<byte[]> getSignerCertificateChainBytes(int signerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    @Override
    public List<Integer> getWorkers(int workerType) {
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

    private static class Worker {
        private IProcessable processable;
        private WorkerConfig config;

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
