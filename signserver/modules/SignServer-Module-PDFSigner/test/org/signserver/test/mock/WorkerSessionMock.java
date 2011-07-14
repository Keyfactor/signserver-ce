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
package org.signserver.test.mock;

import java.math.BigInteger;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import org.apache.log4j.Logger;
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

    public ProcessResponse process(int workerId, ProcessRequest request,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        Worker worker = workers.get(workerId);
        if (worker == null) {
            throw new CryptoTokenOfflineException("No such worker: "
                    + workerId);
        }
        return worker.getProcessable().processData(request, requestContext);
    }

    public WorkerStatus getStatus(int workerId) throws
            InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public int getWorkerId(String workerName) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void reloadConfiguration(int workerId) {
        final Worker worker = workers.get(workerId);
        if (worker == null) {
            LOG.error("No such worker: " + workerId);
        } else {
            worker.getProcessable().init(workerId, worker.getConfig(),
                    null, null);
        }
    }

    public void activateSigner(int signerId, String authenticationCode)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public boolean deactivateSigner(int signerId) throws
            CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public WorkerConfig getCurrentWorkerConfig(int signerId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void setWorkerProperty(int workerId, String key, String value) {
        final boolean result;
        final Worker worker = workers.get(workerId);
        if (worker == null) {
            LOG.error("No such worker: " + workerId);
        } else {
            worker.getConfig().setProperty(key, value);
        }
    }

    public boolean removeWorkerProperty(int workerId, String key) {
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

    public Collection<AuthorizedClient> getAuthorizedClients(int signerId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void addAuthorizedClient(int signerId, AuthorizedClient authClient) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public boolean removeAuthorizedClient(int signerId,
            AuthorizedClient authClient) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public ICertReqData getCertificateRequest(int signerId, 
            ISignerCertReqInfo certReqInfo, final boolean explicitEccParameters)
            throws CryptoTokenOfflineException,
            InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public ICertReqData getCertificateRequest(int signerId, 
            ISignerCertReqInfo certReqInfo, final boolean explicitEccParameters, 
            boolean defaultKey) throws CryptoTokenOfflineException,
            InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public Certificate getSignerCertificate(int signerId) throws
            CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public List<Certificate> getSignerCertificateChain(int signerId) throws
            CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public Date getSigningValidityNotAfter(int workerId) throws
            CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public Date getSigningValidityNotBefore(int workerId) throws
            CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public long getKeyUsageCounterValue(int workerId) throws
            CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public boolean destroyKey(int signerId, int purpose) throws
            InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public String generateSignerKey(int signerId, String keyAlgorithm, 
            String keySpec, String alias, char[] authCode) throws
            CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public Collection<KeyTestResult> testKey(int signerId, String alias, 
            char[] authCode) throws CryptoTokenOfflineException,
            InvalidWorkerIdException, KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void uploadSignerCertificate(int signerId,
            byte[] signerCert, String scope) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void uploadSignerCertificateChain(int signerId,
            Collection<byte[]> signerCerts, String scope) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public int genFreeWorkerId() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public ArchiveDataVO findArchiveDataFromArchiveId(int signerId,
            String archiveId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public List<ArchiveDataVO> findArchiveDatasFromRequestIP(int signerId,
            String requestIP) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

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
