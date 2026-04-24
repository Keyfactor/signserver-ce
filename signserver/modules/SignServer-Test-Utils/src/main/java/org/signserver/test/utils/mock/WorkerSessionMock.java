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
import java.security.cert.X509Certificate;
import java.util.*;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.CertTools;
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
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.QueryException;
import org.signserver.common.ReadOnlyWorkerException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerExistsException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerType;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.util.ReadOnlyUtils;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.server.IProcessable;
import org.signserver.server.IWorker;
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

    // Array of integers containing worker ID's that will be treated as read-only.
    private Set<Integer> readOnlyWorkers;

    public WorkerSessionMock() {
        readOnlyWorkers = new HashSet<>();
    }

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
            String key, String value) throws ReadOnlyWorkerException {
        // Special case for auto-detecting worker type
        if (WorkerConfig.TYPE.equalsIgnoreCase(key) && (value == null || value.trim().isEmpty())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Auto-detecting worker type");
            }
            try {
                // Imitating the WorkerFactory loadWorker(..) method.
                IWorker obj = workers.get(workerId).getProcessable();
                if (obj.getConfig() == null) {
                    throw new NoSuchWorkerException(String.valueOf(workerId));
                }
                value = obj.getWorkerType().name();
            } catch (NoSuchWorkerException ex) {
                LOG.error("Unable to auto-detect worker type as the worker can not be found: " + ex.getWorkerIdOrName());
            }
        }

        if (!ReadOnlyUtils.isModificationAllowed(adminInfo, workerId, readOnlyWorkers)) {
            throw new ReadOnlyWorkerException("Worker " + workerId + " is read-only");
        }

        WorkerConfig config = workers.get(workerId).getConfig();
        config.setProperty(key.toUpperCase(Locale.ENGLISH), value);
        setWorkerConfig(adminInfo, workerId, config, null, null);
    }

    @Override
    public boolean removeWorkerProperty(AdminInfo adminInfo, int workerId,
            String key) throws ReadOnlyWorkerException {
        final boolean result;
        final Worker worker = workers.get(workerId);
        if (worker == null) {
            LOG.error("No such worker: " + workerId);
            return false;
        }

        if (!ReadOnlyUtils.isModificationAllowed(adminInfo, workerId, readOnlyWorkers)) {
            throw new ReadOnlyWorkerException("Worker " + workerId + " is read-only");
        }

        return worker.getConfig().removeProperty(key);
    }

    @Override
    public void removeWorker(AdminInfo adminInfo, int workerId) throws ReadOnlyWorkerException, NoSuchWorkerException {
        if (!isWorkerExists(workerId)) {
            LOG.debug("No such worker: " + workerId);
            throw new NoSuchWorkerException(String.valueOf(workerId));
        }

        if (!ReadOnlyUtils.isModificationAllowed(adminInfo, workerId, readOnlyWorkers)) {
            throw new ReadOnlyWorkerException("Worker " + workerId + " is read-only");
        }

        final Worker worker = workers.remove(workerId);
        boolean result = worker != null;

        if (result) {
            LOG.debug("Worker " + workerId + " removed.");
        } else {
            LOG.debug("Removing worker with ID " + workerId + " failed.");
            throw new NoSuchWorkerException(String.valueOf(workerId));
        }
    }

    @Override
    public boolean isWorkerExists(int workerId) {
        return workers.containsKey(workerId);
    }

    @Override
    public boolean isWorkerExists(AdminInfo adminInfo, int workerId) {
        return workers.containsKey(workerId);
    }

    @Override
    public void addWorker(AdminInfo adminInfo, int workerId, Map<String, String> propertiesAndValues) throws WorkerExistsException, ReadOnlyWorkerException {
        if (isWorkerExists(workerId)) {
            LOG.debug("Worker already exists: " + workerId);
            throw new WorkerExistsException(String.valueOf(workerId));
        }
        updateWorkerProperties(adminInfo, workerId, propertiesAndValues, Collections.emptyList());
    }

    @Override
    public void addAuthorizedClient(AdminInfo adminInfo, int signerId,
            AuthorizedClient authClient) throws ReadOnlyWorkerException {
        if (!ReadOnlyUtils.isModificationAllowed(adminInfo, signerId, readOnlyWorkers)) {
            throw new ReadOnlyWorkerException("Worker " + signerId + " is read-only");
        }
        WorkerConfig config = workers.get(signerId).getConfig();
        config.addAuthorizedClient(authClient);
        setWorkerConfig(adminInfo, signerId, config, "added:authorized_client",
                "SN: " + authClient.getCertSN() + ", issuer DN: " + authClient.getIssuerDN());
    }

    @Override
    public void addAuthorizedClientGen2(AdminInfo adminInfo, int signerId,
            CertificateMatchingRule authClient) throws ReadOnlyWorkerException {
        if (!ReadOnlyUtils.isModificationAllowed(adminInfo, signerId, readOnlyWorkers)) {
            throw new ReadOnlyWorkerException("Worker " + signerId + " is read-only");
        }
        WorkerConfig config = workers.get(signerId).getConfig();
        config.addAuthorizedClientGen2(authClient);
        setWorkerConfig(adminInfo, signerId, config, "added:authorized_client_gen2", authClient.toString());
    }

    @Override
    public boolean removeAuthorizedClient(AdminInfo adminInfo, int signerId,
            AuthorizedClient authClient) throws ReadOnlyWorkerException {
        if (!ReadOnlyUtils.isModificationAllowed(adminInfo, signerId, readOnlyWorkers)) {
            throw new ReadOnlyWorkerException("Worker " + signerId + " is read-only");
        }
        boolean result;
        WorkerConfig config = workers.get(signerId).getConfig();

        result = config.removeAuthorizedClient(authClient);
        setWorkerConfig(adminInfo, signerId, config, "removed:authorized_client",
                "SN: " + authClient.getCertSN() + ", issuer DN: " + authClient.getIssuerDN());
        return result;
    }

    @Override
    public boolean removeAuthorizedClientGen2(AdminInfo adminInfo, int signerId,
            CertificateMatchingRule authClient) throws ReadOnlyWorkerException {
        if (!ReadOnlyUtils.isModificationAllowed(adminInfo, signerId, readOnlyWorkers)) {
            throw new ReadOnlyWorkerException("Worker " + signerId + " is read-only");
        }
        boolean result;
        WorkerConfig config = workers.get(signerId).getConfig();

        result = config.removeAuthorizedClientGen2(authClient);
        setWorkerConfig(adminInfo, signerId, config, "removed:authorized_client_gen2", authClient.toString());
        return result;
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
            byte[] signerCert, String scope) throws CertificateException, ReadOnlyWorkerException {
        if (!ReadOnlyUtils.isModificationAllowed(adminInfo, signerId, readOnlyWorkers)) {
            throw new ReadOnlyWorkerException("Worker " + signerId + " is read-only");
        }

        WorkerConfig config = workers.get(signerId).getConfig();
        final Certificate cert  = CertTools.getCertfromByteArray(signerCert);
        config.setSignerCertificate((X509Certificate)cert,scope);
        setWorkerConfig(adminInfo, signerId, config, null, null);
    }

    @Override
    public void uploadSignerCertificateChain(AdminInfo adminInfo, int signerId, List<byte[]> signerCerts, String scope)
            throws CertificateException, ReadOnlyWorkerException {
        if (!ReadOnlyUtils.isModificationAllowed(adminInfo, signerId, readOnlyWorkers)) {
            throw new ReadOnlyWorkerException("Worker " + signerId + " is read-only");
        }

        WorkerConfig config = workers.get(signerId).getConfig();
        ArrayList<Certificate> certs = new ArrayList<>();
        Iterator<byte[]> iter = signerCerts.iterator();
        while(iter.hasNext()){
            X509Certificate cert;
            cert = (X509Certificate) CertTools.getCertfromByteArray(iter.next());
            certs.add(cert);
        }
        // Collections.reverse(certs); // TODO: Why?

        config.setSignerCertificateChain(certs, scope);
        setWorkerConfig(adminInfo, signerId, config, null, null);
    }

    @Override
    public Response process(final AdminInfo adminInfo, WorkerIdentifier workerId,
                            Optional<String> certId, Optional<String> publicKeyId, Request request,
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
    public WorkerConfig getCurrentWorkerConfig(AdminInfo admin, int signerId) {
        return workers.get(signerId).getConfig();
    }

    @Override
    public Properties exportWorkerConfig(int signerId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setWorkerProperty(int workerId, String key, String value) throws ReadOnlyWorkerException {
        setWorkerProperty(null, workerId, key, value);
    }

    @Override
    public boolean removeWorkerProperty(int workerId, String key) throws ReadOnlyWorkerException {
        return removeWorkerProperty(new AdminInfo("CLI user", null, null, null), workerId, key);
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
    public void addAuthorizedClient(int signerId, AuthorizedClient authClient) throws ReadOnlyWorkerException {
        addAuthorizedClient(new AdminInfo("CLI user", null, null, null),
                signerId, authClient);
    }

    @Override
    public void addAuthorizedClientGen2(int signerId, CertificateMatchingRule authClient) throws ReadOnlyWorkerException {
        addAuthorizedClientGen2(new AdminInfo("CLI user", null, null, null), signerId, authClient);
    }

    @Override
    public boolean removeAuthorizedClient(int signerId,
            AuthorizedClient authClient) throws ReadOnlyWorkerException {
        return removeAuthorizedClient(new AdminInfo("CLI user", null, null, null), signerId, authClient);
    }

    @Override
    public boolean removeAuthorizedClientGen2(int signerId,
            CertificateMatchingRule authClient) throws ReadOnlyWorkerException {
        return removeAuthorizedClientGen2(new AdminInfo("CLU user", null, null, null), signerId, authClient);
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
            byte[] signerCert, String scope) throws CertificateException, ReadOnlyWorkerException {
        uploadSignerCertificate(new AdminInfo("CLI user", null, null, null), signerId, signerCert, scope);
    }

    @Override
    public void uploadSignerCertificateChain(int signerId, List<byte[]> signerCerts, String scope) throws CertificateException, ReadOnlyWorkerException {
        uploadSignerCertificateChain(new AdminInfo("CLI user", null, null, null),
                signerId, signerCerts, scope);
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
        // In some cases, we might not want to specify a crypto token.
        if (cryptoToken != null) {
            config.setProperty(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, cryptoToken);
        }
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
    public void importCertificateChain(WorkerIdentifier signerId, List<byte[]> signerCerts, String alias, char[] authenticationCode) throws CryptoTokenOfflineException, CertificateException, IllegalArgumentException, OperationUnsupportedException {
        importCertificateChain(new AdminInfo("CLI user", null, null, null),
                signerId, signerCerts, alias, authenticationCode);
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
                                       List<String> propertiesToRemove) throws ReadOnlyWorkerException {
        if (!ReadOnlyUtils.isModificationAllowed(adminInfo, workerId, readOnlyWorkers)) {
            throw new ReadOnlyWorkerException("Worker " + workerId + " is read-only");
        }
        final WorkerConfig config = workers.get(workerId).getConfig();

        //First we add the added and changed properties to the config
        for (Map.Entry mapElement : propertiesAndValues.entrySet()) {
            config.setProperty(((String)mapElement.getKey()).toUpperCase(Locale.ENGLISH), (String)mapElement.getValue());
        }

        //We extend the hashmap with all values that shall be removed
        //for logging ourposes, the log will go through all items in the HM-hashmap
        for (String toDelete: propertiesToRemove) {
            propertiesAndValues.put(toDelete, "REMOVED");
        }

        //Then we remove all properties that are on the remove-list
        for (String propertyToRemove: propertiesToRemove) {
            config.removeProperty(propertyToRemove.toUpperCase());
        }
    }

    @Override
    public void replaceWorkerProperties(AdminInfo adminInfo, int workerId, Map<String, String> propertiesAndValues) throws NoSuchWorkerException, ReadOnlyWorkerException, WorkerExistsException {
        if (!isWorkerExists(workerId)) {
            LOG.debug("No such worker: " + workerId);
            throw new NoSuchWorkerException(String.valueOf(workerId));
        }

        if (!ReadOnlyUtils.isModificationAllowed(adminInfo, workerId, readOnlyWorkers)) {
            throw new ReadOnlyWorkerException("Worker " + workerId + " is read-only");
        }
        final WorkerConfig config = workers.get(workerId).getConfig();

        if (propertiesAndValues.containsKey("NAME")
                && !config.getProperties().getProperty("NAME").equalsIgnoreCase(propertiesAndValues.get("NAME"))) {
            String workerName = propertiesAndValues.get("NAME");
            if (checkWorkerNameAlreadyExists(workerName)) {
                LOG.debug("Worker name already exists: " + workerName);
                throw new WorkerExistsException(workerName);
            }
        }

        //First we remove all the properties from the config
        for (Map.Entry mapEntry : config.getProperties().entrySet()) {
            config.removeProperty(((String) mapEntry.getKey()).toUpperCase());
        }

        //We add new properties to the config
        for (Map.Entry mapElement : propertiesAndValues.entrySet()) {
            config.setProperty(((String) mapElement.getKey()).toUpperCase(Locale.ENGLISH), (String) mapElement.getValue());
        }

        updateWorkerConfig(adminInfo, workerId, config);
    }

    @Override
    public void updateWorkerProperties(int workerId,
                                       Map<String, String> propertiesAndValues,
                                       List<String> propertiesToRemove) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void addUpdateDeleteWorkerProperties(int workerId, Map<String, String> propertiesAndValues,
                                                List<String> propertiesToRemove) throws NoSuchWorkerException, WorkerExistsException, ReadOnlyWorkerException {
        addUpdateDeleteWorkerProperties(new AdminInfo("CLI user", null, null, null), workerId,
                propertiesAndValues, propertiesToRemove);
    }

    @Override
    public void addUpdateDeleteWorkerProperties(AdminInfo adminInfo, int workerId, Map<String, String> propertiesAndValues,
                                                List<String> propertiesToRemove) throws ReadOnlyWorkerException, NoSuchWorkerException, WorkerExistsException {
        if (!ReadOnlyUtils.isModificationAllowed(adminInfo, workerId, readOnlyWorkers)) {
            throw new ReadOnlyWorkerException("Worker " + workerId + " is read-only");
        }
        if (!isWorkerExists(workerId)) {
            LOG.debug("No such worker: " + workerId);
            throw new NoSuchWorkerException(String.valueOf(workerId));
        }
        final WorkerConfig config = workers.get(workerId).getConfig();

        if (propertiesAndValues.containsKey("NAME")
                && !config.getProperties().getProperty("NAME").equalsIgnoreCase(propertiesAndValues.get("NAME"))) {
            String workerName = propertiesAndValues.get("NAME");
            if (checkWorkerNameAlreadyExists(workerName)) {
                LOG.debug("Worker name already exists: " + workerName);
                throw new WorkerExistsException(workerName);
            }
        }

        //First we add the added and changed properties to the config
        for (Map.Entry mapElement : propertiesAndValues.entrySet()) {
            config.setProperty(((String) mapElement.getKey()).toUpperCase(Locale.ENGLISH), (String) mapElement.getValue());
        }

        //Then we remove all properties that are on the remove-list
        for (String propertyToRemove : propertiesToRemove) {
            config.removeProperty(propertyToRemove.toUpperCase());
        }
        updateWorkerConfig(adminInfo, workerId, config);
    }

    private boolean checkWorkerNameAlreadyExists(String workerName) {
        for (Worker worker : workers.values()) {
            final String currentWorkerName = worker.getConfig().getProperty("NAME");
            if (workerName.equalsIgnoreCase(currentWorkerName)) {
                return true;
            }
        }
        return false;
    }

    private void updateWorkerConfig(AdminInfo adminInfo, int workerId, WorkerConfig config) {
        if (config.getProperties().size() <= config.getVirtualPropertiesNumber()) {
            workers.remove(workerId);
            LOG.debug("WorkerConfig is empty and therefore removed.");
        } else {
            setWorkerConfig(adminInfo, workerId, config, null, null);
        }
    }

    private void setWorkerConfig(/*Usually used for audit logging */final AdminInfo adminInfo, final int workerId, final WorkerConfig config,
                                 final String additionalLogKey, final String additionalLogValue) {
        final WorkerConfig oldConfig = workers.get(workerId).getConfig();

        scrambleMaskedProperties(oldConfig);

        Map<String, Object> configChanges = config.propertyDiffAgainst(oldConfig);

        if (additionalLogKey != null) {
            configChanges.put(additionalLogKey, additionalLogValue);
        }

        Worker worker = workers.get(workerId);
        workers.replace(workerId, new Worker(worker.getProcessable(), config));
    }

    private void scrambleMaskedProperties(final WorkerConfig config) {
        for (final Object o : config.getProperties().keySet()) {
            final String key = (String) o;

            if (config.shouldMaskProperty(key)) {
                config.getProperties().setProperty(key, "_OLD_MASKED_");
            }
        }
    }

    public void setReadOnlyWorkers(final Set<Integer> readOnlyWorkers) {
        this.readOnlyWorkers = readOnlyWorkers;
    }

    private static class Worker {
        private final IProcessable processable;
        private final WorkerConfig config;

        public Worker(IProcessable processable, WorkerConfig config) {
            this.processable = processable;
            this.config = config;
        }

        public Worker(WorkerConfig config) {
            this.config = config;
            processable = null;
        }

        public WorkerConfig getConfig() {
            return config;
        }

        public IProcessable getProcessable() {
            return processable;
        }

    }
}
