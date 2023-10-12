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
package org.signserver.testutils;

import io.restassured.http.Method;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.QueryCriteria;
import org.json.simple.JSONObject;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.ArchiveMetadata;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.QueryException;
import org.signserver.common.SignServerException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerExistsException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerType;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.server.cryptotokens.TokenSearchResults;

/**
 * Wrapper implementing the operations from WorkerSessionRemote with REST
 * calls.
 * Used to seemlessly move system tests to use the REST interface for 
 * administration operations.
 * 
 * @author Marcus Lundblad
 */
public class WorkerSessionRest implements WorkerSessionRemote {

    private final ModulesTestCase mt;
    private final WorkerSessionRemote workerSessionEjb;

    public WorkerSessionRest(final ModulesTestCase mt,
                             final WorkerSessionRemote workerSessionEjb) {
        this.mt = mt;
        this.workerSessionEjb = workerSessionEjb;
    }
    
    @Override
    public List<? extends AuditLogEntry> selectAuditLogs(int startIndex, int max, QueryCriteria criteria, String logDeviceId) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public TokenSearchResults searchTokenEntries(WorkerIdentifier workerId, int startIndex, int max, QueryCriteria qc, boolean includeData, Map<String, Object> params) throws InvalidWorkerIdException, AuthorizationDeniedException, CryptoTokenOfflineException, QueryException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter, OperationUnsupportedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public WorkerStatus getStatus(WorkerIdentifier wi) throws InvalidWorkerIdException {
        return workerSessionEjb.getStatus(wi);
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
        /* delegate to the EJB implementation, as this is not supported by REST
         * interface yet
         */
        workerSessionEjb.reloadConfiguration(workerId);
    }

    @Override
    public void activateSigner(WorkerIdentifier signerId, String authenticationCode) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean deactivateSigner(WorkerIdentifier signerId) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public WorkerConfig getCurrentWorkerConfig(int signerId) {
        /* delegate to the EJB implementation, as this is not supported by REST
         * interface yet
         */
        return workerSessionEjb.getCurrentWorkerConfig(signerId);
    }

    @Override
    public Properties exportWorkerConfig(int signerId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setWorkerProperty(int workerId, String key, String value) {
        final JSONObject body = new JSONObject();
        final JSONObject properties = new JSONObject();

        properties.put(key, value);
        body.put("properties", properties);

        mt.callRest(Method.PATCH, "/workers/" + workerId, body);
    }

    @Override
    public boolean removeWorkerProperty(int workerId, String key) {
        final JSONObject body = new JSONObject();
        final JSONObject properties = new JSONObject();

        properties.put("-" + key, "");
        body.put("properties", properties);
        
        mt.callRest(Method.PATCH, "/workers/" + workerId, body);

        return true;
    }

    @Override
    public void updateWorkerProperties(int workerId, Map<String, String> propertiesAndValues, List<String> propertiesToRemove) {
        final JSONObject body = new JSONObject();
        final JSONObject properties = new JSONObject();

        for (final String property : propertiesAndValues.keySet()) {
            properties.put(property, propertiesAndValues.get(property));
        }
        for (final String property : propertiesToRemove) {
            properties.put("-" + property, null);
        }
        body.put("properties", properties);

        mt.callRest(Method.PATCH, "/workers/" + workerId, body);
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
    public boolean removeAuthorizedClient(int signerId, AuthorizedClient authClient) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean removeAuthorizedClientGen2(int signerId, CertificateMatchingRule authClient) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ICertReqData getCertificateRequest(WorkerIdentifier signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ICertReqData getCertificateRequest(WorkerIdentifier signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, boolean defaultKey) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ICertReqData getCertificateRequest(WorkerIdentifier signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, String keyAlias) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Certificate getSignerCertificate(WorkerIdentifier signerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] getSignerCertificateBytes(WorkerIdentifier signerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<Certificate> getSignerCertificateChain(WorkerIdentifier signerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<Certificate> getSignerCertificateChain(WorkerIdentifier signerId, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<byte[]> getSignerCertificateChainBytes(WorkerIdentifier signerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Date getSigningValidityNotAfter(WorkerIdentifier workerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Date getSigningValidityNotBefore(WorkerIdentifier workerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public long getKeyUsageCounterValue(WorkerIdentifier workerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean removeKey(WorkerIdentifier signerId, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException, SignServerException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String generateSignerKey(WorkerIdentifier signerId, String keyAlgorithm, String keySpec, String alias, char[] authCode) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Collection<KeyTestResult> testKey(WorkerIdentifier signerId, String alias, char[] authCode) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void uploadSignerCertificate(int signerId, byte[] signerCert, String scope) throws CertificateException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void uploadSignerCertificateChain(int signerId, List<byte[]> signerCerts, String scope) throws CertificateException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void importCertificateChain(WorkerIdentifier signerId, List<byte[]> signerCerts, String alias, char[] authenticationCode) throws CryptoTokenOfflineException, CertificateException, OperationUnsupportedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int genFreeWorkerId() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<ArchiveDataVO> findArchiveDataFromArchiveId(int signerId, String archiveId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<ArchiveDataVO> findArchiveDatasFromRequestIP(int signerId, String requestIP) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<ArchiveDataVO> findArchiveDatasFromRequestCertificate(int signerId, BigInteger serialNumber, String issuerDN) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<ArchiveMetadata> searchArchive(int startIndex, int max, QueryCriteria criteria, boolean includeData) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<ArchiveMetadata> searchArchiveWithIds(List<String> uniqueIds, boolean includeData) throws AuthorizationDeniedException {
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
    public List<String> getAllWorkerNames() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<String> getCertificateIssues(int workerId, List<Certificate> certificateChain) throws InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void addUpdateDeleteWorkerProperties(int workerId, Map<String, String> propertiesAndValues, List<String> propertiesToRemove) throws NoSuchWorkerException, WorkerExistsException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
}
