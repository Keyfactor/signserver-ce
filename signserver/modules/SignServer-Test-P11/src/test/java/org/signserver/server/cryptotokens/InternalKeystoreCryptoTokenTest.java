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
package org.signserver.server.cryptotokens;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.QueryCriteria;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.ArchiveMetadata;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.NoSuchAliasException;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.QueryException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerType;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.server.IServices;
import org.signserver.server.ServicesImpl;
import org.signserver.server.entities.IKeyUsageCounterDataService;
import org.signserver.server.entities.KeyUsageCounter;
import org.signserver.server.log.AdminInfo;
import org.signserver.test.utils.mock.MockedServicesImpl;

/**
 * Generic CryptoToken tests using KeyStoreCryptoToken.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class InternalKeystoreCryptoTokenTest extends CryptoTokenTestBase {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(InternalKeystoreCryptoTokenTest.class);
    
    private final MockedKeystoreInConfig instance = new MockedKeystoreInConfig();

    private final String existingKey1 = getConfig().getProperty("test.p11.existingkey1");
    private final String existingECKey1 = getConfig().getProperty("test.p11.existingECkey1");

    public InternalKeystoreCryptoTokenTest() {
    }
    
    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }
    
    private void initKeystore() throws CryptoTokenInitializationFailureException,
                                       CryptoTokenAuthenticationFailureException,
                                       CryptoTokenOfflineException {
        Properties config = new Properties();
        config.setProperty("KEYSTOREPASSWORD", "password123123213");
        instance.init(1, config, new MockedServicesImpl());
        instance.activate("password123123213", instance.getMockedServices());
        instance.generateKey("RSA", "1024", existingKey1, null, Collections.<String, Object>emptyMap(), instance.getMockedServices());
        instance.generateKey("ECDSA", "secp384r1", existingECKey1, null, Collections.<String, Object>emptyMap(), instance.getMockedServices());
    }
    
    @Test
    public void testSearchTokenEntries_KeystoreCryptoToken() throws Exception {
        initKeystore();
        searchTokenEntriesHelper(existingKey1);
    }
   
    @Test
    public void testImportCertificateChain() throws Exception {
        initKeystore();
        importCertificateChainHelper(existingKey1);
    }
    
    @Test
    public void testExportCertificateChain() throws Exception {
        initKeystore();
        exportCertificatesHelper(existingKey1);
    }

    @Override
    public TokenSearchResults searchTokenEntries(int startIndex, int max, QueryCriteria qc, boolean includeData) throws CryptoTokenOfflineException, QueryException {
        return instance.searchTokenEntries(startIndex, max, qc, includeData, null, instance.getMockedServices());
    }

    @Override
    public void generateKey(String keyType, String keySpec, String alias) throws CryptoTokenOfflineException {
        instance.generateKey(keyType, keySpec, alias, null, Collections.<String, Object>emptyMap(), instance.getMockedServices());
    }

    @Override
    public boolean removeKey(String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException, KeyStoreException {
        return instance.removeKey(alias, instance.getMockedServices());
    }

    @Override
    protected void importCertificateChain(List<Certificate> chain, String alias) throws CryptoTokenOfflineException, IllegalArgumentException {
        instance.importCertificateChain(chain, alias, null, Collections.<String, Object>emptyMap(), new ServicesImpl());
    }

    @Override
    protected ICertReqData genCertificateRequest(final ISignerCertReqInfo req,
                                                 final boolean explicitEccParameters,
                                                 final String alias)
            throws CryptoTokenOfflineException {
        return instance.genCertificateRequest(req, explicitEccParameters, alias, null);
    }

    @Override
    protected List<Certificate> getCertificateChain(String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        RequestContext context = new RequestContext(true);
        context.setServices(instance.getMockedServices());
        ICryptoInstance crypto = null;
        try {
            crypto = instance.acquireCryptoInstance(alias, Collections.<String, Object>emptyMap(), context);
            return crypto.getCertificateChain();
        } catch (InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter | IllegalRequestException | NoSuchAliasException ex) {
            throw new CryptoTokenOfflineException(ex);
        } finally {
            if (crypto != null) {
                instance.releaseCryptoInstance(crypto, context);
            }
        }
    }

    
    private static class MockedKeystoreInConfig extends KeystoreInConfigCryptoToken {
        
        private WorkerSessionLocal workerSession;
        
        /**
        * @return A mocked IServices with the same WorkerSessionLocal as a call
        * to getWorkerSession() would return
        */
        public IServices getMockedServices() {
            IServices servicesImpl = new ServicesImpl();
            servicesImpl.put(WorkerSessionLocal.class, getWorkerSession(null));
            servicesImpl.put(IKeyUsageCounterDataService.class, getKeyUsageCounterDataService());
            return servicesImpl;
        }
    
        @Override
        protected WorkerSessionLocal getWorkerSession(final IServices services) { // TODO Extract to adaptor
            if (workerSession == null) {
                workerSession = new WorkerSessionLocal() {

                    private byte[] keystoreData;

                    @Override
                    public List<? extends AuditLogEntry> selectAuditLogs(AdminInfo adminInfo, int startIndex, int max, QueryCriteria criteria, String logDeviceId) throws AuthorizationDeniedException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public boolean removeKey(AdminInfo adminInfo, WorkerIdentifier signerId, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException, SignServerException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public String generateSignerKey(AdminInfo adminInfo, WorkerIdentifier signerId, String keyAlgorithm, String keySpec, String alias, char[] authCode) throws CryptoTokenOfflineException, InvalidWorkerIdException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public Collection<KeyTestResult> testKey(AdminInfo adminInfo, WorkerIdentifier signerId, String alias, char[] authCode) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public void setWorkerProperty(AdminInfo adminInfo, int workerId, String key, String value) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public boolean removeWorkerProperty(AdminInfo adminInfo, int workerId, String key) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public void addAuthorizedClient(AdminInfo adminInfo, int signerId, AuthorizedClient authClient) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }
                    
                    @Override
                    public void addAuthorizedClientGen2(AdminInfo adminInfo, int signerId, CertificateMatchingRule authClient) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public boolean removeAuthorizedClient(AdminInfo adminInfo, int signerId, AuthorizedClient authClient) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }
                    
                    @Override
                    public boolean removeAuthorizedClientGen2(AdminInfo adminInfo, int signerId, CertificateMatchingRule authClient) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public ICertReqData getCertificateRequest(AdminInfo adminInfo, WorkerIdentifier signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, boolean defaultKey) throws CryptoTokenOfflineException, InvalidWorkerIdException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public ICertReqData getCertificateRequest(AdminInfo adminInfo, WorkerIdentifier signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters) throws CryptoTokenOfflineException, InvalidWorkerIdException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public ICertReqData getCertificateRequest(AdminInfo adminInfo, WorkerIdentifier signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, String keyAlias) throws CryptoTokenOfflineException, InvalidWorkerIdException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public byte[] getKeystoreData(AdminInfo adminInfo, int signerId) {
                        return keystoreData;
                    }

                    @Override
                    public void setKeystoreData(AdminInfo adminInfo, int signerId, byte[] keystoreData) {
                        this.keystoreData = keystoreData;
                    }

                    @Override
                    public void uploadSignerCertificate(AdminInfo adminInfo, int signerId, byte[] signerCert, String scope) throws CertificateException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public void uploadSignerCertificateChain(AdminInfo adminInfo, int signerId, List<byte[]> signerCerts, String scope) throws CertificateException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public void importCertificateChain(AdminInfo adminInfo, WorkerIdentifier signerId, List<byte[]> signerCerts, String alias, char[] authenticationCode) throws CryptoTokenOfflineException, CertificateException, OperationUnsupportedException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public void reloadConfiguration(AdminInfo adminInfo, int workerId) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public List<ArchiveMetadata> searchArchive(AdminInfo adminInfo, int startIndex, int max, QueryCriteria criteria, boolean includeData) throws AuthorizationDeniedException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public List<ArchiveMetadata> searchArchiveWithIds(AdminInfo adminInfo, List<String> uniqueIds, boolean includeData) throws AuthorizationDeniedException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public WorkerStatus getStatus(WorkerIdentifier workerId) throws InvalidWorkerIdException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public boolean isTokenActive(WorkerIdentifier workerId) throws InvalidWorkerIdException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public int getWorkerId(String workerName) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public void reloadConfiguration(int workerId) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public void activateSigner(WorkerIdentifier signerId, String authenticationCode) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException, InvalidWorkerIdException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public boolean deactivateSigner(WorkerIdentifier signerId) throws CryptoTokenOfflineException, InvalidWorkerIdException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public WorkerConfig getCurrentWorkerConfig(int signerId) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public void setWorkerProperty(int workerId, String key, String value) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public boolean removeWorkerProperty(int workerId, String key) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public Collection<AuthorizedClient> getAuthorizedClients(int signerId) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }
                    
                    @Override
                    public Collection<CertificateMatchingRule> getAuthorizedClientsGen2(int signerId) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public void addAuthorizedClient(int signerId, AuthorizedClient authClient) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }
                    
                    @Override
                    public void addAuthorizedClientGen2(int signerId, CertificateMatchingRule authClient) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public boolean removeAuthorizedClient(int signerId, AuthorizedClient authClient) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }
                    
                    @Override
                    public boolean removeAuthorizedClientGen2(int signerId, CertificateMatchingRule authClient) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public ICertReqData getCertificateRequest(WorkerIdentifier signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters) throws CryptoTokenOfflineException, InvalidWorkerIdException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public ICertReqData getCertificateRequest(WorkerIdentifier signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, boolean defaultKey) throws CryptoTokenOfflineException, InvalidWorkerIdException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public ICertReqData getCertificateRequest(WorkerIdentifier signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, String keyAlias) throws CryptoTokenOfflineException, InvalidWorkerIdException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public Certificate getSignerCertificate(WorkerIdentifier signerId) throws CryptoTokenOfflineException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public byte[] getSignerCertificateBytes(WorkerIdentifier signerId) throws CryptoTokenOfflineException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public List<Certificate> getSignerCertificateChain(WorkerIdentifier signerId) throws CryptoTokenOfflineException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public List<byte[]> getSignerCertificateChainBytes(WorkerIdentifier signerId) throws CryptoTokenOfflineException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public Date getSigningValidityNotAfter(WorkerIdentifier workerId) throws CryptoTokenOfflineException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public Date getSigningValidityNotBefore(WorkerIdentifier workerId) throws CryptoTokenOfflineException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public long getKeyUsageCounterValue(WorkerIdentifier workerId) throws CryptoTokenOfflineException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public boolean removeKey(WorkerIdentifier signerId, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException, SignServerException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public String generateSignerKey(WorkerIdentifier signerId, String keyAlgorithm, String keySpec, String alias, char[] authCode) throws CryptoTokenOfflineException, InvalidWorkerIdException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public Collection<KeyTestResult> testKey(WorkerIdentifier signerId, String alias, char[] authCode) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public void uploadSignerCertificate(int signerId, byte[] signerCert, String scope) throws CertificateException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public void uploadSignerCertificateChain(int signerId, List<byte[]> signerCerts, String scope) throws CertificateException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public void importCertificateChain(WorkerIdentifier signerId, List<byte[]> signerCerts, String alias, char[] authenticationCode) throws CryptoTokenOfflineException, CertificateException, OperationUnsupportedException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public int genFreeWorkerId() {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public List<ArchiveDataVO> findArchiveDataFromArchiveId(int signerId, String archiveId) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public List<ArchiveDataVO> findArchiveDatasFromRequestIP(int signerId, String requestIP) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public List<ArchiveDataVO> findArchiveDatasFromRequestCertificate(int signerId, BigInteger serialNumber, String issuerDN) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public List<ArchiveMetadata> searchArchive(int startIndex, int max, QueryCriteria criteria, boolean includeData) throws AuthorizationDeniedException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public List<ArchiveMetadata> searchArchiveWithIds(List<String> uniqueIds, boolean includeData) throws AuthorizationDeniedException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public List<Integer> getWorkers(WorkerType workerType) {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public List<Integer> getAllWorkers() {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public TokenSearchResults searchTokenEntries(AdminInfo adminInfo, WorkerIdentifier workerId, int startIndex, int max, QueryCriteria qc, boolean includeData, Map<String, Object> params) throws OperationUnsupportedException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public List<Certificate> getSigningCertificateChain(AdminInfo adminInfo, WorkerIdentifier signerId, String alias) throws CryptoTokenOfflineException {
                        throw new UnsupportedOperationException("Not supported yet.");
                    }

                    @Override
                    public List<Certificate> getSignerCertificateChain(WorkerIdentifier signerId, String alias) throws CryptoTokenOfflineException {
                        throw new UnsupportedOperationException("Not supported yet.");
                    }

                    @Override
                    public List<String> getCertificateIssues(int workerId, List<Certificate> certificateChain) throws InvalidWorkerIdException {
                        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                    }

                    @Override
                    public Properties exportWorkerConfig(int signerId) {
                        throw new UnsupportedOperationException("Not supported yet.");
                    }

                    @Override
                    public List<String> getAllWorkerNames() {
                        throw new UnsupportedOperationException("Not supported yet."); 
                    }

                    @Override
                    public boolean isKeyGenerationDisabled() {
                        return false;
                    }

                    @Override
                    public void updateWorkerProperties(int workerId,
                                                       Map<String, String> propertiesAndValues,
                                                       List<String> propertiesToRemove) {
                        throw new UnsupportedOperationException("Not supported yet."); 
                    }
                    
                    @Override
                    public void updateWorkerProperties(AdminInfo adminInfo,
                                                       int workerId,
                                                       Map<String, String> propertiesAndValues,
                                                       List<String> propertiesToRemove) {
                        throw new UnsupportedOperationException("Not supported yet."); 
                    }

                    
                };
            }
            return workerSession;
        }
    }
    
     private static IKeyUsageCounterDataService getKeyUsageCounterDataService() {
        IKeyUsageCounterDataService KeyUsageCounterDataService = new IKeyUsageCounterDataService() {
            @Override
            public void create(String keyHash) {
                throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
            }

            @Override
            public KeyUsageCounter getCounter(String keyHash) {
                return null;
            }

            @Override
            public boolean incrementIfWithinLimit(String keyHash, long limit) {
                throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
            }

            @Override
            public boolean isWithinLimit(String keyHash, long keyUsageLimit) {
                throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
            }
        };
        return KeyUsageCounterDataService;
    }
}
