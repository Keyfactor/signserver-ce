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
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Date;
import java.util.List;
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
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.NotSupportedException;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.QueryException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.log.AdminInfo;

/**
 * Generic CryptoToken tests using KeyStoreCryptoToken.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class KeystoreCryptoTokenTest extends CryptoTokenTestBase {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(KeystoreCryptoTokenTest.class);
    
    private final MockedKeystoreInConfig instance = new MockedKeystoreInConfig();
    
    private final String existingKey1 = getConfig().getProperty("test.p11.existingkey1");
    private final String existingKey2 = getConfig().getProperty("test.p11.existingkey2");

    public KeystoreCryptoTokenTest() {
    }
    
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
    }
    
    private void initKeystore() throws CryptoTokenInitializationFailureException,
                                       CryptoTokenAuthenticationFailureException,
                                       CryptoTokenOfflineException {
        Properties config = new Properties();
        config.setProperty("KEYSTOREPASSWORD", "password123123213");
        instance.init(1, config);
        instance.activate("password123123213");
        instance.generateKey("RSA", "1024", existingKey1, null);
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
    protected TokenSearchResults searchTokenEntries(int startIndex, int max, QueryCriteria qc, boolean includeData) throws CryptoTokenOfflineException, QueryException {
        return instance.searchTokenEntries(startIndex, max, qc, includeData);
    }

    @Override
    protected void generateKey(String keyType, String keySpec, String alias) throws CryptoTokenOfflineException {
        instance.generateKey(keyType, keySpec, alias, null);
    }

    @Override
    protected boolean destroyKey(String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException, KeyStoreException {
        return instance.removeKey(alias);
    }

    @Override
    protected void importCertificateChain(List<Certificate> chain, String alias) throws CryptoTokenOfflineException, IllegalArgumentException {
        instance.importCertificateChain(chain, alias, null);
    }

    @Override
    protected ICertReqData genCertificateRequest(final ISignerCertReqInfo req,
                                                 final boolean explicitEccParameters,
                                                 final String alias)
            throws CryptoTokenOfflineException {
        return instance.genCertificateRequest(req, explicitEccParameters, alias);
    }

    @Override
    protected List<Certificate> getCertificateChain(final String alias)
            throws CryptoTokenOfflineException {
        return instance.getCertificateChain(alias);
    }

    
    private static class MockedKeystoreInConfig extends KeystoreInConfigCryptoToken {
        @Override
        protected IWorkerSession.ILocal getWorkerSession() { // TODO Extract to adaptor
            
            return new IWorkerSession.ILocal() {
                
                private byte[] keystoreData;

                @Override
                public List<? extends AuditLogEntry> selectAuditLogs(AdminInfo adminInfo, int startIndex, int max, QueryCriteria criteria, String logDeviceId) throws AuthorizationDeniedException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public boolean removeKey(AdminInfo adminInfo, int signerId, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException, SignServerException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public String generateSignerKey(AdminInfo adminInfo, int signerId, String keyAlgorithm, String keySpec, String alias, char[] authCode) throws CryptoTokenOfflineException, InvalidWorkerIdException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public Collection<KeyTestResult> testKey(AdminInfo adminInfo, int signerId, String alias, char[] authCode) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException {
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
                public boolean removeAuthorizedClient(AdminInfo adminInfo, int signerId, AuthorizedClient authClient) {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public ICertReqData getCertificateRequest(AdminInfo adminInfo, int signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, boolean defaultKey) throws CryptoTokenOfflineException, InvalidWorkerIdException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public ICertReqData getCertificateRequest(AdminInfo adminInfo, int signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters) throws CryptoTokenOfflineException, InvalidWorkerIdException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public ICertReqData getCertificateRequest(AdminInfo adminInfo, int signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, String keyAlias) throws CryptoTokenOfflineException, InvalidWorkerIdException {
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
                public void uploadSignerCertificateChain(AdminInfo adminInfo, int signerId, Collection<byte[]> signerCerts, String scope) throws CertificateException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public void importCertificateChain(AdminInfo adminInfo, int signerId, List<byte[]> signerCerts, String alias, char[] authenticationCode) throws CryptoTokenOfflineException, CertificateException, OperationUnsupportedException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public ProcessResponse process(AdminInfo info, int workerId, ProcessRequest request, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
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
                public ProcessResponse process(int workerId, ProcessRequest request, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public WorkerStatus getStatus(int workerId) throws InvalidWorkerIdException {
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
                public void activateSigner(int signerId, String authenticationCode) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException, InvalidWorkerIdException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public boolean deactivateSigner(int signerId) throws CryptoTokenOfflineException, InvalidWorkerIdException {
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
                public void addAuthorizedClient(int signerId, AuthorizedClient authClient) {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public boolean removeAuthorizedClient(int signerId, AuthorizedClient authClient) {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public ICertReqData getCertificateRequest(int signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters) throws CryptoTokenOfflineException, InvalidWorkerIdException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public ICertReqData getCertificateRequest(int signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, boolean defaultKey) throws CryptoTokenOfflineException, InvalidWorkerIdException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public ICertReqData getCertificateRequest(int signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, String keyAlias) throws CryptoTokenOfflineException, InvalidWorkerIdException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public Certificate getSignerCertificate(int signerId) throws CryptoTokenOfflineException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public byte[] getSignerCertificateBytes(int signerId) throws CryptoTokenOfflineException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public List<Certificate> getSignerCertificateChain(int signerId) throws CryptoTokenOfflineException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public List<byte[]> getSignerCertificateChainBytes(int signerId) throws CryptoTokenOfflineException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public Date getSigningValidityNotAfter(int workerId) throws CryptoTokenOfflineException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public Date getSigningValidityNotBefore(int workerId) throws CryptoTokenOfflineException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public long getKeyUsageCounterValue(int workerId) throws CryptoTokenOfflineException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public boolean removeKey(int signerId, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException, SignServerException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public String generateSignerKey(int signerId, String keyAlgorithm, String keySpec, String alias, char[] authCode) throws CryptoTokenOfflineException, InvalidWorkerIdException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public Collection<KeyTestResult> testKey(int signerId, String alias, char[] authCode) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public void uploadSignerCertificate(int signerId, byte[] signerCert, String scope) throws CertificateException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public void uploadSignerCertificateChain(int signerId, Collection<byte[]> signerCerts, String scope) throws CertificateException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public void importCertificateChain(int signerId, List<byte[]> signerCerts, String alias, char[] authenticationCode) throws CryptoTokenOfflineException, CertificateException, OperationUnsupportedException {
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
                public List<Integer> getWorkers(int workerType) {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public TokenSearchResults searchTokenEntries(AdminInfo adminInfo, int workerId, int startIndex, int max, QueryCriteria qc, boolean includeData) throws NotSupportedException, CryptoTokenOfflineException, QueryException, InvalidWorkerIdException, AuthorizationDeniedException, SignServerException {
                    throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                }

                @Override
                public List<Certificate> getSigningCertificateChain(AdminInfo adminInfo, int signerId, String alias) throws CryptoTokenOfflineException {
                    throw new UnsupportedOperationException("Not supported yet.");
                }

                @Override
                public List<Certificate> getSignerCertificateChain(int signerId, String alias) throws CryptoTokenOfflineException {
                    throw new UnsupportedOperationException("Not supported yet.");
                }
            };
        }
    }
}
