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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.*;
import org.signserver.server.IServices;
import org.signserver.server.cryptotokens.BaseCryptoToken;
import org.signserver.server.cryptotokens.DefaultCryptoInstance;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.TokenSearchResults;

/**
 * CryptoToken backed by the provided Keys and Certificates.
 * Only used methods are implemented.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class MockedCryptoToken extends BaseCryptoToken {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(MockedCryptoToken.class);
    
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final Certificate signerCertificate;
    private final List<Certificate> certificateChain;
    private final Provider provider;
    private final String providerName;

    private int privateKeyCalls;
    
    public MockedCryptoToken(PrivateKey privateKey, PublicKey publicKey, Certificate signerCertificate, List<Certificate> certificateChain, String providerName) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.signerCertificate = signerCertificate;
        this.certificateChain = certificateChain;
        this.providerName = providerName;
        this.provider = null;
    }

    public MockedCryptoToken(PrivateKey privateKey, PublicKey publicKey, Certificate signerCertificate, List<Certificate> certificateChain, Provider provider) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.signerCertificate = signerCertificate;
        this.certificateChain = certificateChain;
        this.provider = provider;
        this.providerName = null;
    }

    /** Constructs a MockedCryptoToken for a non-existing key. */
    public MockedCryptoToken() {
        this(null, null, null, null, (Provider) null);
    }

    @Override
    public void init(int workerId, Properties props, IServices services) throws CryptoTokenInitializationFailureException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public int getCryptoTokenStatus() {
        LOG.debug(">getCryptoTokenStatus");
        return privateKey != null ? WorkerStatus.STATUS_ACTIVE : WorkerStatus.STATUS_OFFLINE;
    }
    
    @Override
    public int getCryptoTokenStatus(final IServices services) {
        return getCryptoTokenStatus();
    }

    @Override
    public void activate(String authenticationcode, final IServices services) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException {
        LOG.debug(">activate");
    }

    @Override
    public boolean deactivate(final IServices services) throws CryptoTokenOfflineException {
        LOG.debug(">deactivate");
        return true;
    }

    public PrivateKey getPrivateKey(int purpose) throws CryptoTokenOfflineException {
        LOG.debug(">getPrivateKey");
        privateKeyCalls++;
        checkExisting();
        return privateKey;
    }

    public PublicKey getPublicKey(int purpose) throws CryptoTokenOfflineException {
        LOG.debug(">getPublicKey");
        checkExisting();
        return publicKey;
    }

    public String getProvider(int providerUsage) {
        LOG.debug(">getProvider");
        if (provider == null) {
            return providerName;
        } else {
            return provider.getName();
        }
    }

    public Certificate getCertificate(int purpose) throws CryptoTokenOfflineException {
        LOG.debug(">getCertificate");
        checkExisting();
        return signerCertificate;
    }

    public List<Certificate> getCertificateChain(int purpose) throws CryptoTokenOfflineException {
        LOG.debug(">getCertificateChain");
        checkExisting();
        return certificateChain;
    }

    public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, boolean defaultKey) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public boolean destroyKey(int purpose) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public Collection<KeyTestResult> testKey(String alias, char[] authCode) throws CryptoTokenOfflineException, KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public KeyStore getKeyStore() throws UnsupportedOperationException, CryptoTokenOfflineException, KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public int getPrivateKeyCalls() {
        return privateKeyCalls;
    }
    
    @Override
    public void importCertificateChain(List<Certificate> certChain, String alias, char[] athenticationCode, Map<String, Object> params, IServices services) throws CryptoTokenOfflineException, IllegalArgumentException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public TokenSearchResults searchTokenEntries(int startIndex, int max, QueryCriteria qc, boolean includeData, Map<String, Object> params, IServices services) throws CryptoTokenOfflineException, QueryException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public ICryptoInstance acquireCryptoInstance(String alias, Map<String, Object> params, RequestContext context) throws CryptoTokenOfflineException, NoSuchAliasException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter, IllegalRequestException {
        checkExisting();
        return new DefaultCryptoInstance(alias, context, provider == null ? Security.getProvider(providerName) : provider, privateKey, certificateChain);
    }

    @Override
    public void releaseCryptoInstance(ICryptoInstance instance, RequestContext context) {
        // NOP
    }

    @Override
    public void generateKey(String keyAlgorithm, String keySpec, String alias, char[] authCode, Map<String, Object> params, IServices services) throws CryptoTokenOfflineException, IllegalArgumentException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, String keyAlias, IServices services) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Collection<KeyTestResult> testKey(String alias, char[] authCode, IServices Services) throws CryptoTokenOfflineException, KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean removeKey(String alias, IServices services) throws CryptoTokenOfflineException, KeyStoreException, SignServerException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    private void checkExisting() throws CryptoTokenOfflineException {
        if (privateKey == null) {
            throw new CryptoTokenOfflineException("Non-existing key");
        }
    }

}
