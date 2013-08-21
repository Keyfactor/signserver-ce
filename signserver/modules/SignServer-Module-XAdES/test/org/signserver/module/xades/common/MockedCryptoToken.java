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
package org.signserver.module.xades.common;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.server.cryptotokens.ICryptoToken;

/**
 * CryptoToken backed by the provided Keys and Certificates.
 * Only used methods are implemented.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class MockedCryptoToken implements ICryptoToken {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(MockedCryptoToken.class);
    
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Certificate signerCertificate;
    private List<Certificate> certificateChain;
    private String provider;

    private int privateKeyCalls;
    
    public MockedCryptoToken(PrivateKey privateKey, PublicKey publicKey, Certificate signerCertificate, List<Certificate> certificateChain, String provider) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.signerCertificate = signerCertificate;
        this.certificateChain = certificateChain;
        this.provider = provider;
    }
    
    public void init(int workerId, Properties props) throws CryptoTokenInitializationFailureException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public int getCryptoTokenStatus() {
        LOG.debug(">getCryptoTokenStatus");
        return CryptoTokenStatus.STATUS_ACTIVE;
    }

    public void activate(String authenticationcode) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException {
        LOG.debug(">activate");
    }

    public boolean deactivate() throws CryptoTokenOfflineException {
        LOG.debug(">deactivate");
        return true;
    }

    public PrivateKey getPrivateKey(int purpose) throws CryptoTokenOfflineException {
        LOG.debug(">getPrivateKey");
        privateKeyCalls++;
        return privateKey;
    }

    public PublicKey getPublicKey(int purpose) throws CryptoTokenOfflineException {
        LOG.debug(">getPublicKey");
        return publicKey;
    }

    public String getProvider(int providerUsage) {
        LOG.debug(">getProvider");
        return provider;
    }

    public Certificate getCertificate(int purpose) throws CryptoTokenOfflineException {
        LOG.debug(">getCertificate");
        return signerCertificate;
    }

    public List<Certificate> getCertificateChain(int purpose) throws CryptoTokenOfflineException {
        LOG.debug(">getCertificateChain");
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

    public KeyStore getKeyStore() throws UnsupportedOperationException, CryptoTokenOfflineException, KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public int getPrivateKeyCalls() {
        return privateKeyCalls;
    }
    
}
