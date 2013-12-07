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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.KeyTestResult;

/**
 * Empty crypto token implementation that can be used by workers not really needing 
 * a crypto token.
 * 
 * The crypto token remain in the status given when it is constructed. Activation
 * and de-activation has no effect.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class NullCryptoToken implements ICryptoToken {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(NullCryptoToken.class);
    
    private final int status;

    public NullCryptoToken(final int status) {
        this.status = status;
    }
    
    @Override
    public void init(int workerId, Properties props) throws CryptoTokenInitializationFailureException {
        if (LOG.isTraceEnabled()) {
            LOG.trace("init");
        }
    }

    @Override
    public int getCryptoTokenStatus() {
        return status;
    }

    @Override
    public void activate(final String authenticationcode) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException {
        if (LOG.isTraceEnabled()) {
            LOG.trace("activate");
        }
    }

    @Override
    public boolean deactivate() throws CryptoTokenOfflineException {
        if (LOG.isTraceEnabled()) {
            LOG.trace("deactivate");
        }
        return true;
    }

    @Override
    public PrivateKey getPrivateKey(int purpose) throws CryptoTokenOfflineException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("getPrivateKey(" + purpose + ")");
        }
        throw new CryptoTokenOfflineException("Unsupported by crypto token");
    }

    @Override
    public PublicKey getPublicKey(int purpose) throws CryptoTokenOfflineException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("getPublicKey(" + purpose + ")");
        }
        throw new CryptoTokenOfflineException("Unsupported by crypto token");
    }

    @Override
    public String getProvider(int providerUsage) {
        return "BC";
    }

    @Override
    public Certificate getCertificate(int purpose) throws CryptoTokenOfflineException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("getCertificate(" + purpose + ")");
        }
        return null;
    }

    @Override
    public List<Certificate> getCertificateChain(int purpose) throws CryptoTokenOfflineException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("getCertificateChain(" + purpose + ")");
        }
        throw new CryptoTokenOfflineException("Unsupported by crypto token");
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, boolean defaultKey) throws CryptoTokenOfflineException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("genCertificateRequest");
        }
        throw new CryptoTokenOfflineException("Unsupported by crypto token");
    }

    @Override
    public boolean destroyKey(int purpose) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("destroyKey");
        }
        return true;
    }

    @Override
    public Collection<KeyTestResult> testKey(String alias, char[] authCode) throws CryptoTokenOfflineException, KeyStoreException {
        if (LOG.isTraceEnabled()) {
            LOG.trace("testKey");
        }
        return Collections.emptyList();
    }

    @Override
    public KeyStore getKeyStore() throws UnsupportedOperationException, CryptoTokenOfflineException, KeyStoreException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("getKeyStore");
        }
        throw new CryptoTokenOfflineException("Unsupported by crypto token");
    }
    
}
