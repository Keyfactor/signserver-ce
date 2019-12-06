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
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.KeyTestResult;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.server.IServices;

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
public class NullCryptoToken extends BaseCryptoToken {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(NullCryptoToken.class);
    
    private final int status;

    public NullCryptoToken(final int status) {
        this.status = status;
    }
    
    @Override
    public void init(int workerId, Properties props, org.signserver.server.IServices services) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("init");
        }
    }

    @Override
    public int getCryptoTokenStatus(IServices services) {
        return status;
    }

    @Override
    public void activate(final String authenticationcode, IServices services) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("activate");
        }
    }

    @Override
    public boolean deactivate(IServices services) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("deactivate");
        }
        return true;
    }

    @Override
    public KeyStore getKeyStore() throws CryptoTokenOfflineException{
        if (LOG.isDebugEnabled()) {
            LOG.debug("getKeyStore");
        }
        throw new CryptoTokenOfflineException("Unsupported by crypto token");
    }

    @Override
    public void importCertificateChain(List<Certificate> certChain, String alias, char[] athenticationCode, Map<String, Object> params, IServices services) throws CryptoTokenOfflineException {
        throw new CryptoTokenOfflineException("Unsupported by crypto token");
    }

    @Override
    public TokenSearchResults searchTokenEntries(int startIndex, int max, QueryCriteria qc, boolean includeData, Map<String, Object> params, IServices services) throws CryptoTokenOfflineException {
        throw new CryptoTokenOfflineException("Unsupported by crypto token");
    }

    @Override
    public ICryptoInstance acquireCryptoInstance(String alias, Map<String, Object> params, RequestContext context) throws CryptoTokenOfflineException {
        throw new CryptoTokenOfflineException("Unsupported by crypto token");
    }

    @Override
    public void releaseCryptoInstance(ICryptoInstance instance, RequestContext context) {
    }

    @Override
    public void generateKey(String keyAlgorithm, String keySpec, String alias, char[] authCode, Map<String, Object> params, IServices services) throws CryptoTokenOfflineException {
        throw new CryptoTokenOfflineException("Unsupported by crypto token");
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, String keyAlias, IServices services) throws CryptoTokenOfflineException {
        throw new CryptoTokenOfflineException("Unsupported by crypto token");
    }

    @Override
    public Collection<KeyTestResult> testKey(String alias, char[] authCode, IServices Services) throws CryptoTokenOfflineException {
        throw new CryptoTokenOfflineException("Unsupported by crypto token");
    }

    @Override
    public boolean removeKey(String alias, IServices services) throws CryptoTokenOfflineException, KeyStoreException, SignServerException {
        throw new CryptoTokenOfflineException("Unsupported by crypto token");
    }

}
