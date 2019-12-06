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
package org.signserver.server.timedservices.hsmkeepalive;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.DuplicateAliasException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.NoSuchAliasException;
import org.signserver.common.QueryException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.TokenOutOfSpaceException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerStatus;
import org.signserver.server.IServices;
import org.signserver.server.cryptotokens.BaseCryptoToken;
import org.signserver.server.cryptotokens.DefaultCryptoInstance;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.TokenSearchResults;
import org.signserver.statusrepo.common.NoSuchPropertyException;
import org.signserver.statusrepo.StatusRepositorySessionLocal;

/**
 * Test crypto token recording testKey() operations.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class TestKeyDebugCryptoToken extends BaseCryptoToken {

    private static Logger LOG = Logger.getLogger(TestKeyDebugCryptoToken.class);

    private String debugProperty;
    private String testKey;
    private boolean disableTestKey;

    /**
     * Status repository property to set.
     */
    public static String TESTKEY_DEBUG_PROPERTY = "TESTKEY_DEBUG_PROPERTY";
    
    /**
     * Property to set to simulate missing TESTKEY.
     */
    public static String DISABLE_TESTKEY = "DISABLE_TESTKEY";
    
    @Override
    public void init(int workerId, Properties props, org.signserver.server.IServices services) throws CryptoTokenInitializationFailureException {
        this.debugProperty = props.getProperty(TESTKEY_DEBUG_PROPERTY);
        this.testKey = props.getProperty(HSMKeepAliveTimedService.TESTKEY);
        this.disableTestKey =
                Boolean.parseBoolean(props.getProperty(DISABLE_TESTKEY,
                                                       Boolean.FALSE.toString()));
    }

    @Override
    public int getCryptoTokenStatus(final IServices services) {
        return WorkerStatus.STATUS_ACTIVE;
    }

    @Override
    public void activate(String authenticationcode, final IServices services) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean deactivate(final IServices services) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Collection<KeyTestResult> testKey(String alias, char[] authCode, final IServices services) throws CryptoTokenOfflineException, KeyStoreException {
        boolean success = true;
        String message = "";
        String content = alias;
        
        // if using the TESTKEY alias and set to simulate missing the test key
        if (testKey != null && testKey.equals(alias) && disableTestKey) {
            success = false;
            message = "no such key";
            content = "_NoKey";
        }
        try {
            services.get(StatusRepositorySessionLocal.class).update(debugProperty, content);
        } catch (NoSuchPropertyException ex) {
            throw new CryptoTokenOfflineException("Unknown status property: " +
                    debugProperty);
        }

        return Arrays.asList(new KeyTestResult(alias, success, message, null));
    }

    @Override
    public KeyStore getKeyStore() throws UnsupportedOperationException, CryptoTokenOfflineException, KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void importCertificateChain(List<Certificate> certChain, String alias, char[] athenticationCode, Map<String, Object> params, IServices services) throws TokenOutOfSpaceException, CryptoTokenOfflineException, NoSuchAliasException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public TokenSearchResults searchTokenEntries(int startIndex, int max, QueryCriteria qc, boolean includeData, Map<String, Object> params, IServices services) throws CryptoTokenOfflineException, QueryException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ICryptoInstance acquireCryptoInstance(String alias, Map<String, Object> params, RequestContext context) throws CryptoTokenOfflineException, NoSuchAliasException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter, IllegalRequestException {
        return new DefaultCryptoInstance(alias, context, null, null);
    }

    @Override
    public void releaseCryptoInstance(ICryptoInstance instance, RequestContext context) {
    }

    @Override
    public void generateKey(String keyAlgorithm, String keySpec, String alias, char[] authCode, Map<String, Object> params, IServices services) throws TokenOutOfSpaceException, CryptoTokenOfflineException, DuplicateAliasException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, String keyAlias, IServices services) throws CryptoTokenOfflineException, NoSuchAliasException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean removeKey(String alias, IServices services) throws CryptoTokenOfflineException, KeyStoreException, SignServerException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
