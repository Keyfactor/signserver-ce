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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Properties;
import javax.naming.NamingException;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.KeyTestResult;
import org.signserver.common.ServiceLocator;
import org.signserver.common.WorkerStatus;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.statusrepo.common.NoSuchPropertyException;
import org.signserver.statusrepo.StatusRepositorySession;

/**
 * Test crypto token recording testKey() operations.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class TestKeyDebugCryptoToken implements ICryptoToken {

    private static Logger LOG = Logger.getLogger(TestKeyDebugCryptoToken.class);

    private String debugProperty;
    private String testKey;
    private boolean disableTestKey;
      
    private StatusRepositorySession statusSession;
    
    /**
     * Status repository property to set.
     */
    public static String TESTKEY_DEBUG_PROPERTY = "TESTKEY_DEBUG_PROPERTY";
    
    /**
     * Property to set to simulate missing TESTKEY.
     */
    public static String DISABLE_TESTKEY = "DISABLE_TESTKEY";
    
    @Override
    public void init(int workerId, Properties props) throws CryptoTokenInitializationFailureException {
        this.debugProperty = props.getProperty(TESTKEY_DEBUG_PROPERTY);
        this.testKey = props.getProperty(HSMKeepAliveTimedService.TESTKEY);
        this.disableTestKey =
                Boolean.parseBoolean(props.getProperty(DISABLE_TESTKEY,
                                                       Boolean.FALSE.toString()));
    
        try {
            statusSession = ServiceLocator.getInstance().lookupLocal(StatusRepositorySession.class);
        } catch (NamingException ex) {
            throw new RuntimeException("Unable to lookup worker session",
                    ex);
        }
    }

    @Override
    public int getCryptoTokenStatus() {
        return WorkerStatus.STATUS_ACTIVE;
    }

    @Override
    public void activate(String authenticationcode) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean deactivate() throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public PrivateKey getPrivateKey(int purpose) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public PublicKey getPublicKey(int purpose) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String getProvider(int providerUsage) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Certificate getCertificate(int purpose) throws CryptoTokenOfflineException {
        return null;
    }

    @Override
    public List<Certificate> getCertificateChain(int purpose) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, boolean defaultKey) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean destroyKey(int purpose) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Collection<KeyTestResult> testKey(String alias, char[] authCode) throws CryptoTokenOfflineException, KeyStoreException {
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
            statusSession.update(debugProperty, content);
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
    
}
