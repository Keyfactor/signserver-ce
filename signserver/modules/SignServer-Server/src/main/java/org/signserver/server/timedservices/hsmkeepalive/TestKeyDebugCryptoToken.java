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
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Arrays;
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
import org.signserver.server.cryptotokens.ICryptoToken;

/**
 * Test crypto token recording testKey() operations.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class TestKeyDebugCryptoToken implements ICryptoToken {

    private static Logger LOG = Logger.getLogger(TestKeyDebugCryptoToken.class);

    private String outPath;
    private String testKey;
    private boolean disableTestKey;
    
    /**
     * Output path for debug files.
     */
    static String TESTKEY_DEBUG_OUTPATH = "TESTKEY_DEBUG_OUTPATH";
    
    /**
     * Property to set to simulate missing TESTKEY.
     */
    static String DISABLE_TESTKEY = "DISABLE_TESTKEY";
    
    @Override
    public void init(int workerId, Properties props) throws CryptoTokenInitializationFailureException {
        this.outPath = props.getProperty(TESTKEY_DEBUG_OUTPATH);
        this.testKey = props.getProperty(HSMKeepAliveTimedService.TESTKEY);
        this.disableTestKey =
                Boolean.parseBoolean(props.getProperty(DISABLE_TESTKEY,
                                                       Boolean.FALSE.toString()));
    }

    @Override
    public int getCryptoTokenStatus() {
        throw new UnsupportedOperationException("Not supported yet.");
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
        // record the invocation
        final File debugFile =
                new File(outPath);
        
        // if using the TESTKEY alias and set simulate missing the test key
        if (testKey.equals(alias) && disableTestKey) {
            return Arrays.asList(new KeyTestResult(alias, false, "no such key", null));
        }
        
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(debugFile);
            fos.write(alias.getBytes());
        } catch (IOException e) {
            LOG.error("Failed to create debug file");
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                    // NOPMD ignored
                }
            }
        }
        
        return Arrays.asList(new KeyTestResult(alias, true, "", null));
    }

    @Override
    public KeyStore getKeyStore() throws UnsupportedOperationException, CryptoTokenOfflineException, KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
}
