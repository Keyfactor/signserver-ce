/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.signserver.common.CompileTimeSettings;
import org.signserver.server.cryptotokens.CryptoServiceLocatorV2;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Class implementing a keystore on PKCS11 tokens.
 *
 * @version $Id: PKCS11CryptoToken.java 31320 2019-01-25 10:35:32Z anatom $
 */
public class PKCS11CryptoToken implements CryptoToken {

    static final Logger LOG = Logger.getLogger(org.cesecore.keys.token.PKCS11CryptoToken.class);
    private final org.cesecore.keys.token.CryptoToken delegate;

    public PKCS11CryptoToken() throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        final String value = CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.USEP11NGASP11);
        boolean usep11ngasp11 = Boolean.parseBoolean(value);
        final boolean usep11ngasp11dbCli = getCLIDbEnabled();
        Class<?> implClass;
        if (usep11ngasp11 || usep11ngasp11dbCli) {
            implClass = CryptoServiceLocatorV2.getCryptoTokenImplementationClass(true);
        } else {
            implClass = org.cesecore.keys.token.LegacyPKCS11CryptoToken.class;
        }
        LOG.info("Using the following PKCS#11 implementation for database protection: " + implClass.getName());
        Object obj = implClass.newInstance();
        delegate = (org.cesecore.keys.token.CryptoToken) obj;
    }

    @Override
    public void init(final Properties properties, final byte[] data, final int id) throws Exception {
        Properties props = new Properties();
        props.putAll(properties);

        String value = CompileTimeSettings.getInstance().getProperty("cryptotoken.p11.usep11ngasp11");
        boolean usep11ngasp11 = Boolean.parseBoolean(value);
        final boolean usep11ngasp11dbCli = getCLIDbEnabled();
        if (usep11ngasp11 || usep11ngasp11dbCli) {
            if (props.containsKey("slotLabelType")) {
                props.setProperty("SLOTLABELTYPE", props.getProperty("slotLabelType"));
                props.setProperty("SLOTLABELVALUE", props.getProperty("slotLabelValue"));
                props.remove("slotLabelType");
                props.remove("slotLabelValue");
            }
        }
        delegate.init(props, data, id);
    }

    @Override
    public int getId() {
        return delegate.getId();
    }

    @Override
    public void activate(char[] authenticationcode) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        delegate.activate(authenticationcode);
    }

    @Override
    public void deactivate() {
        delegate.deactivate();
    }

    @Override
    public boolean isAliasUsed(String alias) {
        return delegate.isAliasUsed(alias);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) throws CryptoTokenOfflineException {
        return delegate.getPrivateKey(alias);
    }

    @Override
    public PublicKey getPublicKey(String alias) throws CryptoTokenOfflineException {
        return delegate.getPublicKey(alias);
    }

    @Override
    public Key getKey(String alias) throws CryptoTokenOfflineException {
        return delegate.getKey(alias);
    }

    @Override
    public void deleteEntry(String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, CryptoTokenOfflineException {
        delegate.deleteEntry(alias);
    }

    @Override
    public void generateKeyPair(String keySpec, String alias) throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        delegate.generateKeyPair(keySpec, alias);
    }

    @Override
    public void generateKeyPair(AlgorithmParameterSpec spec, String alias) throws InvalidAlgorithmParameterException, CertificateException, IOException, CryptoTokenOfflineException {
        delegate.generateKeyPair(spec, alias);
    }

    @Override
    public void generateKey(String algorithm, int keysize, String alias) throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException, SignatureException, CertificateException, IOException, NoSuchPaddingException, IllegalBlockSizeException {
        delegate.generateKey(algorithm, keysize, alias);
    }

    @Override
    public String getSignProviderName() {
        return delegate.getSignProviderName();
    }

    @Override
    public String getEncProviderName() {
        return delegate.getEncProviderName();
    }

    @Override
    public void reset() {
        delegate.reset();
    }

    @Override
    public String getTokenName() {
        return delegate.getTokenName();
    }

    @Override
    public void setTokenName(String tokenName) {
        delegate.setTokenName(tokenName);
    }

    @Override
    public int getTokenStatus() {
        return delegate.getTokenStatus();
    }

    @Override
    public Properties getProperties() {
        return delegate.getProperties();
    }

    @Override
    public void setProperties(Properties properties) {
        delegate.setProperties(properties);
    }

    @Override
    public void storeKey(String alias, Key key, Certificate[] chain, char[] password) throws KeyStoreException {
        delegate.storeKey(alias, key, chain, password);
    }

    @Override
    public byte[] getTokenData() {
        return delegate.getTokenData();
    }

    @Override
    public void testKeyPair(String alias) throws InvalidKeyException, CryptoTokenOfflineException {
        delegate.testKeyPair(alias);
    }

    @Override
    public void testKeyPair(String alias, PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
        delegate.testKeyPair(alias, publicKey, privateKey);
    }

    @Override
    public boolean doPermitExtractablePrivateKey() {
        return delegate.doPermitExtractablePrivateKey();
    }

    @Override
    public List<String> getAliases() throws KeyStoreException, CryptoTokenOfflineException {
        return delegate.getAliases();
    }

    @Override
    public boolean isAutoActivationPinPresent() {
        return delegate.isAutoActivationPinPresent();
    }

    private boolean getCLIDbEnabled() {
        Properties properties = new Properties();
        InputStream in = null;
        try {
            in = PKCS11CryptoToken.class.getResourceAsStream("/signserver_cli.properties");
            if (in != null) {
                properties.load(in);
            }
        } catch (IOException ex) {
            LOG.error("Could not load configuration: " + ex.getMessage());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOG.error("Failed to close configuration", ex);
                }
            }
        }
        return Boolean.parseBoolean(properties.getProperty("dbcli.databaseprotection.usep11ngasp11"));
    }

}
