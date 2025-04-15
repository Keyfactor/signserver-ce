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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.*;
import org.signserver.server.IServices;

import javax.naming.NamingException;

/**
 *
 * @author user
 */
public class PKCS11CryptoToken extends BaseCryptoToken {

    static final Logger LOG = Logger.getLogger(org.signserver.server.cryptotokens.PKCS11CryptoToken.class);
    private final ICryptoTokenV4 delegate;

    public PKCS11CryptoToken() throws ClassNotFoundException, InstantiationException, IllegalAccessException, NamingException {

        final String value = CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.USEP11NGASP11);
        boolean usep11ngasp11 = Boolean.parseBoolean(value);
        Class<?> implClass;
        if (usep11ngasp11) {
            implClass = CryptoServiceLocatorV2.getCryptoTokenImplementationClass(false);
        } else {
            implClass = org.signserver.server.cryptotokens.LegacyPKCS11CryptoToken.class;
        }
        LOG.info("Using the following PKCS#11 provider: " + implClass.getName());
        Object obj = implClass.newInstance();
        delegate = (ICryptoTokenV4) obj;
    }

    @Override
    public void init(int workerId, Properties props, IServices services) throws CryptoTokenInitializationFailureException {

        Properties properties = new Properties();
        properties.putAll(props);

        // Check that both the new or the legacy properties are specified at the same time
        if (props.getProperty(CryptoTokenHelper.PROPERTY_SLOT) != null && props.getProperty(CryptoTokenHelper.PROPERTY_SLOTLABELVALUE) != null) {
            throw new CryptoTokenInitializationFailureException("Can not specify both " + CryptoTokenHelper.PROPERTY_SLOT + " and  " + CryptoTokenHelper.PROPERTY_SLOTLABELVALUE);
        }

        String value = CompileTimeSettings.getInstance().getProperty("cryptotoken.p11.usep11ngasp11");
        boolean usep11ngasp11 = Boolean.parseBoolean(value);
        if (usep11ngasp11) {
            if (properties.containsKey("SLOT")) {
                properties.setProperty("SLOTLABELTYPE", "SLOT_NUMBER");
                properties.setProperty("SLOTLABELVALUE", properties.getProperty("SLOT"));
                properties.remove("SLOT");
            }
            if (properties.containsKey("SLOTLISTINDEX")) {
                properties.setProperty("SLOTLABELTYPE", "SLOT_INDEX");
                properties.setProperty("SLOTLABELVALUE", properties.getProperty("SLOTLISTINDEX"));
                properties.remove("SLOTLISTINDEX");
            }
        }
        delegate.init(workerId, properties, services);
    }

    @Override
    public void activate(String authenticationcode, IServices services) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException {
        delegate.activate(authenticationcode, services);
    }

    @Override
    public boolean deactivate(IServices services) throws CryptoTokenOfflineException {
        return delegate.deactivate(services);
    }

    @Override
    public KeyStore getKeyStore() throws UnsupportedOperationException, CryptoTokenOfflineException, KeyStoreException {
        return delegate.getKeyStore();
    }

    @Override
    public int getCryptoTokenStatus(IServices services) {
        return delegate.getCryptoTokenStatus(services);
    }

    @Override
    public void importCertificateChain(List<Certificate> certChain, String alias, char[] athenticationCode, Map<String, Object> params, IServices services) throws TokenOutOfSpaceException, CryptoTokenOfflineException, NoSuchAliasException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
        delegate.importCertificateChain(certChain, alias, athenticationCode, params, services);
    }

    @Override
    public TokenSearchResults searchTokenEntries(int startIndex, int max, QueryCriteria qc, boolean includeData, Map<String, Object> params, IServices services) throws CryptoTokenOfflineException, QueryException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
        return delegate.searchTokenEntries(startIndex, max, qc, includeData, params, services);
    }

    @Override
    public ICryptoInstance acquireCryptoInstance(String alias, Map<String, Object> params, RequestContext context) throws CryptoTokenOfflineException, NoSuchAliasException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter, IllegalRequestException, SignServerException {
        return delegate.acquireCryptoInstance(alias, params, context);
    }

    @Override
    public void releaseCryptoInstance(ICryptoInstance instance, RequestContext context) {
        delegate.releaseCryptoInstance(instance, context);
    }

    @Override
    public void generateKey(String keyAlgorithm, String keySpec, String alias, char[] authCode, Map<String, Object> params, IServices services) throws TokenOutOfSpaceException, CryptoTokenOfflineException, DuplicateAliasException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
        delegate.generateKey(keyAlgorithm, keySpec, alias, authCode, params, services);
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, String keyAlias, IServices services) throws CryptoTokenOfflineException, NoSuchAliasException {
        return delegate.genCertificateRequest(info, explicitEccParameters, keyAlias, services);
    }

    @Override
    public Collection<KeyTestResult> testKey(String alias, char[] authCode, IServices Services) throws CryptoTokenOfflineException, KeyStoreException {
        return delegate.testKey(alias, authCode, Services);
    }

    @Override
    public boolean removeKey(String alias, IServices services) throws CryptoTokenOfflineException, KeyStoreException, SignServerException {
        return delegate.removeKey(alias, services);
    }

    @Override
    public boolean isNoCertificatesRequired() {
        return delegate.isNoCertificatesRequired();
    }

}
