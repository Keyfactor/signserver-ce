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

import java.io.IOException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.NoSuchAliasException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.keys.token.AzureCryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.util.query.QueryCriteria;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.QueryException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.TokenOutOfSpaceException;
import org.signserver.common.WorkerStatus;
import org.signserver.server.ExceptionUtil;
import org.signserver.server.IServices;

/**
 * CryptoToken implementation wrapping the new AzureCryptoToken from CESeCore.
 * 
 * Note: The mapping between SignServer APIs and CESeCore is not perfect. In 
 * particular the SignServer calls for testing and generating key-pairs takes 
 * an authentication code while the CESeCore ones assumes the token is already 
 * activated. This means that the auth code parameter will be ignored for those
 * methods.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AzureKeyVaultCryptoToken extends BaseCryptoToken {

    private static final Logger LOG = Logger.getLogger(AzureKeyVaultCryptoToken.class);

    private AzureCryptoToken delegate;

    /** Our worker cache entry name. */
    private static final String WORKERCACHE_ENTRY = "PKCS11CryptoToken.CRYPTO_INSTANCE";
    
    private static final String PROPERTY_SIGNATUREALGORITHM = "SIGNATUREALGORITHM";

    private AttributeProperties attributeProperties;

    public AzureKeyVaultCryptoToken() {
    }

    private String keyAlias;
    private String nextKeyAlias;
    private String signatureAlgorithm;
    
    private Integer keygenerationLimit;

    private KeyStoreDelegator keystoreDelegator;

    private final String[] allowedKeyVaultTypes = {"standard", "premium"};

    @Override
    public void init(int workerId, Properties props, org.signserver.server.IServices services) throws CryptoTokenInitializationFailureException {
        try {
            // Check that the crypto token is not disabled
            CryptoTokenHelper.checkEnabled(props);
            
            // Optional property SIGNATUREALGORITHM
            final String value = props.getProperty(PROPERTY_SIGNATUREALGORITHM);
            if (!StringUtils.isBlank(value)) {
                signatureAlgorithm = value;
            }
            
            final String keyVaultName =
                    props.getProperty(CryptoTokenHelper.PROPERTY_KEY_VAULT_NAME);
            final String keyVaultClientId =
                    props.getProperty(CryptoTokenHelper.PROPERTY_KEY_VAULT_CLIENT_ID);
            final String keyVaultType =
                    props.getProperty(CryptoTokenHelper.PROPERTY_KEY_VAULT_TYPE);
            final List<String> missingRequiredProperties = new LinkedList<>();

            if (StringUtils.isBlank(keyVaultName)) {
                missingRequiredProperties.add(CryptoTokenHelper.PROPERTY_KEY_VAULT_NAME);
            }

            if (StringUtils.isBlank(keyVaultClientId)) {
                missingRequiredProperties.add(CryptoTokenHelper.PROPERTY_KEY_VAULT_CLIENT_ID);
            }

            if (StringUtils.isBlank(keyVaultType)) {
                missingRequiredProperties.add(CryptoTokenHelper.PROPERTY_KEY_VAULT_TYPE);
            }
            
            if (!missingRequiredProperties.isEmpty()) {
                final String message;

                if (missingRequiredProperties.size() == 1) {
                    message = "Missing value for " + missingRequiredProperties.get(0);
                } else {
                    message = "Missing values for " + missingRequiredProperties.toString();
                }

                throw new CryptoTokenInitializationFailureException(message);
            }

            if (!Arrays.asList(allowedKeyVaultTypes).contains(keyVaultType)) {
                throw new CryptoTokenInitializationFailureException("Unsupported KEY_VAULT_TYPE: " +
                        keyVaultType + ", allowed values: " + Arrays.asList(allowedKeyVaultTypes).toString());
            }
            
            props = CryptoTokenHelper.fixAzureKeyVaultProperties(props);

            keyAlias = props.getProperty("defaultKey");
            nextKeyAlias = props.getProperty("nextCertSignKey");

            if (LOG.isDebugEnabled()) { 
                final StringBuilder sb = new StringBuilder();
                sb.append("keyAlias: ").append(keyAlias).append("\n");
                sb.append("nextKeyAlias: ").append(nextKeyAlias).append("\n");
                LOG.debug(sb.toString());
            }

            // Read property KEYGENERATIONLIMIT
            final String keygenLimitValue = props.getProperty(CryptoTokenHelper.PROPERTY_KEYGENERATIONLIMIT);
            if (keygenLimitValue != null && !keygenLimitValue.trim().isEmpty()) {
                try {
                    keygenerationLimit = Integer.parseInt(keygenLimitValue.trim());
                } catch (NumberFormatException ex) {
                    throw new CryptoTokenInitializationFailureException("Incorrect value for " + CryptoTokenHelper.PROPERTY_KEYGENERATIONLIMIT + ": " + ex.getLocalizedMessage());
                }
            }

            delegate = new AzureCryptoToken();
            delegate.init(props, null, workerId);
            keystoreDelegator = new AzureKeyVaultKeyStoreDelegator(delegate);

        } catch (org.cesecore.keys.token.CryptoTokenOfflineException | NumberFormatException ex) {
            LOG.error("Init failed", ex);
            throw new CryptoTokenInitializationFailureException(ex.getMessage());
        } catch (NoSuchSlotException ex) {
            LOG.error("Slot not found", ex);
            throw new CryptoTokenInitializationFailureException(ex.getMessage());
        }
    }

    @Override
    public int getCryptoTokenStatus(IServices services) {
        int result = delegate.getTokenStatus();

        if (result == WorkerStatus.STATUS_ACTIVE) {
            result = WorkerStatus.STATUS_OFFLINE;
            try {
                if (LOG.isDebugEnabled()) { 
                    final StringBuilder sb = new StringBuilder();
                    sb.append("keyAlias: ").append(keyAlias).append("\n");
                    sb.append("nextKeyAlias: ").append(nextKeyAlias).append("\n");
                    LOG.debug(sb.toString());
                }
                for (String testKey : new String[]{keyAlias, nextKeyAlias}) {
                    if (testKey != null && !testKey.isEmpty()) {
                        PrivateKey privateKey = delegate.getPrivateKey(testKey);
                        if (privateKey != null) {
                            PublicKey publicKey = delegate.getPublicKey(testKey);
                            CryptoTokenHelper.testSignAndVerify(privateKey, publicKey, delegate.getSignProviderName(), signatureAlgorithm);
                            result = WorkerStatus.STATUS_ACTIVE;
                        }
                    }
                }
            } catch (org.cesecore.keys.token.CryptoTokenOfflineException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException | ProviderException | OperatorCreationException | IOException ex) {
                LOG.error("Error testing activation", ex);
            }
        }

        return result;
    }

    @Override
    public void activate(String authenticationcode, IServices services) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException {
        try {
            delegate.activate(authenticationcode.toCharArray());
            keystoreDelegator = new AzureKeyVaultKeyStoreDelegator(delegate);
        } catch (org.cesecore.keys.token.CryptoTokenOfflineException ex) {
            LOG.error("Activate failed", ex);
            throw new CryptoTokenOfflineException(ex);
        } catch (CryptoTokenAuthenticationFailedException ex) {
            
            final StringBuilder sb = new StringBuilder();
            sb.append("Activate failed");
            for (final String causeMessage : ExceptionUtil.getCauseMessages(ex)) {
                sb.append(": ");
                sb.append(causeMessage);
            }
            LOG.error(sb.toString());
            throw new CryptoTokenAuthenticationFailureException(sb.toString());
        }
    }

    @Override
    public boolean deactivate(IServices services) throws CryptoTokenOfflineException {
        delegate.deactivate();
        keystoreDelegator = null;
        return true;
    }

    private PrivateKey getPrivateKey(String alias) throws CryptoTokenOfflineException {
        try {
            return delegate.getPrivateKey(alias);
        } catch (org.cesecore.keys.token.CryptoTokenOfflineException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
    }

    private String getProvider(int providerUsage) {
        return delegate.getSignProviderName();
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            final boolean explicitEccParameters, String alias, IServices services)
            throws CryptoTokenOfflineException {
        if (LOG.isDebugEnabled()) {
            LOG.debug(">genCertificateRequest CESeCorePKCS11CryptoToken");
            LOG.debug("alias: " + alias);
        }
        try {
            return CryptoTokenHelper.genCertificateRequest(info, delegate.getPrivateKey(alias), getProvider(ICryptoTokenV4.PROVIDERUSAGE_SIGN), delegate.getPublicKey(alias), explicitEccParameters);
        } catch (org.cesecore.keys.token.CryptoTokenOfflineException e) {
            LOG.error("Certificate request error: " + e.getMessage(), e);
            throw new CryptoTokenOfflineException(e);
        } catch (IllegalArgumentException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.error("Certificate request error", ex);
            }
            throw new CryptoTokenOfflineException(ex.getMessage(), ex);
        }
    }

    @Override
    public boolean removeKey(String alias, IServices services) throws CryptoTokenOfflineException, KeyStoreException, SignServerException {
        return CryptoTokenHelper.removeKey(keystoreDelegator, alias);
    }

    @Override
    public Collection<KeyTestResult> testKey(String alias, char[] authCode, IServices services) throws CryptoTokenOfflineException, KeyStoreException {
        return CryptoTokenHelper.testKey(keystoreDelegator, alias, authCode, delegate.getSignProviderName(), signatureAlgorithm);
    }

    @Override
    public KeyStore getKeyStore() throws UnsupportedOperationException, CryptoTokenOfflineException, KeyStoreException {
        throw new UnsupportedOperationException("KeyStore not supported");
    }

    private void generateKeyPair(String keyAlgorithm, String keySpec, String alias, char[] authCode, Map<String, Object> params, IServices services) throws CryptoTokenOfflineException, IllegalArgumentException {
        // Keyspec for DSA is prefixed with "dsa"
        if (keyAlgorithm != null && keyAlgorithm.equalsIgnoreCase("DSA")
                && !keySpec.contains("dsa")) {
            keySpec = "dsa" + keySpec;
        }
   
        try {
            delegate.generateKeyPair(keySpec, alias);
        } catch (InvalidAlgorithmParameterException | org.cesecore.keys.token.CryptoTokenOfflineException  ex) {
            LOG.error(ex, ex);
            throw new CryptoTokenOfflineException(ex);
        }
    }
    
    @Override
    public void generateKey(String keyAlgorithm, String keySpec, String alias, char[] authCode, Map<String, Object> params, IServices services) throws CryptoTokenOfflineException, IllegalArgumentException {
        if (!"RSA".equalsIgnoreCase(keyAlgorithm) &&
            !"ECDSA".equalsIgnoreCase(keyAlgorithm)) {
            throw new IllegalArgumentException("Only RSA and ECDSA is supported by AzureKeyVaultCryptoToken");
        }
        if (keySpec == null) {
            throw new IllegalArgumentException("Missing keyspec parameter");
        }
        if (alias == null) {
            throw new IllegalArgumentException("Missing alias parameter");
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("keyAlgorithm: " + keyAlgorithm + ", keySpec: " + keySpec
                    + ", alias: " + alias);
        }

        // Check key generation limit, if configured
        if (keygenerationLimit != null && keygenerationLimit > -1) {
            final int current;
            try {
                current = delegate.getAliases().size();
                if (current >= keygenerationLimit) {
                    throw new TokenOutOfSpaceException("Key generation limit exceeded: " + current);
                }
            } catch (org.cesecore.keys.token.CryptoTokenOfflineException ex) {
                LOG.error("Checking key generation limit failed", ex);
                throw new TokenOutOfSpaceException("Current number of key entries could not be obtained: " + ex.getMessage(), ex);
            }
        }

        try {
            generateKeyPair(keyAlgorithm, keySpec, alias, authCode, params, services);
        } catch (UnsupportedOperationException ex) {
            LOG.error(ex, ex);
            throw new CryptoTokenOfflineException(ex);
        } catch (CryptoTokenOfflineException ex) {
            final String exMessage = ex.getMessage();
            final String responseHeader = "JSON response: ";
            
            if (exMessage != null && exMessage.contains(responseHeader)) {
                final String jsonText =
                        exMessage.substring(exMessage.indexOf(responseHeader) +
                                                              responseHeader.length());
                final JSONParser parser = new JSONParser();

                try {
                    final JSONObject response =
                            (JSONObject) parser.parse(jsonText);
                    final JSONObject error = (JSONObject) response.get("error");

                    if (error != null) {
                        final String code = (String) error.get("code");
                        final String message = (String) error.get("message");

                        if ("BadParameter".equals(code)) {
                            throw new IllegalArgumentException(message);
                        } else {
                            throw ex;
                        }
                    } else {
                        throw ex;
                    }
                } catch (ParseException pex) {
                    LOG.error("Failed to parse JSON response: " + pex.getMessage());
                    throw ex;
                }
            } else {
                throw ex;
            }
        }
    }

    @Override
    public void importCertificateChain(final List<Certificate> certChain,
                                       final String alias,
                                       final char[] athenticationCode,
                                       final Map<String, Object> params,
                                       final IServices services)
            throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Import not supported by crypto token");
    }

    @Override
    public TokenSearchResults searchTokenEntries(final int startIndex, final int max, final QueryCriteria qc, final boolean includeData, Map<String, Object> params, final IServices services) throws CryptoTokenOfflineException, QueryException {
        if (keystoreDelegator == null) {
            throw new CryptoTokenOfflineException("Crypto token not activated");
        }
        return CryptoTokenHelper.searchTokenEntries(keystoreDelegator, startIndex, max, qc, includeData, services, null);
    }

    @Override
    public ICryptoInstance acquireCryptoInstance(String alias, Map<String, Object> params, RequestContext context) throws
            CryptoTokenOfflineException, 
            NoSuchAliasException, 
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            IllegalRequestException {
        ICryptoInstance result = null;
        
        // Check if the caller requested caching of the private key
        final Boolean cache = (Boolean) params.get(PARAM_CACHEPRIVATEKEY);
        if (cache != null && cache) {
            // Get the supplied worker-instance-specific cache
            final Map<String, Object> workerCache = (Map<String, Object>) params.get(PARAM_WORKERCACHE);
            if (workerCache != null) {
                
                // Check if we have a cached crypto instance, otherwise create one
                // Note: The cache is shared between all threads serving this worker so we only allow one to query and update the cache at a time.
                synchronized (workerCache) {
                    result = (ICryptoInstance) workerCache.get(WORKERCACHE_ENTRY);
                    if (result == null) {
                        result = createCryptoInstance(alias, context);
                        workerCache.put(WORKERCACHE_ENTRY, result);
                    }
                }
            }
        }
        
        // In case of no caching just load the crypt instance
        if (result == null) {
            result = createCryptoInstance(alias, context);
        }
        
        return result;
    }
    
    /**
     * Queries the keystore for the private key and certificate, creating
     * the crypto instance.
     * Possibly expensive call if a network HSM is used.
     */
    private ICryptoInstance createCryptoInstance(String alias, RequestContext context) throws
            CryptoTokenOfflineException, 
            NoSuchAliasException, 
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            IllegalRequestException {
        try {
            final PrivateKey privateKey = getPrivateKey(alias);
            return new DefaultCryptoInstance(alias, context, Security.getProvider(delegate.getSignProviderName()), privateKey, delegate.getPublicKey(alias));
        } catch (org.cesecore.keys.token.CryptoTokenOfflineException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
    }

    @Override
    public void releaseCryptoInstance(ICryptoInstance instance, RequestContext context) {
        // NOP
    }
}
