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

import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.NoSuchAliasException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.PKCS11Settings;
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
import static org.signserver.server.cryptotokens.CryptoTokenHelper.SECRET_KEY_PREFIX;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;

/**
 * CryptoToken implementation wrapping the new PKCS11CryptoToken from CESeCore.
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
public class PKCS11CryptoToken extends BaseCryptoToken {

    private static final Logger LOG = Logger.getLogger(PKCS11CryptoToken.class);

    private KeyStorePKCS11CryptoToken delegate;

    /** Our worker cache entry name. */
    private static final String WORKERCACHE_ENTRY = "PKCS11CryptoToken.CRYPTO_INSTANCE";
    
    private static final String PROPERTY_SIGNATUREALGORITHM = "SIGNATUREALGORITHM";

    private AttributeProperties attributeProperties;

    public PKCS11CryptoToken() {
    }

    private String keyAlias;
    private String nextKeyAlias;
    private String signatureAlgorithm;

    // cached P11 library definitions (defined at deploy-time)
    private PKCS11Settings settings;
    
    private Integer keygenerationLimit;
    
    private KeyStoreDelegator keystoreDelegator;

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
            
            final String attributesValue = props.getProperty(CryptoTokenHelper.PROPERTY_ATTRIBUTES);
            if (attributesValue != null && props.getProperty(CryptoTokenHelper.PROPERTY_ATTRIBUTESFILE) != null) {
                throw new CryptoTokenInitializationFailureException(
                        "Only specify one of " + CryptoTokenHelper.PROPERTY_ATTRIBUTES
                                + " and " + CryptoTokenHelper.PROPERTY_ATTRIBUTESFILE);
            }

            if (attributesValue != null) {
                OutputStream out = null;
                try {
                    File attributesFile = File.createTempFile("attributes-" + workerId + "-", ".tmp");
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Created attributes file: " + attributesFile.getAbsolutePath());
                    }
                    attributesFile.deleteOnExit();
                    out = new FileOutputStream(attributesFile);
                    IOUtils.write(attributesValue, out);
                    props.setProperty(CryptoTokenHelper.PROPERTY_ATTRIBUTESFILE, attributesFile.getAbsolutePath());
                } catch (IOException ex) {
                    throw new CryptoTokenInitializationFailureException("Unable to create attributes file", ex);
                } finally {
                    IOUtils.closeQuietly(out);
                }
            }

            // Parse newer attribute properties
            try {
                attributeProperties = AttributeProperties.fromWorkerProperties(props);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Attribute properties:\n" + attributeProperties);
                }
            } catch (IllegalArgumentException ex) {
                throw new CryptoTokenInitializationFailureException("Unable to parse attributes: " + ex.getMessage());
            }

            // Check that both the new or the legacy properties are specified at the same time
            if (props.getProperty(CryptoTokenHelper.PROPERTY_SLOT) != null && props.getProperty(CryptoTokenHelper.PROPERTY_SLOTLABELVALUE) != null) {
                throw new CryptoTokenInitializationFailureException("Can not specify both " + CryptoTokenHelper.PROPERTY_SLOT + " and  " + CryptoTokenHelper.PROPERTY_SLOTLABELVALUE);
            }
            if (props.getProperty(CryptoTokenHelper.PROPERTY_SLOTLISTINDEX) != null && props.getProperty(CryptoTokenHelper.PROPERTY_SLOTLABELVALUE) != null) {
                throw new CryptoTokenInitializationFailureException("Can not specify both " + CryptoTokenHelper.PROPERTY_SLOTLISTINDEX + " and  " + CryptoTokenHelper.PROPERTY_SLOTLABELVALUE);
            }

            props = CryptoTokenHelper.fixP11Properties(props);
            
            final String sharedLibraryName = props.getProperty("sharedLibraryName");
            final String sharedLibraryProperty = props.getProperty("sharedLibrary");
            
            settings = PKCS11Settings.getInstance();

            // at least one the SHAREDLIBRARYNAME or SHAREDLIBRAY
            // (for backwards compatability) properties must be defined
            if (sharedLibraryName == null && sharedLibraryProperty == null) {
                final StringBuilder sb = new StringBuilder();
                
                sb.append("Missing SHAREDLIBRARYNAME property\n");
                settings.listAvailableLibraryNames(sb);
                
                throw new CryptoTokenInitializationFailureException(sb.toString());
            }

            // if only the old SHAREDLIBRARY property is given, it must point
            // to one of the libraries defined at deploy-time
            if (sharedLibraryProperty != null && sharedLibraryName == null) {
                // check if the library was defined at deploy-time
                if (!settings.isP11LibraryExisting(sharedLibraryProperty)) {
                    throw new CryptoTokenInitializationFailureException("SHAREDLIBRARY is not permitted when pointing to a library not defined at deploy-time");
                }
            }
            
            // lookup the library defined by SHAREDLIBRARYNAME among the
            // deploy-time-defined values
            final String sharedLibraryFile =
                    sharedLibraryName == null ?
                    null :
                    settings.getP11SharedLibraryFileForName(sharedLibraryName);
            
            // both the old and new properties are allowed at the same time
            // to ease migration, given that they point to the same library
            if (sharedLibraryProperty != null && sharedLibraryName != null) {
                if (sharedLibraryFile != null) {
                    final File byPath = new File(sharedLibraryProperty);
                    final File byName = new File(sharedLibraryFile);

                    try {
                        if (!byPath.getCanonicalPath().equals(byName.getCanonicalPath())) {
                            // the properties pointed to different libraries
                            throw new CryptoTokenInitializationFailureException("Can not specify both SHAREDLIBRARY and SHAREDLIBRARYNAME at the same time");
                        }
                    } catch (IOException e) {
                        // failed to determine canonical paths, treat this as conflicting properties
                        throw new CryptoTokenInitializationFailureException("Can not specify both SHAREDLIBRARY and SHAREDLIBRARYNAME at the same time");
                    }
                } else {
                    // could not associate SHAREDLIBRARYNAME with a path, treat this as conflicting properties
                    throw new CryptoTokenInitializationFailureException("Can not specify both SHAREDLIBRARY and SHAREDLIBRARYNAME at the same time");
                }
            }
            
            // if only SHAREDLIBRARYNAME was given and the value couldn't be
            // found, include a list of available values in the token error
            // message
            if (sharedLibraryFile == null && sharedLibraryProperty == null) {
                final StringBuilder sb = new StringBuilder();
                
                sb.append("SHAREDLIBRARYNAME ");
                sb.append(sharedLibraryName);
                sb.append(" is not referring to a defined value");
                sb.append("\n");
                settings.listAvailableLibraryNames(sb);

                throw new CryptoTokenInitializationFailureException(sb.toString());
            }
            
            // check the file (again) and pass it on to the underlaying implementation
            if (sharedLibraryFile != null) {
                final File sharedLibrary = new File(sharedLibraryFile);
                if (!sharedLibrary.isFile() || !sharedLibrary.canRead()) {
                    throw new CryptoTokenInitializationFailureException("The shared library file can't be read: " + sharedLibrary.getAbsolutePath());
                }

                // propagate the shared library property to the delegate
                props.setProperty("sharedLibrary", sharedLibraryFile);
            }

            final String slotLabelType = props.getProperty(CryptoTokenHelper.PROPERTY_SLOTLABELTYPE);
            if (slotLabelType == null) {
                throw new CryptoTokenInitializationFailureException("Missing " + CryptoTokenHelper.PROPERTY_SLOTLABELTYPE + " property");
            }
            final Pkcs11SlotLabelType slotLabelTypeValue =
                    Pkcs11SlotLabelType.getFromKey(slotLabelType);
            if (slotLabelTypeValue == null) {
                throw new CryptoTokenInitializationFailureException("Illegal " +
                        CryptoTokenHelper.PROPERTY_SLOTLABELTYPE + " property: " +
                        slotLabelType);
            }
            final String slotLabelValue = props.getProperty(CryptoTokenHelper.PROPERTY_SLOTLABELVALUE);
            if (slotLabelValue == null) {
                throw new CryptoTokenInitializationFailureException("Missing " + CryptoTokenHelper.PROPERTY_SLOTLABELVALUE + " property");
            }

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

            delegate = new KeyStorePKCS11CryptoToken();
            delegate.init(props, null, workerId);
            try {
                keystoreDelegator = new JavaKeyStoreDelegator(delegate.getActivatedKeyStore());
            } catch (CryptoTokenOfflineException ex) {
                // don't initialize keystore delegator when not auto-activated
            }
                
        } catch (org.cesecore.keys.token.CryptoTokenOfflineException | NumberFormatException ex) {
            LOG.error("Init failed", ex);
            throw new CryptoTokenInitializationFailureException(ex.getMessage());
        } catch (NoSuchSlotException ex) {
            LOG.error("Slot not found", ex);
            throw new CryptoTokenInitializationFailureException(ex.getMessage());
        } catch (InstantiationException ex) {
            LOG.error("PKCS11 key store initialization failed", ex);
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
            keystoreDelegator = new JavaKeyStoreDelegator(delegate.getActivatedKeyStore());
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
        // unset delegator is CESeCore token is not auto-activated
        if (!delegate.isActive()) {
            keystoreDelegator = null;
        }
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

    private List<Certificate> getCertificateChain(String alias) throws CryptoTokenOfflineException {
        try {
            final List<Certificate> result;
            final Certificate[] certChain = delegate.getActivatedKeyStore().getCertificateChain(alias);
            if (certChain == null) {
                result = null;
            } else {
                result = Arrays.asList(certChain);
            }
            return result;
        } catch (KeyStoreException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
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
        final KeyStore keyStore = delegate.getActivatedKeyStore();
        return CryptoTokenHelper.testKey(keystoreDelegator, alias, authCode, keyStore.getProvider().getName(), signatureAlgorithm);
    }

    @Override
    public KeyStore getKeyStore() throws UnsupportedOperationException, CryptoTokenOfflineException, KeyStoreException {
        return delegate.getActivatedKeyStore();
    }

    private void generateKeyPair(String keyAlgorithm, String keySpec, String alias, char[] authCode, Map<String, Object> params, IServices services) throws CryptoTokenOfflineException, IllegalArgumentException {
        // Keyspec for DSA is prefixed with "dsa"
        if (keyAlgorithm != null && keyAlgorithm.equalsIgnoreCase("DSA")
                && !keySpec.contains("dsa")) {
            keySpec = "dsa" + keySpec;
        }
                
        try {
            // Construct the apropriate AlgorithmParameterSpec
            final AlgorithmParameterSpec spec;
            if ("RSA".equalsIgnoreCase(keyAlgorithm)) {
                if (keySpec.contains("exp")) {
                    spec = CryptoTokenHelper.getPublicExponentParamSpecForRSA(keySpec);
                } else {
                    spec = new RSAKeyGenParameterSpec(Integer.valueOf(keySpec), RSAKeyGenParameterSpec.F4);
                }
            } else if ("DSA".equalsIgnoreCase(keyAlgorithm)) {
                spec = null; // We don't currently support setting attributes for DSA keys. This could be added in future if needed but requires changes in underlaying APIs
            } else if ("ECDSA".equalsIgnoreCase(keyAlgorithm)) {
                // Convert it to the OID if possible since the human friendly name might differ in the provider
                if (ECUtil.getNamedCurveOid(keySpec) != null) {
                    final String oidOrName = AlgorithmTools.getEcKeySpecOidFromBcName(keySpec);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("keySpecification '" + keySpec + "' transformed into OID " + oidOrName);
                    }
                    spec = new ECGenParameterSpec(oidOrName);
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Curve did not have an OID in BC, trying to pick up Parameter spec: " + keySpec);
                    }
                    // This may be a new curve without OID, like curve25519 and we have to do something a bit different
                    X9ECParameters ecP = CustomNamedCurves.getByName(keySpec);
                    if (ecP == null) {
                        throw new InvalidAlgorithmParameterException("Can not generate EC curve, no OID and no ECParameters found: " + keySpec);
                    }
                    spec = new org.bouncycastle.jce.spec.ECParameterSpec(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed()); 
                }
            } else {
                throw new IllegalArgumentException("Unsupported key algorithm: " + keyAlgorithm);
            }
            
            if (spec == null) {
                // Generate the old way without support for attributes
                delegate.generateKeyPair(keySpec, alias);
            } else {
                if (CryptoTokenHelper.isJREPatched()) {
                    final CK_ATTRIBUTE[] publicTemplate = convert(attributeProperties.getPublicTemplate(keyAlgorithm));
                    final CK_ATTRIBUTE[] privateTemplate = convert(attributeProperties.getPrivateTemplate(keyAlgorithm));

                    // TODO: Later on we could override attribute properties from the params parameter

                    // Use different P11AsymmetricParameterSpec classes as the underlaying library assumes the spec contains the string "RSA" or "EC"
                    final AlgorithmParameterSpec specWithAttributes;
                    if ("RSA".equalsIgnoreCase(keyAlgorithm)) {
                        specWithAttributes = new RSAP11AsymmetricParameterSpec(publicTemplate, privateTemplate, spec);
                    } else if ("ECDSA".equalsIgnoreCase(keyAlgorithm)) {
                        specWithAttributes = new ECP11AsymmetricParameterSpec(publicTemplate, privateTemplate, spec);
                    } else {
                        throw new IllegalArgumentException("Unsupported key algorithm: " + keyAlgorithm);
                    }
                    
                    delegate.generateKeyPair(specWithAttributes, alias);
                } else {
                    // Generate without support for attributes
                    delegate.generateKeyPair(spec, alias);
                }
            }

            if (params != null) {
                final KeyStore ks = delegate.getActivatedKeyStore();
                CryptoTokenHelper.regenerateCertIfWanted(alias, authCode, params, keystoreDelegator, ks.getProvider().getName());
            }
        } catch (InvalidAlgorithmParameterException | org.cesecore.keys.token.CryptoTokenOfflineException | CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | OperatorCreationException ex) {
            LOG.error(ex, ex);
            throw new CryptoTokenOfflineException(ex);
        }
    }
    
    @Override
    public void generateKey(String keyAlgorithm, String keySpec, String alias, char[] authCode, Map<String, Object> params, IServices services) throws CryptoTokenOfflineException, IllegalArgumentException {
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
                current = delegate.getActivatedKeyStore().size();
                if (current >= keygenerationLimit) {
                    throw new TokenOutOfSpaceException("Key generation limit exceeded: " + current);
                }
            } catch (KeyStoreException ex) {
                LOG.error("Checking key generation limit failed", ex);
                throw new TokenOutOfSpaceException("Current number of key entries could not be obtained: " + ex.getMessage(), ex);
            }
        }

        try {
            if (CryptoTokenHelper.isKeyAlgorithmAsymmetric(keyAlgorithm)) {
                generateKeyPair(keyAlgorithm, keySpec, alias, authCode, params, services);
            } else {
                generateSecretKey(keyAlgorithm, keySpec, alias);
            }
        } catch (UnsupportedOperationException ex) {
            LOG.error(ex, ex);
            throw new CryptoTokenOfflineException(ex);
        }
    }
    
    private void generateSecretKey(String keyAlgorithm, String keySpec, String alias) throws CryptoTokenOfflineException {
        if (keyAlgorithm.startsWith(SECRET_KEY_PREFIX)) {
            keyAlgorithm = keyAlgorithm.substring(keyAlgorithm.indexOf(SECRET_KEY_PREFIX) + SECRET_KEY_PREFIX.length());
        }
        try {
            delegate.generateKey(keyAlgorithm, Integer.valueOf(keySpec), alias);
        } catch (IllegalArgumentException | NoSuchAlgorithmException | NoSuchProviderException | KeyStoreException | org.cesecore.keys.token.CryptoTokenOfflineException ex) {
            LOG.error(ex, ex);
            throw new CryptoTokenOfflineException(ex);
        }
    }

    @Override
    public void importCertificateChain(final List<Certificate> certChain,
                                       final String alias,
                                       final char[] athenticationCode,
                                       final Map<String, Object> params,
                                       final IServices services)
            throws CryptoTokenOfflineException {
        try {
            final KeyStore keyStore = delegate.getActivatedKeyStore();
            final Key key = keyStore.getKey(alias, athenticationCode);
            
            CryptoTokenHelper.ensureNewPublicKeyMatchesOld(keystoreDelegator,
                                                           alias, certChain.get(0));

            keyStore.setKeyEntry(alias, key, athenticationCode,
                                 certChain.toArray(new Certificate[0]));
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
            LOG.error(ex, ex);
            throw new CryptoTokenOfflineException(ex);
        }
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
                        result = createCryptoInstance(alias, context, params.containsKey(PARAM_INCLUDE_DUMMYCERTIFICATE));
                        workerCache.put(WORKERCACHE_ENTRY, result);
                    }
                }
            }
        }
        
        // In case of no caching just load the crypt instance
        if (result == null) {
            result = createCryptoInstance(alias, context, params.containsKey(PARAM_INCLUDE_DUMMYCERTIFICATE));
        }
        
        return result;
    }
    
    /**
     * Queries the keystore for the private key and certificate, creating
     * the crypto instance.
     * Possibly expensive call if a network HSM is used.
     */
    private ICryptoInstance createCryptoInstance(String alias, RequestContext context, boolean includeDummyCertificate) throws
            CryptoTokenOfflineException, 
            NoSuchAliasException, 
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            IllegalRequestException {
        final PrivateKey privateKey = getPrivateKey(alias);
        final List<Certificate> certificateChain = getCertificateChain(alias);
        if ((certificateChain.size() == 1 && CryptoTokenHelper.isDummyCertificate(certificateChain.get(0)) && !includeDummyCertificate)) {
            return new DefaultCryptoInstance(alias, context, delegate.getActivatedKeyStore().getProvider(), privateKey, certificateChain.get(0).getPublicKey());
        } else {
            return new DefaultCryptoInstance(alias, context, delegate.getActivatedKeyStore().getProvider(), privateKey, certificateChain);
        }
    }

    @Override
    public void releaseCryptoInstance(ICryptoInstance instance, RequestContext context) {
        // NOP
    }

    private CK_ATTRIBUTE[] convert(List<AttributeProperties.Attribute> attributes) {
        if (attributes == null) {
            return new CK_ATTRIBUTE[0];
        }
        final List<CK_ATTRIBUTE> result = new ArrayList<>(attributes.size());
        for (AttributeProperties.Attribute attribute : attributes) {
            result.add(new CK_ATTRIBUTE(attribute.getId(), attribute.getValue()));
        }
        return result.toArray(new CK_ATTRIBUTE[0]);
    }

    private static class KeyStorePKCS11CryptoToken extends org.cesecore.keys.token.PKCS11CryptoToken {

        public KeyStorePKCS11CryptoToken() throws InstantiationException {
            super();
        }

        public KeyStore getActivatedKeyStore() throws CryptoTokenOfflineException {
            try {
                return getKeyStore().getKeyStore(); // TODO: Consider if we should instead use the CachingKeystoreWrapper
            } catch (org.cesecore.keys.token.CryptoTokenOfflineException ex) {
                throw new CryptoTokenOfflineException(ex);
            }
        }
    }

}
