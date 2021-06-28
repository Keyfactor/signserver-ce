/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.p11ng.common.cryptotoken;

import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.NoSuchAliasException;
import org.signserver.common.PKCS11Settings;
import org.signserver.common.QueryException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.TokenOutOfSpaceException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerStatus;
import org.signserver.p11ng.common.provider.CryptokiDevice;
import org.signserver.p11ng.common.provider.CryptokiDevice.Slot;
import org.signserver.p11ng.common.provider.CryptokiManager;
import org.signserver.p11ng.common.provider.SlotEntry;
import org.signserver.server.IServices;
import org.signserver.server.cryptotokens.AttributeProperties;
import org.signserver.server.cryptotokens.BaseCryptoToken;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.SECRET_KEY_PREFIX;
import org.signserver.server.cryptotokens.DefaultCryptoInstance;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.TokenSearchResults;

/**
 * CryptoToken uses JackNJI11.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class JackNJI11CryptoToken extends BaseCryptoToken {
    
    private static final Logger LOG = Logger.getLogger(JackNJI11CryptoToken.class);
    
    public static final String PROPERTY_WRAPPED_TESTKEY = "WRAPPED_TESTKEY";
    public static final String PROPERTY_PUBLICKEY_FROM_TOKEN = "PUBLICKEY_FROM_TOKEN";
    public static final String PROPERTY_CERTIFICATE_FROM_TOKEN = "CERTIFICATE_FROM_TOKEN";
    private static final String PROPERTY_SIGNATUREALGORITHM = "SIGNATUREALGORITHM";
    
    protected CryptokiDevice.Slot slot;

    private String keyAlias;
    private String nextKeyAlias;
    private String signatureAlgorithm;

    private Integer keygenerationLimit;

    protected AttributeProperties attributeProperties;
    private PKCS11Settings settings;

    private final String sharedLibraryFromFile;
    private JackNJI11KeyStoreDelegator keystoreDelegator;    
    
    /**
     * Default constructor normally used to create instances of this class.
     */
    public JackNJI11CryptoToken() {
        this.sharedLibraryFromFile = null;
    }
    
    /**
     * Special purpose constructor used to create an instance of this class using the provided shared library instead of by sharedLibraryName.
     * @param sharedLibrary path to library file
     */
    protected JackNJI11CryptoToken(String sharedLibrary) {
        this.sharedLibraryFromFile = sharedLibrary;
    }

    @Override
    public void init(int workerId, Properties props, IServices services) throws CryptoTokenInitializationFailureException {

        // Optional property SIGNATUREALGORITHM
        final String value = props.getProperty(PROPERTY_SIGNATUREALGORITHM);
        if (!StringUtils.isBlank(value)) {
            signatureAlgorithm = value;
        }    

        /* make sure none of the old SLOT or SLOTLISTINDEX properties are set
         * since these are handled parsed by fixP11Properties() and we want
         * to avoid that
         */
        if (props.getProperty(CryptoTokenHelper.PROPERTY_SLOT) != null ||
            props.getProperty(CryptoTokenHelper.PROPERTY_SLOTLISTINDEX) != null) {
            throw new CryptoTokenInitializationFailureException("Setting legacy properties SLOT or SLOTLISTINDEX is not allowed");
        }
        
        props = CryptoTokenHelper.fixP11Properties(props);

        settings = PKCS11Settings.getInstance();

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
        } else if (slotLabelTypeValue != Pkcs11SlotLabelType.SLOT_NUMBER &&
                   slotLabelTypeValue != Pkcs11SlotLabelType.SLOT_INDEX) {
            // check this early to avoid initing the device prematurely
            throw new CryptoTokenInitializationFailureException("Only SLOT_NUMBER and SLOT_INDEX supported for " +
                        CryptoTokenHelper.PROPERTY_SLOTLABELTYPE);
        }

        final String slotLabelValue =
                props.getProperty(CryptoTokenHelper.PROPERTY_SLOTLABELVALUE);
        if (slotLabelValue == null) {
            throw new CryptoTokenInitializationFailureException("Missing " + CryptoTokenHelper.PROPERTY_SLOTLABELVALUE + " property");
        }
        
        final String sharedLibraryName = props.getProperty("sharedLibraryName");
        if (sharedLibraryFromFile == null && sharedLibraryName == null) {
            final StringBuilder sb = new StringBuilder();
                
            sb.append("Missing SHAREDLIBRARYNAME property\n");
            settings.listAvailableLibraryNames(sb);

            throw new CryptoTokenInitializationFailureException(sb.toString());
        }

        keyAlias = props.getProperty("defaultKey");
        nextKeyAlias = props.getProperty("nextCertSignKey");

        // Check that the crypto token is not disabled
        CryptoTokenHelper.checkEnabled(props);

        final String sharedLibraryFile;
        if (sharedLibraryFromFile == null) {
            // lookup the library defined by SHAREDLIBRARYNAME among the
            // deploy-time-defined values
            sharedLibraryFile = settings.getP11SharedLibraryFileForName(sharedLibraryName);
        
            if (sharedLibraryFile == null) {
                final StringBuilder sb = new StringBuilder();

                sb.append("SHAREDLIBRARYNAME ");
                sb.append(sharedLibraryName);
                sb.append(" is not referring to a defined value");
                sb.append("\n");
                settings.listAvailableLibraryNames(sb);

                throw new CryptoTokenInitializationFailureException(sb.toString());
            }
        } else {
            // Instead use the provided shared library file
            sharedLibraryFile = sharedLibraryFromFile;            
            if (!new File(sharedLibraryFile).isFile()) {
                throw new CryptoTokenInitializationFailureException("Specified shared library file not available: " + sharedLibraryFile);
            }
        }

        final File libraryFile = new File(sharedLibraryFile);
        final String libDir = libraryFile.getParent();
        
        CryptokiDevice device = CryptokiManager.getInstance().getDevice(libraryFile.getName(), libDir);

        if (slotLabelTypeValue == Pkcs11SlotLabelType.SLOT_NUMBER) {
            this.slot = device.getSlot(Long.valueOf(slotLabelValue));
        } else {
            this.slot = device.getSlotByIndex(Integer.valueOf(slotLabelValue));
        }

        if (slot == null) {
            throw new CryptoTokenInitializationFailureException("Unable to obtain token in slot");
        }

        String authCode = props.getProperty("pin");
        if (authCode != null) {
            try {
                slot.login(authCode);
            } catch (Exception e) {
                LOG.error("Error auto activating PKCS11CryptoToken : " + e.getMessage(), e);
            }
        }

        keystoreDelegator = new JackNJI11KeyStoreDelegator(slot);
        
        boolean useCache = Boolean.parseBoolean(props.getProperty(CryptoTokenHelper.PROPERTY_USE_CACHE, CryptoTokenHelper.DEFAULT_PROPERTY_USE_CACHE));
        slot.setUseCache(useCache);

        if (LOG.isDebugEnabled()) { 
            final StringBuilder sb = new StringBuilder();
            sb.append("keyAlias: ").append(keyAlias).append("\n");
            sb.append("nextKeyAlias: ").append(nextKeyAlias);
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

        // Parse attribute properties
        try {
            attributeProperties = AttributeProperties.fromWorkerProperties(props);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Attribute properties:\n" + attributeProperties);
            }
        } catch (IllegalArgumentException ex) {
            throw new CryptoTokenInitializationFailureException("Unable to parse attributes: " + ex.getMessage());
        }
    }

    @Override
    public int getCryptoTokenStatus(final IServices services) {
        int result = WorkerStatus.STATUS_OFFLINE;

        try {
            if (LOG.isDebugEnabled()) { 
                final StringBuilder sb = new StringBuilder();
                sb.append("keyAlias: ").append(keyAlias).append("\n");
                sb.append("nextKeyAlias: ").append(nextKeyAlias).append("\n");
                LOG.debug(sb.toString());
            }
            for (String testKey : new String[]{keyAlias, nextKeyAlias}) {
                if (testKey != null && !testKey.isEmpty()) {
                    PrivateKey privateKey = null;
                    try {
                        privateKey = slot.aquirePrivateKey(testKey);
                        if (privateKey != null) {
                            PublicKey publicKey = slot.getPublicKey(testKey);
                            if (publicKey == null) {
                                publicKey = slot.getCertificate(testKey).getPublicKey();
                            }
                            CryptoTokenHelper.testSignAndVerify(privateKey, publicKey, slot.getProvider().getName(), signatureAlgorithm);
                            result = WorkerStatus.STATUS_ACTIVE;
                        }
                    } finally {
                        if (privateKey != null) {
                            slot.releasePrivateKey(privateKey);
                        }
                    }
                }
            }
        } catch (Throwable th) {
            LOG.error("Error getting token status", th);
            result = WorkerStatus.STATUS_OFFLINE;
        }
        return result;
    }

    @Override
    public void activate(String authenticationcode, IServices services) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException {
        slot.login(authenticationcode);
    }

    @Override
    public boolean deactivate(IServices services) throws CryptoTokenOfflineException {
        slot.logout();
        return true;
    }

    @Override
    public ICryptoInstance acquireCryptoInstance(String alias, Map<String, Object> params, RequestContext context) throws CryptoTokenOfflineException, 
            NoSuchAliasException, 
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            IllegalRequestException {
        return acquireInternal(alias, params, context);
    }
    
    protected ICryptoInstance acquireInternal(String alias, Map<String, Object> params, RequestContext context) throws
            CryptoTokenOfflineException, 
            NoSuchAliasException, 
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            IllegalRequestException {
        final PrivateKey privateKey = slot.aquirePrivateKey(alias);
        if (privateKey == null) {
            LOG.error("No key found for alias: " + alias);
            throw new NoSuchAliasException("No private key with alias: " + alias);
        }

        final List<Certificate> certificateChain = slot.getCertificateChain(alias);
        if (certificateChain == null) {
            LOG.error("No certificate object found for alias: " + alias);
            throw new NoSuchAliasException("No certificate object found in token for private key with alias: " + alias);
        }

        if (certificateChain.size() == 1 && CryptoTokenHelper.isDummyCertificate(certificateChain.get(0))) {
            return new DefaultCryptoInstance(alias, context, slot.getProvider(), privateKey, certificateChain.get(0).getPublicKey());
        } else {
            return new DefaultCryptoInstance(alias, context, slot.getProvider(), privateKey, certificateChain);
        }
    }

    @Override
    public void releaseCryptoInstance(ICryptoInstance cryptoInstance, RequestContext context) {
        if (cryptoInstance == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Null crypto instance");
            }
        } else {
            if (!(cryptoInstance instanceof DefaultCryptoInstance)) {
                throw new IllegalArgumentException("Expected instance of " + DefaultCryptoInstance.class + " but got " + cryptoInstance.getClass());
            }
            final DefaultCryptoInstance instance = (DefaultCryptoInstance) cryptoInstance;
            if (instance.getPrivateKey() != null) {
                slot.releasePrivateKey(instance.getPrivateKey());
            }
            instance.invalidate(); // Mark as invalid. Using it from now on is a programming error.
        }
    }

    @Override
    public KeyStore getKeyStore() throws UnsupportedOperationException, CryptoTokenOfflineException, KeyStoreException {
        throw new UnsupportedOperationException("KeyStore is not supported by this token implementation");
    }
    
    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, String keyAlias, IServices services) throws CryptoTokenOfflineException, NoSuchAliasException {
        PrivateKey privateKey = null;
        try {
            privateKey = slot.aquirePrivateKey(keyAlias);
            if (privateKey == null) {
                throw new CryptoTokenOfflineException("No such private key");
            }
            PublicKey publicKey = slot.getPublicKey(keyAlias);
            if (publicKey == null) {
                final Certificate certificate = slot.getCertificate(keyAlias);
                if (certificate == null) {
                    throw new CryptoTokenOfflineException("No such public key");
                }
                publicKey = certificate.getPublicKey();
            }
            return CryptoTokenHelper.genCertificateRequest(info, privateKey, slot.getProvider().getName(), publicKey, explicitEccParameters);
        } finally {
            if (privateKey != null) {
                slot.releasePrivateKey(privateKey);
            }
        }
    }

    @Override
    public Collection<KeyTestResult> testKey(String alias, char[] authCode, IServices services) throws CryptoTokenOfflineException, KeyStoreException {        
        return CryptoTokenHelper.testKey(keystoreDelegator, alias, authCode, slot.getProvider().getName(), signatureAlgorithm);
    }
    
    @Override
    public void generateKey(String keyAlgorithm, String keySpec, String newAlias, char[] authCode, final Map<String, Object> params, final IServices services) throws CryptoTokenOfflineException, IllegalArgumentException {
        // Check key generation limit, if configured
        if (keygenerationLimit != null && keygenerationLimit > -1) {
            final int current;
            current = getSize(slot);
            if (current >= keygenerationLimit) {
                throw new TokenOutOfSpaceException("Key generation limit exceeded: " + current);
            }
        }
        if (CryptoTokenHelper.isKeyAlgorithmAsymmetric(keyAlgorithm)) {
            generateKeyPair(keyAlgorithm, keySpec, newAlias, authCode, params, services);
        } else {
            generateSecretKey(keyAlgorithm, keySpec, newAlias);
        }
    }

    public void generateKeyPair(String keyAlgorithm, String keySpec, final String newAlias, char[] authCode, final Map<String, Object> params, final IServices services) throws CryptoTokenOfflineException, IllegalArgumentException {
        try {
            slot.generateKeyPair(keyAlgorithm, keySpec, newAlias, false, CryptoTokenHelper.convertCKAAttributeListToMap(attributeProperties.getPublicTemplate(keyAlgorithm)), CryptoTokenHelper.convertCKAAttributeListToMap(attributeProperties.getPrivateTemplate(keyAlgorithm)), new CryptokiDevice.CertificateGenerator() {
                @Override
                public X509Certificate generateCertificate(KeyPair keyPair, Provider provider) throws OperatorCreationException, CertificateException {
                    return CryptoTokenHelper.createDummyCertificate(newAlias, params, keyPair, slot.getProvider().getName());
                }
            }, true);
        } catch (CertificateException | OperatorCreationException ex) {
            throw new CryptoTokenOfflineException("Dummy certificate generation failed. Objects might still have been created in the device: " + ex.getMessage(), ex);
        }
    }    

    private void generateSecretKey(String keyAlgorithm, String keySpec, String newAlias) throws TokenOutOfSpaceException {
        if (keyAlgorithm.startsWith(SECRET_KEY_PREFIX)) {
            keyAlgorithm = keyAlgorithm.substring(keyAlgorithm.indexOf(SECRET_KEY_PREFIX) + SECRET_KEY_PREFIX.length());
        }
        if (StringUtils.isNumeric(keyAlgorithm)) {// long constant value is provided for key algorithm            
            long providerAlgoValue = Long.parseLong(keyAlgorithm);
            slot.generateKey(providerAlgoValue, (Integer.valueOf(keySpec)), newAlias);
        } else {
            if (keyAlgorithm.startsWith("0x")) {// hexa decimial value is provided for key algorithm
                long providerAlgoValue = Long.parseLong(keyAlgorithm.substring("0x".length()), 16);
                slot.generateKey(providerAlgoValue, (Integer.valueOf(keySpec)), newAlias);
            } else {// standard java name is provided for key algorithm
                slot.generateKey(CryptoTokenHelper.getProviderAlgoValue(keyAlgorithm), (Integer.valueOf(keySpec)), newAlias);
            }
        }
    }
    
    private int getSize(Slot slot) throws CryptoTokenOfflineException { // TODO: Performance!
        int i = 0;
        Enumeration<SlotEntry> aliases = slot.aliases();
        while (aliases.hasMoreElements()) {
            aliases.nextElement();
            i++;
        }
        return i;
    }

    @Override
    public boolean removeKey(String alias, IServices services) throws CryptoTokenOfflineException, KeyStoreException, SignServerException {
        try {
            return slot.removeKey(alias);
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    @Override
    public void importCertificateChain(List<Certificate> certChain, String alias, char[] athenticationCode, final Map<String, Object> params, final IServices services) throws CryptoTokenOfflineException, IllegalArgumentException {
        try {
            // Check if public keys match in old & new certificates  
            CryptoTokenHelper.ensureNewPublicKeyMatchesOld(keystoreDelegator, alias, certChain.get(0));

            slot.importCertificateChain(certChain, alias);
        } catch (KeyStoreException ex) {
            LOG.error(ex, ex);
            throw new CryptoTokenOfflineException(ex);
        }
    }

    @Override
    public TokenSearchResults searchTokenEntries(int startIndex, int max, org.cesecore.util.query.QueryCriteria qc, boolean includeData, final Map<String, Object> params, final IServices services) throws CryptoTokenOfflineException, QueryException {
        return CryptoTokenHelper.searchTokenEntries(keystoreDelegator,
                   startIndex, max, qc, includeData, services, null);
    }

    protected Slot getSlot() {
        return slot;
    }

}
