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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.crypto.SecretKey;
import javax.persistence.EntityManager;
import javax.persistence.Query;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.util.CertTools;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.QueryGenerator;
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
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerStatus;
import org.signserver.p11ng.common.provider.CryptokiDevice;
import org.signserver.p11ng.common.provider.CryptokiManager;
import org.signserver.p11ng.common.provider.GeneratedKeyData;
import org.signserver.server.IServices;
import org.signserver.server.cryptotokens.BaseCryptoToken;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.CKM_PREFIX;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.DEFAULT_WRAPPING_CIPHER_ALGORITHM;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_ALGORITHM;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_PUBLIC_EXPONENT;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_SPECIFICATION;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_SIGNINGS;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.PROPERTY_WRAPPING_CIPHER_ALGORITHM;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_WRAPPING_CIPHER;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_WRAPPING_KEY;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.createKeyHash;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.getNoOfSignings;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.SUBJECT_DUMMY_4_3_0;
import org.signserver.server.cryptotokens.DefaultCryptoInstance;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.cryptotokens.MechanismNames;
import org.signserver.server.cryptotokens.TokenEntry;
import org.signserver.server.cryptotokens.TokenSearchResults;
import org.signserver.server.key.entities.KeyData;
import org.signserver.server.key.entities.KeyDataService;

/**
 * CryptoToken uses JackNJI11, symmetric keys for wrapping/unwrapping and
 * stores the wrapped key material in a database table.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class JackNJI11KeyWrappingCryptoToken extends BaseCryptoToken {

    private static final Logger LOG = Logger.getLogger(JackNJI11KeyWrappingCryptoToken.class);

    public static final String PROPERTY_WRAPPED_TESTKEY = "WRAPPED_TESTKEY";

    private CryptokiDevice.Slot delegate;

    private String unwrapKeyAlias;
    private String wrappedTestKeyAlias;
    private String wrappingCipher;
    private long wrappingCipherValue;
    private PKCS11Settings settings;    

    public JackNJI11KeyWrappingCryptoToken() throws InstantiationException {

    }

    /**
     * Constructor used when using this implementation without calling the init method.
     * @param unwrapKeyAlias key to use for wrapping/unwrapping
     * @param wrappedTestKeyAlias key in database to test with
     * @param delegate token to use
     * @param wrappingCipherValue cipher algorithm constant to be used for wrapping the key pair
     */
    public JackNJI11KeyWrappingCryptoToken(String unwrapKeyAlias, String wrappedTestKeyAlias, CryptokiDevice.Slot delegate, long wrappingCipherValue) {
        this.delegate = delegate;
        this.unwrapKeyAlias = unwrapKeyAlias;
        this.wrappedTestKeyAlias = wrappedTestKeyAlias;
        this.wrappingCipherValue = wrappingCipherValue;
    }

    @Override
    public void init(int workerId, Properties props, IServices services) throws CryptoTokenInitializationFailureException {
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
        if (sharedLibraryName == null) {
            final StringBuilder sb = new StringBuilder();

            sb.append("Missing SHAREDLIBRARYNAME property\n");
            settings.listAvailableLibraryNames(sb);

            throw new CryptoTokenInitializationFailureException(sb.toString());
        }

        // Check that the crypto token is not disabled
        CryptoTokenHelper.checkEnabled(props);

        // lookup the library defined by SHAREDLIBRARYNAME among the
        // deploy-time-defined values
        final String sharedLibraryFile =
                settings.getP11SharedLibraryFileForName(sharedLibraryName);

        if (sharedLibraryFile == null) {
            final StringBuilder sb = new StringBuilder();

            sb.append("SHAREDLIBRARYNAME ");
            sb.append(sharedLibraryName);
            sb.append(" is not referring to a defined value");
            sb.append("\n");
            settings.listAvailableLibraryNames(sb);

            throw new CryptoTokenInitializationFailureException(sb.toString());
        }

        final File libraryFile = new File(sharedLibraryFile);
        final String libDir = libraryFile.getAbsolutePath();

        CryptokiDevice device = CryptokiManager.getInstance().getDevice(libraryFile.getName(), libDir);

        if (slotLabelTypeValue == Pkcs11SlotLabelType.SLOT_NUMBER) {
            this.delegate = device.getSlot(Long.valueOf(slotLabelValue));
        } else {
            this.delegate = device.getSlotByIndex(Integer.valueOf(slotLabelValue));
        }

        if (delegate == null) {
            throw new CryptoTokenInitializationFailureException("Unable to obtain token in slot");
        }
        String authCode = props.getProperty("pin");
        if (authCode != null) {
            try {
                delegate.login(authCode);
            } catch (Exception e) {
                LOG.error("Error auto activating PKCS11CryptoToken : " + e.getMessage(), e);
            }
        }

        unwrapKeyAlias = props.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY);
        if (unwrapKeyAlias == null) {
            throw new CryptoTokenInitializationFailureException("Missing " + CryptoTokenHelper.PROPERTY_DEFAULTKEY + " property");
        }
        
        wrappedTestKeyAlias = props.getProperty(PROPERTY_WRAPPED_TESTKEY);
        // Use similar way as in JackNJI11KeyWrappingCryptoWorker. Empty value is not allowed for WRAPPED_TESTKEY
        if (StringUtils.isBlank(wrappedTestKeyAlias)) {
            wrappedTestKeyAlias = null;
        }

        wrappingCipher = props.getProperty(PROPERTY_WRAPPING_CIPHER_ALGORITHM);
        if (StringUtils.isBlank(wrappingCipher)) {
            wrappingCipher = DEFAULT_WRAPPING_CIPHER_ALGORITHM;
        }

        try {
            if (StringUtils.isNumeric(wrappingCipher)) {// long constant value is provided for cipher algorithm
                wrappingCipherValue = Long.parseLong(wrappingCipher);
            } else {
                if (wrappingCipher.startsWith("0x")) {// hexa decimial value is provided for cipher algorithm
                    wrappingCipherValue = Long.parseLong(wrappingCipher.substring("0x".length()), 16);
                } else if (wrappingCipher.startsWith(CKM_PREFIX)) {// CKM constant name is provided for key cipher algorithm
                    wrappingCipherValue = CryptoTokenHelper.getProviderCipherAlgoValue(wrappingCipher);
                } else {
                    throw new CryptoTokenInitializationFailureException("Provided Cipher Algorithm " + wrappingCipher + " is invalid");
                }
            }
        } catch (NumberFormatException ex) {
            throw new CryptoTokenInitializationFailureException("Cipher Algorithm could not be parsed as number: " + ex.getMessage());
        } catch (IllegalArgumentException ex) {
            throw new CryptoTokenInitializationFailureException(ex.getMessage());
        }
        
        boolean useCache = Boolean.parseBoolean(props.getProperty(CryptoTokenHelper.PROPERTY_USE_CACHE, CryptoTokenHelper.DEFAULT_PROPERTY_USE_CACHE));
        delegate.setUseCache(useCache);
    }

    @Override
    public int getCryptoTokenStatus(final IServices services) {
        int result;

        try {
            SecretKey secretKey = delegate.getSecretKey(unwrapKeyAlias);
            if (secretKey == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unable to get secret key with alias " + unwrapKeyAlias);
                }
                result = WorkerStatus.STATUS_OFFLINE;
            } else {

                // If we have a wrapped test key, let's use it
                if (wrappedTestKeyAlias == null) {
                    result = WorkerStatus.STATUS_ACTIVE;
                } else {
                    ICryptoInstance crypto = null;
                    try {
                        crypto = acquireInternal(wrappedTestKeyAlias, services.get(EntityManager.class));
                        CryptoTokenHelper.testSignAndVerify(crypto.getPrivateKey(), crypto.getPublicKey(), crypto.getProvider().getName(), null);
                        result = WorkerStatus.STATUS_ACTIVE;
                    } finally {
                        if (crypto != null) {
                            releaseCryptoInstance(crypto, null);
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
        delegate.login(authenticationcode);
    }

    @Override
    public boolean deactivate(IServices services) throws CryptoTokenOfflineException {
        delegate.logout();
        return true;
    }

    @Override
    public ICryptoInstance acquireCryptoInstance(String alias, Map<String, Object> params, RequestContext context) throws
            CryptoTokenOfflineException,
            NoSuchAliasException,
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            IllegalRequestException {
        return acquireInternal(alias, context.getServices().get(EntityManager.class));
    }

    private ICryptoInstance acquireInternal(String alias, EntityManager em) throws IllegalRequestException, CryptoTokenOfflineException {
        KeyDataService service = new KeyDataService(em);

        KeyData keyData = service.find(alias);
        if (keyData == null) {
            LOG.error("No keyData found for alias: " + alias);
            throw new CryptoTokenOfflineException("No key with alias: " + alias + " in database");
        }
        String wrappedKey = keyData.getKeyData();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found keydata for alias: " + alias);
        }
        String certData = keyData.getCertData();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found certdata for alias: " + alias);
        }
        String wrappingKeyAliasFromDB = keyData.getWrappingKeyAlias();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found wrappingKeyAlias for alias: " + wrappingKeyAliasFromDB);
        }
        long wrappingCipherFromDB = keyData.getWrappingCipher();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found wrappingCipher for alias: " + wrappingCipherFromDB);
        }

        // Let's do everything now. This could however instead be done lazily later in the ICryptoInstance instance.
        PrivateKey privateKey = delegate.unwrapPrivateKey(org.bouncycastle.util.encoders.Base64.decode(wrappedKey), wrappingKeyAliasFromDB, wrappingCipherFromDB);

        List<Certificate> certificateChain;
        try {
            certificateChain = CertTools.getCertsFromPEM(new ByteArrayInputStream(certData.getBytes("ASCII")), Certificate.class);
        } catch (CertificateException | IOException ex) {
            LOG.error("Incorrect certificate data for alias " + alias + ": " + ex.getMessage());
            throw new CryptoTokenOfflineException("Incorrect certificate data");
        }

        if (certificateChain != null && certificateChain.size() == 1 && CryptoTokenHelper.isDummyCertificate(certificateChain.get(0))) {
            return new DefaultCryptoInstance(alias, null, delegate.getProvider(), privateKey, null, certificateChain.get(0).getPublicKey());
        } else {
            return new DefaultCryptoInstance(alias, null, delegate.getProvider(), privateKey, certificateChain);
        }
    }

    @Override
    public void releaseCryptoInstance(ICryptoInstance cryptoInstance, RequestContext context) {
        if (cryptoInstance == null) {
            return;
        }
        if (!(cryptoInstance instanceof DefaultCryptoInstance)) {
            throw new IllegalArgumentException("Expected instance of " + DefaultCryptoInstance.class + " but got " + cryptoInstance.getClass());
        }
        final DefaultCryptoInstance instance = (DefaultCryptoInstance) cryptoInstance;
        if (instance.getPrivateKey() != null) {
            delegate.releasePrivateKey(instance.getPrivateKey());
        }
        instance.invalidate(); // Mark as invalid. Using it from now on is a programming error.
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, String keyAlias, IServices services) throws CryptoTokenOfflineException {
        try {
            final EntityManager em = services.get(EntityManager.class);
            if (em == null) {
                throw new CryptoTokenOfflineException("Crypto token requires a database connection"); // TODO: type
            }
            KeyDataService service = new KeyDataService(services.get(EntityManager.class));

            KeyData keyData = service.find(keyAlias);
            if (keyData == null) {
                LOG.error("No keyData found for alias: " + keyAlias);
                throw new IllegalArgumentException("No such key");
            }
            String wrappedKey = keyData.getKeyData();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found keydata for alias: " + keyAlias);
            }
            String certData = keyData.getCertData();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found certdata for alias: " + keyAlias);
            }
            String wrappingKeyAliasFromDB = keyData.getWrappingKeyAlias();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found wrappingKeyAlias for alias: " + wrappingKeyAliasFromDB);
            }
            long wrappingCipherFromDB = keyData.getWrappingCipher();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found wrappingCipher for alias: " + wrappingCipherFromDB);
            }

            PrivateKey privateKey = delegate.unwrapPrivateKey(org.bouncycastle.util.encoders.Base64.decode(wrappedKey), wrappingKeyAliasFromDB, wrappingCipherFromDB);
            List<Certificate> chain = CertTools.getCertsFromPEM(new ByteArrayInputStream(keyData.getCertData().getBytes("ASCII")), Certificate.class);
            PublicKey publicKey = chain.iterator().next().getPublicKey();
            
            return CryptoTokenHelper.genCertificateRequest(info, privateKey, delegate.getProvider().getName(), publicKey, explicitEccParameters);
        } catch (IOException | CertificateException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public Collection<KeyTestResult> testKey(String alias, char[] authCode, IServices services) throws CryptoTokenOfflineException, KeyStoreException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("testKey for alias: " + alias);
        }

        if (alias.equalsIgnoreCase(ICryptoTokenV4.ALL_KEYS)) {
            throw new CryptoTokenOfflineException("Testing all keys not supported by this token");
        }

        final Collection<KeyTestResult> result = new LinkedList<>();

        String status;
        boolean success = false;
        SecretKey secretKey = delegate.getSecretKey(alias);
        String publicKeyHash = "";
        if (secretKey == null) {

            ICryptoInstance crypto = null;
            try {
                crypto = acquireInternal(alias, services.get(EntityManager.class));
                publicKeyHash = createKeyHash(crypto.getPublicKey());
                CryptoTokenHelper.testSignAndVerify(crypto.getPrivateKey(), crypto.getPublicKey(), crypto.getProvider().getName(), null);
                status = "";
                success = true;
            } catch (IllegalRequestException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException | OperatorCreationException | IOException ex) {
                status = ex.getMessage();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Test failed", ex);
                }
            } finally {
                if (crypto != null) {
                    releaseCryptoInstance(crypto, null);
                }
            }
            result.add(new KeyTestResult(alias, success, status, publicKeyHash));
        } else {
            status = "";
            success = true;
            result.add(new KeyTestResult(alias, success, status, "(symmetric key)"));
        }



        if (LOG.isDebugEnabled()) {
            LOG.debug("<testKey");
        }
        return result;
    }

    @Override
    public void generateKey(String keyAlgorithm, String keySpec, String newAlias, char[] authCode, final Map<String, Object> params, final IServices services) throws CryptoTokenOfflineException, IllegalArgumentException {
        final EntityManager em = services.get(EntityManager.class);
        if (em == null) {
            throw new CryptoTokenOfflineException("Key generation not supported by this crypto token without a database"); // TODO: type
        }

        KeyDataService service = new KeyDataService(em);

        final GeneratedKeyData keyData = delegate.generateWrappedKey(unwrapKeyAlias, keyAlgorithm, keySpec, wrappingCipherValue);

        PrivateKey privateKey = null;
        try {
            privateKey = delegate.unwrapPrivateKey(keyData.getWrappedPrivateKey(), unwrapKeyAlias, wrappingCipherValue);

            Calendar cal = Calendar.getInstance();
            Date notBefore = cal.getTime();
            cal.add(Calendar.YEAR, 50);
            Date notAfter = cal.getTime();

            X500Name dn = new X500Name(SUBJECT_DUMMY_4_3_0 + newAlias);

            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(dn, new BigInteger("123"), notBefore, notAfter, dn, keyData.getPublicKey());
            X509CertificateHolder cert = builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(privateKey));
            StringWriter out = new StringWriter();
            try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
                writer.writeObject(cert);
            }
            String pemCertificates = out.toString();
            service.create(newAlias, Base64.toBase64String(keyData.getWrappedPrivateKey()), pemCertificates, unwrapKeyAlias, wrappingCipherValue);
        } catch (Exception ex) { // TODO
            throw new CryptoTokenOfflineException("generateWrappedKey failed: " + ex.getMessage(), ex); // TODO
        } finally {
            if (privateKey != null) {
                delegate.releasePrivateKey(privateKey);
            }
        }
    }

    @Override
    public boolean removeKey(String alias, IServices services) throws CryptoTokenOfflineException, KeyStoreException, SignServerException {
        final EntityManager em = services.get(EntityManager.class);
        if (em == null) {
            throw new CryptoTokenOfflineException("Key removal not supported by this crypto token without a database");
        }
        KeyDataService service = new KeyDataService(em);
        return service.remove(alias);
    }

    @Override
    public void importCertificateChain(List<Certificate> certChain, String alias, char[] athenticationCode, final Map<String, Object> params, final IServices services) throws CryptoTokenOfflineException, IllegalArgumentException {
        try {
            final EntityManager em = services.get(EntityManager.class);
            if (em == null) {
                throw new CryptoTokenOfflineException("Crypto token requires a database connection"); // TODO: type
            }
            KeyDataService service = new KeyDataService(services.get(EntityManager.class));

            KeyData keyData = service.find(alias);
            if (keyData == null) {
                LOG.error("No keyData found for alias: " + alias);
                throw new IllegalArgumentException("No such key");
            }
            
            // Check if public keys match in old & new certificates  
            String certData = keyData.getCertData();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found certdata for alias: " + alias);
            }
            List<Certificate> oldCertificateChain;
            try {
                oldCertificateChain = CertTools.getCertsFromPEM(new ByteArrayInputStream(certData.getBytes("ASCII")), Certificate.class);
            } catch (UnsupportedEncodingException ex) {
                throw new CryptoTokenOfflineException("Incorrect certificate data");
            }
            if (!oldCertificateChain.get(0).getPublicKey().equals(certChain.get(0).getPublicKey())) {
                throw new CryptoTokenOfflineException("New certificate public key does not match current one");
            }

            keyData.setCertData(new String(CertTools.getPemFromCertificateChain(certChain), StandardCharsets.US_ASCII));
        } catch (CertificateException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public TokenSearchResults searchTokenEntries(int startIndex, int max, org.cesecore.util.query.QueryCriteria qc, boolean includeData, final Map<String, Object> params, final IServices services) throws CryptoTokenOfflineException, QueryException {
        final TokenSearchResults result;
        final EntityManager em = services.get(EntityManager.class);
        if (em == null) {
            throw new CryptoTokenOfflineException("Crypto token requires a database connection"); // TODO: type
        }

        final ArrayList<TokenEntry> tokenEntries = new ArrayList<>();

        final List<KeyData> keyDatas = internalSelectKeyData(em, startIndex, max + 1, qc);

        int i = 0;
        for (KeyData data : keyDatas) {
            // We did query one extra entry just to see if there are more available,
            // don't include it in the result
            if (++i > max) {
                break;
            }

            final String keyAlias = data.getKeyAlias();

            final String type;
            /*if (keyStore.entryInstanceOf(keyAlias, KeyStore.PrivateKeyEntry.class)) {
                type = TokenEntry.TYPE_PRIVATEKEY_ENTRY;
            } else if (keyStore.entryInstanceOf(keyAlias, KeyStore.SecretKeyEntry.class)) {
                type = TokenEntry.TYPE_SECRETKEY_ENTRY;
            } else if (keyStore.entryInstanceOf(keyAlias, KeyStore.TrustedCertificateEntry.class)) {
                type = TokenEntry.TYPE_TRUSTED_ENTRY;
            }  else {
                type = null;
            }*/
            type = TokenEntry.TYPE_PRIVATEKEY_ENTRY; // TODO: Should be entry in entity for type

            TokenEntry entry = new TokenEntry(keyAlias, type);

            {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("checking keyAlias: " + keyAlias);
                }

                // Add additional data
                if (includeData) {
                    final Map<String, String> info = new HashMap<>();
                    entry.setInfo(info);
                    /*try {
                        Date creationDate = keyStore.getCreationDate(keyAlias);
                        entry.setCreationDate(creationDate);
                    } catch (ProviderException ex) {} // NOPMD: We ignore if it is not supported
                    */

                    if (TokenEntry.TYPE_PRIVATEKEY_ENTRY.equals(type)) {
                        try {
                            List<Certificate> chain = CertTools.getCertsFromPEM(new ByteArrayInputStream(data.getCertData().getBytes(StandardCharsets.US_ASCII)), Certificate.class);
                            if (!chain.isEmpty()) {
                                final PublicKey pubKey = chain.get(0).getPublicKey();
                                final String keyAlgorithm =
                                        AlgorithmTools.getKeyAlgorithm(pubKey);
                                info.put(INFO_KEY_ALGORITHM, keyAlgorithm);
                                info.put(INFO_KEY_SPECIFICATION,
                                         AlgorithmTools.getKeySpecification(pubKey));
                                if (AlgorithmConstants.KEYALGORITHM_RSA.equals(keyAlgorithm)) {
                                    final RSAPublicKey rsaKey = (RSAPublicKey) pubKey;

                                    info.put(INFO_KEY_PUBLIC_EXPONENT,
                                            rsaKey.getPublicExponent().toString(10));
                                }
                                info.put(INFO_KEY_SIGNINGS, String.valueOf(getNoOfSignings(pubKey, services)));
                                info.put(INFO_KEY_WRAPPING_KEY, data.getWrappingKeyAlias());
                                String wrappingCipherName = MechanismNames.nameFromLong(data.getWrappingCipher());
                                info.put(INFO_KEY_WRAPPING_CIPHER, wrappingCipherName);
                            }
                            entry.setParsedChain(chain.toArray(new Certificate[0]));
                        } catch (CertificateEncodingException ex) {
                            LOG.error("Certificates could not be encoded for alias: " + keyAlias, ex);
                        } catch (CertificateException ex) {
                            LOG.error("Certificates could not be encoded for alias: " + keyAlias, ex);
                        }
                    } /*else if (TokenEntry.TYPE_TRUSTED_ENTRY.equals(type)) {
                        Certificate certificate = keyStore.getCertificate(keyAlias);
                        try {
                            entry.setParsedTrustedCertificate(certificate);
                        } catch (CertificateEncodingException ex) {
                            LOG.error("Certificate could not be encoded for alias: " + keyAlias, ex);
                        }
                    }*/
                }
                tokenEntries.add(entry);
            }

        }

        result = new TokenSearchResults(tokenEntries, i > max);
        return result;
    }

    @SuppressWarnings("unchecked")
    private List<KeyData> internalSelectKeyData(final EntityManager em, final int startIndex, final int max, final QueryCriteria criteria) {
        return buildConditionalQuery(em, "SELECT a FROM KeyData a", criteria, startIndex, max).getResultList();
    }

    /**
     * Build a JPA Query from the supplied queryStr and criteria.
     * Optionally using startIndex and resultLimit (used if >0).
     */
    private Query buildConditionalQuery(final EntityManager entityManager, final String queryStr, final QueryCriteria criteria, final int startIndex, final int resultLimit) {
        final Query query;
        if (criteria == null) {
            query = entityManager.createQuery(queryStr);
        } else {
            QueryGenerator generator = QueryGenerator.generator(KeyData.class, criteria, "a");
            final String conditions = generator.generate();
            query = entityManager.createQuery(queryStr + conditions);
            for (final String key : generator.getParameterKeys()) {
                final Object param = generator.getParameterValue(key);
                query.setParameter(key, param);
            }
        }
        if (resultLimit > 0) {
            query.setMaxResults(resultLimit);
        }
        if (startIndex > 0) {
            query.setFirstResult(startIndex-1);
        }
        return query;
    }

    @Override
    public KeyStore getKeyStore() throws UnsupportedOperationException, CryptoTokenOfflineException, KeyStoreException {
        throw new UnsupportedOperationException("KeyStore is not supported by this token implementation");
    }

}
