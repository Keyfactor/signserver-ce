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
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.*;
import org.signserver.server.IServices;
import org.signserver.server.log.AdminInfo;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.SECRET_KEY_PREFIX;

/**
 * Class that uses a PKCS12 or JKS file on the file system for signing.
 *
 * If no DEFAULTKEY property is specified the first key found will be used.
 *
 * Loads on activation and releases the keys from memory when deactivating
 *
 * Available properties are:
 * KEYSTOREPATH : The full path to the key store to load. (required)
 * KEYSTOREPASSWORD : The password that locks the key store.
 * KEYSTORETYPE : PKCS12 or JKS. (required)
 * DEFAULTKEY : Alias of keystore entry to use. (optional)
 * NEXTCERTSIGNKEY : Can be used to hold the alias of the next key. (optional)
 *
 * @author Philip Vendil, Markus Kilas
 * @version $Id$
 */
public class KeystoreCryptoToken extends BaseCryptoToken {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(KeystoreCryptoToken.class);

    public static final String KEYSTOREPATH = "KEYSTOREPATH";
    public static final String KEYSTOREPASSWORD = "KEYSTOREPASSWORD";
    public static final String KEYSTORETYPE = "KEYSTORETYPE";
    public static final String DEFAULTKEY = "DEFAULTKEY";
    public static final String NEXTKEY = "NEXTCERTSIGNKEY";

    public static final String TYPE_PKCS12 = "PKCS12";
    public static final String TYPE_JKS = "JKS";
    public static final String TYPE_INTERNAL = "INTERNAL";
    
    private static final String PROPERTY_SIGNATUREALGORITHM = "SIGNATUREALGORITHM";

    private String keystorepath = null;
    private String keystorepassword = null;
    private boolean autoActivate;
    private String signatureAlgorithm;

    private volatile KeyStore ks; // Note: Needs volatile as different threads might load the key store at activation time
    private String keystoretype;
    private Properties properties;

    /** Mapping from alias or key purpose to KeyEntry. */
    private Map<Object, KeyEntry> entries;

    private char[] authenticationCode;

    private int workerId;
    private Integer keygenerationLimit;
    
    private KeyStoreDelegator delegator;

    @Override
    public void init(int workerId, Properties properties, IServices services) throws CryptoTokenInitializationFailureException {
        this.properties = properties;
        this.workerId = workerId;
        keystorepath = properties.getProperty(KEYSTOREPATH);
        keystorepassword = properties.getProperty(KEYSTOREPASSWORD);
        keystoretype = properties.getProperty(KEYSTORETYPE);

        // check keystore type
        if (keystoretype == null) {
            throw new CryptoTokenInitializationFailureException("Missing KEYSTORETYPE property");
        }

        if (!TYPE_PKCS12.equals(keystoretype) &&
            !TYPE_JKS.equals(keystoretype) &&
            !TYPE_INTERNAL.equals(keystoretype)) {
            throw new CryptoTokenInitializationFailureException("KEYSTORETYPE should be either PKCS12, JKS, or INTERNAL");
        }

        // Check that the crypto token is not disabled
        CryptoTokenHelper.checkEnabled(properties);

        // check keystore file
        if (TYPE_PKCS12.equals(keystoretype) || TYPE_JKS.equals(keystoretype)) {
            if (keystorepath == null) {
                throw new CryptoTokenInitializationFailureException("Missing KEYSTOREPATH property");
            } else {
                final File keystoreFile = new File(keystorepath);

                if (!keystoreFile.isFile()) {
                    throw new CryptoTokenInitializationFailureException("File not found: " + keystorepath);
                }
            }
        }

        // Optional property SIGNATUREALGORITHM
        final String value = properties.getProperty(PROPERTY_SIGNATUREALGORITHM);
        if (!StringUtils.isBlank(value)) {
            signatureAlgorithm = value;
        }

        // Read property KEYGENERATIONLIMIT
        final String keygenLimitValue = properties.getProperty(CryptoTokenHelper.PROPERTY_KEYGENERATIONLIMIT);
        if (keygenLimitValue != null && !keygenLimitValue.trim().isEmpty()) {
            try {
                keygenerationLimit = Integer.parseInt(keygenLimitValue.trim());
            } catch (NumberFormatException ex) {
                throw new CryptoTokenInitializationFailureException("Incorrect value for " + CryptoTokenHelper.PROPERTY_KEYGENERATIONLIMIT + ": " + ex.getLocalizedMessage());
            }
        }

        // If a password is specified we are in auto-activate mode
        autoActivate = keystorepassword != null;
        if (autoActivate) {
            try {
                activate(keystorepassword, services);
            } catch (CryptoTokenAuthenticationFailureException | CryptoTokenOfflineException ex) {
                LOG.error("Auto activation failed: " + ex.getLocalizedMessage());
            }
        }
    }

    @Override
    public int getCryptoTokenStatus(final IServices services) {
        if (entries != null && entries.get(PURPOSE_SIGN) != null
                && (!properties.containsKey(NEXTKEY)
                    || entries.get(PURPOSE_NEXTKEY) != null)) {
            return WorkerStatus.STATUS_ACTIVE;
        } else if (autoActivate) {
            try {
                activate(keystorepassword, services);
                if (entries != null && entries.get(PURPOSE_SIGN) != null
                        && (!properties.containsKey(NEXTKEY)
                            || entries.get(PURPOSE_NEXTKEY) != null)) {
                    return WorkerStatus.STATUS_ACTIVE;
                }
            } catch (CryptoTokenAuthenticationFailureException | CryptoTokenOfflineException ex) {
                LOG.error("Auto activation failed: " + ex.getLocalizedMessage());
            }
        }

        return WorkerStatus.STATUS_OFFLINE;
    }

    /**
     * (Re)read from keystore to in-memory representation.
     */
    private void readFromKeystore(final String authenticationcode, final IServices services)
            throws KeyStoreException, CertificateException,
                   NoSuchProviderException, NoSuchAlgorithmException,
                   IOException,
                   UnrecoverableKeyException {
        if (authenticationcode != null) {
            this.authenticationCode = authenticationcode.toCharArray();
        }
        this.ks = getKeystore(keystoretype, keystorepath, authenticationCode, services);
        this.delegator = new JavaKeyStoreDelegator(this.ks);
        
        entries = new HashMap<>();

        Enumeration<String> e = ks.aliases();
        while (e.hasMoreElements()) {
            final String alias = e.nextElement();
            if (ks.isKeyEntry(alias)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Alias " + alias + " is KeyEntry.");
                }
                final Key key = ks.getKey(alias, authenticationCode);
                if (key instanceof PrivateKey) {
                    final Certificate[] chain = KeyTools.getCertChain(ks,
                            alias);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Loaded certificate chain with length "
                                + chain.length + " from keystore.");
                    }

                    final KeyEntry entry = new KeyEntry((PrivateKey) key,
                            chain[0], Arrays.asList(chain));

                    entries.put(alias, entry);
                } else {
                    LOG.error("Not a private key for alias " + alias);
                }
            }
        }

        // Use the first entry as default key if none specified
        if (properties.getProperty(DEFAULTKEY) == null) {
            e = ks.aliases();

            while (e.hasMoreElements()) {
                final String alias = e.nextElement();
                if (ks.isKeyEntry(alias)) {
                    if (ks.getKey(alias, authenticationCode) != null) {
                        LOG.debug("Aliases " + alias + " is KeyEntry.");
                        properties.setProperty(DEFAULTKEY, alias);
                        break;
                    }
                }
            }
        }

        final String defaultKey = properties.getProperty(DEFAULTKEY);
        if (defaultKey != null) {
            final KeyEntry entry = entries.get(defaultKey);
            if (entry != null) {
                entries.put(ICryptoTokenV4.PURPOSE_SIGN, entry);
                entries.put(ICryptoTokenV4.PURPOSE_DECRYPT, entry);
            } else {
                LOG.error("Not a private key for alias " + defaultKey);
            }
        }

        final String nextKey = properties.getProperty(NEXTKEY);
        if (nextKey != null) {
            final KeyEntry entry = entries.get(nextKey);
            if (entry != null) {
                entries.put(ICryptoTokenV4.PURPOSE_NEXTKEY, entry);
            } else {
                LOG.error("Not a private key for alias " + defaultKey);
            }
        }
    }
    
    @Override
    public void activate(final String authenticationcode, final IServices services)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Keystore type is " + keystoretype +
                    " and path is " + keystorepath);
        }

        try {
            readFromKeystore(authenticationcode, services);
        } catch (KeyStoreException e1) {
            LOG.error("Error :", e1);
            throw new CryptoTokenAuthenticationFailureException("KeyStoreException " + e1.getMessage());
        } catch (FileNotFoundException e) {
            LOG.error("Error :", e);
            throw new CryptoTokenAuthenticationFailureException("Keystore file not found : " + e.getMessage());
        } catch (NoSuchProviderException e1) {
            LOG.error("Error :", e1);
            throw new CryptoTokenAuthenticationFailureException("NoSuchProviderException " + e1.getMessage());
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Error :", e);
            throw new CryptoTokenAuthenticationFailureException("NoSuchAlgorithmException " + e.getMessage());
        } catch (CertificateException e) {
            LOG.error("Error :", e);
            throw new CryptoTokenAuthenticationFailureException("CertificateException " + e.getMessage());
        } catch (IOException e) {
            LOG.error("Error :", e);
            throw new CryptoTokenAuthenticationFailureException("IOException " + e.getMessage());
        } catch (UnrecoverableKeyException e) {
            LOG.error("Error :", e);
            throw new CryptoTokenAuthenticationFailureException("UnrecoverableKeyException " + e.getMessage());
        }
    }

    @Override
    public boolean deactivate(final IServices services) {
        entries = null;
        ks = null;
        if (authenticationCode != null) {
            Arrays.fill(authenticationCode, '\0');
        }
        this.authenticationCode = null;
        this.delegator = null;
        return true;
    }

    private String getProvider(int providerUsage) {
        return "BC";
    }

    private KeyEntry getKeyEntry(final Object purposeOrAlias, IServices services) throws CryptoTokenOfflineException {
        if (entries == null) {
            if (keystorepassword != null) {
                try {
                    activate(keystorepassword, services);
                } catch (CryptoTokenAuthenticationFailureException e) {
                    throw new CryptoTokenOfflineException(
                        "Error trying to autoactivating the keystore, wrong password set? "
                        + e.getMessage());
                }
            } else {
                throw new CryptoTokenOfflineException("Signtoken isn't active.");
            }
        }
        if (purposeOrAlias == null) {
            LOG.error("Alias or Purpose is null");
            throw new CryptoTokenOfflineException("Alias or Purpose is null");
        }
        KeyEntry entry = entries.get(purposeOrAlias);
        if (entry == null || entry.getCertificate() == null) {
            throw new CryptoTokenOfflineException(
                    "No key available for purpose: " + purposeOrAlias);
        }
        return entry;
    }

    @Override
    public Collection<KeyTestResult> testKey(final String alias,
            final char[] authCode,
            final IServices services) throws CryptoTokenOfflineException,
            KeyStoreException {
        return CryptoTokenHelper.testKey(this.delegator, alias, authenticationCode, "BC", signatureAlgorithm);
    }

    @Override
    public TokenSearchResults searchTokenEntries(final int startIndex, final int max, QueryCriteria qc, boolean includeData, Map<String, Object> params, IServices services)
            throws CryptoTokenOfflineException, QueryException {

        // check first whether keystore is available and initialized
        if (this.delegator == null) {
            throw new CryptoTokenOfflineException("PKCS#12 keystore invalid - wrong password or corrupted file?");
        }

        return CryptoTokenHelper.searchTokenEntries(this.delegator, startIndex, max, qc, includeData, services, authenticationCode);
    }

    private void generateKeyPair(String keyAlgorithm, String keySpec, String alias, char[] authCode, Map<String, Object> params, IServices services) throws CryptoTokenOfflineException, IllegalArgumentException {
        try {
            final KeyStore keystore = getKeyStore();
                        
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm, "BC");

            String sigAlgName = null;

            if ("ECDSA".equals(keyAlgorithm)) {
                kpg.initialize(ECNamedCurveTable.getParameterSpec(keySpec));
            } else if ("SPHINCS+".equalsIgnoreCase(keyAlgorithm)) {
                sigAlgName = "SPHINCS+";
                // For now we just use the defaults, later we should use SPHINCSPlusParameterSpec
            } else {
                if ("RSA".equals(keyAlgorithm) && keySpec.contains("exp")) {
                    final AlgorithmParameterSpec spec =
                            CryptoTokenHelper.getPublicExponentParamSpecForRSA(keySpec);
                    kpg.initialize(spec);
                } else {
                    kpg.initialize(Integer.valueOf(keySpec));
                }
            }

            if (sigAlgName == null) {
                sigAlgName = "SHA1With" + keyAlgorithm;
            }

            LOG.debug("generating...");
            final KeyPair keyPair = kpg.generateKeyPair();
            Certificate[] chain = new Certificate[1];
            chain[0] = CryptoTokenHelper.createDummyCertificate(alias, sigAlgName, keyPair, getProvider(PROVIDERUSAGE_SIGN));
            LOG.debug("Creating certificate with entry "+alias+'.');

            keystore.setKeyEntry(alias, keyPair.getPrivate(), authenticationCode, chain);
            
            // TODO: Future optimization: we don't need to regenerate if we create it right from the beginning a few lines up!
            if (params != null) {
                CryptoTokenHelper.regenerateCertIfWanted(alias, authenticationCode, params, this.delegator, keystore.getProvider().getName());
            }
            
            final OutputStream os;
            
            if (TYPE_INTERNAL.equalsIgnoreCase(keystoretype)) {
                os = new ByteArrayOutputStream();
            } else {
                os = new FileOutputStream(new File(keystorepath));
            }
            
            keystore.store(os, authenticationCode);
            
            if (TYPE_INTERNAL.equalsIgnoreCase(keystoretype)) {
                final ByteArrayOutputStream baos = (ByteArrayOutputStream) os;
                
                final WorkerSessionLocal workerSessionLocal = services.get(WorkerSessionLocal.class);
                if (workerSessionLocal == null) {
                    throw new IllegalStateException("No WorkerSession available");
                }
                workerSessionLocal.setKeystoreData(new AdminInfo("Internal", null, null),
                        workerId, baos.toByteArray());
            }

            final KeyEntry entry = new KeyEntry((PrivateKey) keyPair.getPrivate(), 
                                chain[0], Arrays.asList(chain));

            // If this is the first entry
            entries.put(alias, entry);
            if (properties.getProperty(DEFAULTKEY) == null) {
                properties.setProperty(DEFAULTKEY, alias);
                entries.put(ICryptoTokenV4.PURPOSE_SIGN, entry);
                entries.put(ICryptoTokenV4.PURPOSE_DECRYPT, entry);
            }

        } catch (UnsupportedOperationException | KeyStoreException | NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | NumberFormatException | OperatorCreationException | CertificateException | IOException | IllegalStateException | UnrecoverableKeyException ex) {
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
        try {
            final KeyStore keystore = getKeyStore();

            // Check key generation limit, if configured
            if (keygenerationLimit != null && keygenerationLimit > -1) {
                final int current;
                try {
                    current = keystore.size();
                    if (current >= keygenerationLimit) {
                        throw new TokenOutOfSpaceException("Key generation limit exceeded: " + current);
                    }
                } catch (KeyStoreException ex) {
                    LOG.error("Checking key generation limit failed", ex);
                    throw new TokenOutOfSpaceException("Current number of key entries could not be obtained: " + ex.getMessage(), ex);
                }
            }

            if (CryptoTokenHelper.isKeyAlgorithmAsymmetric(keyAlgorithm)) {
                generateKeyPair(keyAlgorithm, keySpec, alias, authCode, params, services);
            } else {
                generateSecretKey(keyAlgorithm, keySpec, alias);
            }
        } catch (UnsupportedOperationException | KeyStoreException ex) {
            LOG.error(ex, ex);
            throw new CryptoTokenOfflineException(ex);
        }
    }
    
    private void generateSecretKey(String keyAlgorithm, String keySpec, String alias) throws CryptoTokenOfflineException {
        if (keyAlgorithm.startsWith(CryptoTokenHelper.SECRET_KEY_PREFIX)) {
            keyAlgorithm = keyAlgorithm.substring(keyAlgorithm.indexOf(SECRET_KEY_PREFIX) + SECRET_KEY_PREFIX.length());
        }
        OutputStream os = null;
        try {
            final KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgorithm);
            keyGen.init(Integer.valueOf(keySpec));
            SecretKey secretKey = keyGen.generateKey();
            final KeyStore keystore = getKeyStore();
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(authenticationCode);
            KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
            keystore.setEntry(alias, skEntry, protParam);

            os = new FileOutputStream(new File(keystorepath));
            keystore.store(os, authenticationCode);
        } catch (NoSuchAlgorithmException | UnsupportedOperationException | KeyStoreException | IOException | CertificateException ex) {
            LOG.error(ex, ex);
            throw new CryptoTokenOfflineException(ex);
        } finally {
            if (os != null) {
                try {
                    os.close();
                } catch (IOException ex) {
                    LOG.error("Error closing file", ex);
                }
            }
        }
    }

    @Override
    public KeyStore getKeyStore() throws UnsupportedOperationException,
            CryptoTokenOfflineException, KeyStoreException {
        if (ks == null) {
            throw new CryptoTokenOfflineException("Not activated");
        }
        return ks;
    }

    private KeyStore getKeystore(final String type, final String path,
            final char[] authCode, final IServices services) throws
            KeyStoreException, CertificateException, NoSuchProviderException,
            NoSuchAlgorithmException, FileNotFoundException, IOException {
        final KeyStore result;
        if (TYPE_PKCS12.equalsIgnoreCase(type) ||
            TYPE_INTERNAL.equalsIgnoreCase(type)) {
            result = KeyStore.getInstance("PKCS12", "BC");
        } else {
            result = KeyStore.getInstance("JKS");
        }

        InputStream in = null;
        
        try {
            if (!TYPE_INTERNAL.equalsIgnoreCase(type)) {
                if (path == null) {
                    throw new FileNotFoundException("Missing property "
                            + KeystoreCryptoToken.KEYSTOREPATH + ".");
                }
            
                in = new FileInputStream(path);
            } else {
                // load data from internal worker data...
                final byte[] keystoreData =
                        getWorkerSession(services).getKeystoreData(new AdminInfo("Internal", null, null),
                                        this.workerId);
                if (keystoreData != null) {
                    in = new ByteArrayInputStream(keystoreData);
                }
            }

            result.load(in, authCode);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOG.error("Error closing file", ex);
                }
            }
        }
        return result;
    }

    @Override
    public boolean removeKey(final String alias, final IServices services) throws CryptoTokenOfflineException, KeyStoreException, SignServerException {
        final KeyStore keyStore = getKeyStore();
        boolean result = CryptoTokenHelper.removeKey(this.delegator, alias);
        if (result) {
            OutputStream out = null;
            try {
                if (!TYPE_INTERNAL.equalsIgnoreCase(keystoretype)) {
                    out = new FileOutputStream(new File(keystorepath));
                } else {
                    // use internal worker data
                    out = new ByteArrayOutputStream();
                }
                keyStore.store(out, authenticationCode);
                
                if (TYPE_INTERNAL.equalsIgnoreCase(keystoretype)) {
                    final byte[] data = ((ByteArrayOutputStream) out).toByteArray();
                    
                    getWorkerSession(services).setKeystoreData(new AdminInfo("Internal", null, null), 
                                                       this.workerId, data);
                }
                
                readFromKeystore(null, services);
            } catch (IOException | NoSuchAlgorithmException | CertificateException | NoSuchProviderException | UnrecoverableKeyException ex) {
                LOG.error("Unable to persist new keystore after key removal: " + ex.getMessage(), ex);
                throw new SignServerException("Unable to persist key removal");
            } finally {
                IOUtils.closeQuietly(out);
            }
        }
        return result;
    }

    private PrivateKey getPrivateKey(String alias, IServices services) throws CryptoTokenOfflineException {
        return getKeyEntry(alias, services).getPrivateKey();
    }

    private PublicKey getPublicKey(String alias, IServices services) throws CryptoTokenOfflineException {
        return getKeyEntry(alias, services).getCertificate().getPublicKey();
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, String keyAlias, IServices services) throws CryptoTokenOfflineException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Alias: " + keyAlias);
        }
        try {
            return CryptoTokenHelper.genCertificateRequest(info, getPrivateKey(keyAlias, services), getProvider(ICryptoTokenV4.PROVIDERUSAGE_SIGN), getPublicKey(keyAlias, services), explicitEccParameters);
        } catch (IllegalArgumentException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.error("Certificate request error", ex);
            }
            throw new CryptoTokenOfflineException(ex.getMessage(), ex);
        }
    }

    @Override
    public void importCertificateChain(final List<Certificate> certChain,
                                       final String alias,
                                       final char[] authCode,
                                       final Map<String, Object> params,
                                       final IServices services)
        throws CryptoTokenOfflineException, IllegalArgumentException {
        if (certChain.size() < 1) {
            throw new IllegalArgumentException("Certificate chain can not be empty");
        }
        
        try {
            final KeyStore keyStore = getKeyStore();
            final Key key =
                    keyStore.getKey(alias, authCode != null ? authCode : authenticationCode);
            
            CryptoTokenHelper.ensureNewPublicKeyMatchesOld(this.delegator, alias, certChain.get(0));
            
            keyStore.setKeyEntry(alias, key,
                                 authCode != null ? authCode : authenticationCode,
                                 certChain.toArray(new Certificate[0]));
            
            // persist keystore
            final OutputStream out;
            
            if (!TYPE_INTERNAL.equalsIgnoreCase(keystoretype)) {
                out = new FileOutputStream(new File(keystorepath));
            } else {
                // use internal worker data
                out = new ByteArrayOutputStream();
            }
            keyStore.store(out, authenticationCode);

            if (TYPE_INTERNAL.equalsIgnoreCase(keystoretype)) {
                final byte[] data = ((ByteArrayOutputStream) out).toByteArray();

                getWorkerSession(services).setKeystoreData(new AdminInfo("Internal", null, null), 
                                                   this.workerId, data);
            }
                
            // update in-memory representation
            KeyEntry entry = getKeyEntry(alias, services);
            final Certificate signingCert = certChain.get(0);
            
            if (entry == null) {
                entry = new KeyEntry();
            }
            
            entry.setCertificate(signingCert);
            entry.setCertificateChain(certChain);
        } catch (Exception e) {
            throw new CryptoTokenOfflineException(e);
        }   
    }

    protected WorkerSessionLocal getWorkerSession(final IServices services) {
        return services.get(WorkerSessionLocal.class);
    }

    @Override
    public ICryptoInstance acquireCryptoInstance(String alias, Map<String, Object> params, RequestContext context) throws
            CryptoTokenOfflineException, 
            NoSuchAliasException, 
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            IllegalRequestException {
        final boolean includeDummyCertificate = params.containsKey(PARAM_INCLUDE_DUMMYCERTIFICATE);
        final KeyEntry entry = getKeyEntry(alias, context.getServices());
        if ((entry.getCertificateChain().size() == 1 && CryptoTokenHelper.isDummyCertificate(entry.getCertificateChain().get(0))) && !includeDummyCertificate) {
            return new DefaultCryptoInstance(alias, context, ks.getProvider(), entry.getPrivateKey(), entry.getCertificateChain().get(0).getPublicKey());
        } else {
            return new DefaultCryptoInstance(alias, context, ks.getProvider(), entry.getPrivateKey(), entry.getCertificateChain());
        }
    }

    @Override
    public void releaseCryptoInstance(ICryptoInstance instance, RequestContext context) {
        // NOP
    }

    private static class KeyEntry {
        private PrivateKey privateKey;
        private Certificate certificate;
        private List<Certificate> certificateChain;

        public KeyEntry() {
        }
        
        public KeyEntry(final PrivateKey privateKey,
                final Certificate certificate,
                final List<Certificate> certificateChain) {
            this.privateKey = privateKey;
            this.certificate = certificate;
            this.certificateChain = certificateChain;
        }

        public Certificate getCertificate() {
            return certificate;
        }

        public List<Certificate> getCertificateChain() {
            return certificateChain;
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }
        
        public void setCertificate(final Certificate cert) {
            certificate = cert;
        }
        
        public void setCertificateChain(final List<Certificate> certChain) {
            certificateChain = certChain;
        }
        
        public void setPrivateKey(final PrivateKey privKey) {
            privateKey = privKey;
        }
    }

}
