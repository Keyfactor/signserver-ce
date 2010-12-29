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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.SignerStatus;
import org.signserver.common.KeyTestResult;

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
 * STORETYPE : PKCS12 or JKS. (required)
 * DEFAULTKEY : Alias of keystore entry to use. (optional)
 * NEXTCERTSIGNKEY : Can be used to hold the alias of the next key. (optional)
 *
 * @author Philip Vendil, Markus Kilas
 * $Id$
 */
public class KeystoreCryptoToken implements ICryptoToken,
    IKeyGenerator {

    private static final Logger LOG = Logger.getLogger(KeystoreCryptoToken.class);

    public static final String KEYSTOREPATH = "KEYSTOREPATH";
    public static final String KEYSTOREPASSWORD = "KEYSTOREPASSWORD";
    public static final String KEYSTORETYPE = "KEYSTORETYPE";
    public static final String DEFAULTKEY = "DEFAULTKEY";
    public static final String NEXTKEY = "NEXTCERTSIGNKEY";

    public static final String TYPE_PKCS12 = "PKCS12";
    public static final String TYPE_JKS = "JKS";

    private static final String SUBJECT_DUMMY = "L=_SignServer_DUMMY_CERT_";

    private String keystorepath = null;
    private String keystorepassword = null;

    private KeyStore ks;
    private String provider;
    private String keystoretype;
    private Properties properties;

    private Map<Integer, KeyEntry> entries;

    private char[] authenticationCode;

    /**
     * @see org.signserver.server.cryptotokens.ICryptoToken#init(java.util.Properties)
     */
    public void init(int workerId, Properties properties) {
        this.properties = properties;
        keystorepath = properties.getProperty(KEYSTOREPATH);
        keystorepassword = properties.getProperty(KEYSTOREPASSWORD);
        keystoretype = properties.getProperty(KEYSTORETYPE);
    }

    /**
     * Returns true if the key store was properly loaded.
     *
     * @see org.signserver.server.cryptotokens.ICryptoToken#getCryptoTokenStatus()
     *
     */
    public int getCryptoTokenStatus() {
        if (entries != null && entries.get(PURPOSE_SIGN) != null
                && (!properties.containsKey(NEXTKEY)
                    || entries.get(PURPOSE_NEXTKEY) != null)) {
            return SignerStatus.STATUS_ACTIVE;
        }

        return SignerStatus.STATUS_OFFLINE;
    }

    /**
     * Loads the key store into memory
     *
     * @see org.signserver.server.cryptotokens.ICryptoToken#activate(java.lang.String)
     */
    public void activate(String authenticationcode)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Keystore type is " + keystoretype +
                    " and path is " + keystorepath);
        }

        try {
            this.ks = getKeystore(keystoretype, keystorepath,
                    authenticationcode.toCharArray());
            this.provider = ks.getProvider().getName();
            this.authenticationCode = authenticationcode.toCharArray();

            entries = new HashMap<Integer, KeyEntry>();

            // Use the first entry as default key if none specified
            if (properties.getProperty(DEFAULTKEY) == null) {
                Enumeration<String> e = ks.aliases();

                while (e.hasMoreElements()) {
                    final String alias = e.nextElement();
                    if (ks.isKeyEntry(alias)) {
                        if (ks.getKey(alias,
                                authenticationcode.toCharArray()) != null) {
                            LOG.debug("Aliases " + alias + " is KeyEntry.");
                                properties.setProperty(DEFAULTKEY, alias);
                            break;
                        }
                    }
                }
            }

            final String defaultKey = properties.getProperty(DEFAULTKEY);
            if (defaultKey != null) {
                final Key key = ks.getKey(defaultKey,
                        authenticationcode.toCharArray());
                if (key instanceof PrivateKey) {

                    final Certificate[] chain = KeyTools.getCertChain(ks,
                            defaultKey);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Loaded certificate chain with length "
                                + chain.length + " from keystore.");
                    }

                    final KeyEntry entry = new KeyEntry((PrivateKey) key, 
                            chain[0], Arrays.asList(chain));

                    entries.put(ICryptoToken.PURPOSE_SIGN, entry);
                    entries.put(ICryptoToken.PURPOSE_DECRYPT, entry);
                } else {
                    LOG.error("Not a private key for alias " + defaultKey);
                }
            }

            final String nextKey = properties.getProperty(NEXTKEY);
            if (nextKey != null) {
                final Key key = ks.getKey(nextKey,
                        authenticationcode.toCharArray());
                if (key instanceof PrivateKey) {

                    final Certificate[] chain = KeyTools.getCertChain(ks,
                            nextKey);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Loaded certificate chain with length "
                                + chain.length + " from keystore.");
                    }

                    final KeyEntry entry = new KeyEntry((PrivateKey) key,
                            chain[0], Arrays.asList(chain));

                    entries.put(ICryptoToken.PURPOSE_NEXTKEY, entry);
                } else {
                    LOG.error("Not a private key for alias " + defaultKey);
                }
            }
            
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

    /**
     * Method that clear the key data from memory.
     *
     * @see org.signserver.server.cryptotokens.ICryptoToken#deactivate()
     */
    public boolean deactivate() {
        entries = null;
        ks = null;
        if (authenticationCode != null) {
            for (int i = 0; i < authenticationCode.length; i++) {
                authenticationCode[i] = 0;
            }
        }
        this.authenticationCode = null;
        return true;
    }

    /**
     * 
     * @see org.signserver.server.cryptotokens.ICryptoToken#getPrivateKey(int)
     */
    public PrivateKey getPrivateKey(int purpose)
            throws CryptoTokenOfflineException {

        if (entries == null) {
            if (keystorepassword != null) {
                try {
                    activate(keystorepassword);
                } catch (CryptoTokenAuthenticationFailureException e) {
                    throw new CryptoTokenOfflineException("Error trying to autoactivating the keystore, wrong password set? " + e.getMessage());
                }
            } else {
                throw new CryptoTokenOfflineException("Signtoken isn't active.");
            }
        }
        KeyEntry entry = entries.get(purpose);
        // If key for 'purpose' not available and no nextKey defined, try with
        // default
        if ((entry == null || entry.getPrivateKey() == null)
                && !properties.containsKey(NEXTKEY)) {
            entry = entries.get(PURPOSE_SIGN);
        }
        if (entry == null || entry.getPrivateKey() == null) {
            throw new CryptoTokenOfflineException(
                    "No key available for purpose: " + purpose);
        }
        return entry.getPrivateKey();
    }

    /**
     * 
     * @see org.signserver.server.cryptotokens.ICryptoToken#getPublicKey(int)
     */
    public PublicKey getPublicKey(int purpose) throws
            CryptoTokenOfflineException {
        final Certificate cert = getKeyEntry(purpose).getCertificate();
        return cert.getPublicKey();
    }

    /**
     * Always returns BC
     * @see org.signserver.server.cryptotokens.ICryptoToken#getProvider()
     */
    public String getProvider(int providerUsage) {
        return provider;
    }

    private KeyEntry getKeyEntry(final int purpose) throws CryptoTokenOfflineException {
        if (entries == null) {
            if (keystorepassword != null) {
                try {
                    activate(keystorepassword);
                } catch (CryptoTokenAuthenticationFailureException e) {
                    throw new CryptoTokenOfflineException(
                        "Error trying to autoactivating the keystore, wrong password set? "
                        + e.getMessage());
                }
            } else {
                throw new CryptoTokenOfflineException("Signtoken isn't active.");
            }
        }
        KeyEntry entry = entries.get(purpose);
        // If key for 'purpose' not available and no nextKey defined, try with
        // default
        if ((entry == null || entry.getCertificate() == null)
                && !properties.containsKey(NEXTKEY)) {
            entry = entries.get(PURPOSE_SIGN);
        }
        if (entry == null || entry.getCertificate() == null) {
            throw new CryptoTokenOfflineException(
                    "No key available for purpose: " + purpose);
        }
        return entry;
    }

    public Certificate getCertificate(int purpose) throws CryptoTokenOfflineException {
        try {
            final KeyEntry entry = getKeyEntry(purpose);
            Certificate result = entry.getCertificate();

            // Do not return the dummy certificate
            if (result instanceof X509Certificate) {
                if (((X509Certificate) result).getSubjectDN().getName()
                        .contains(SUBJECT_DUMMY)) {
                    result = null;
                }
            }
            return result;
        } catch (CryptoTokenOfflineException ex) {
            return null;
        }
    }

    public Collection<Certificate> getCertificateChain(int purpose) throws CryptoTokenOfflineException {
        final KeyEntry entry = getKeyEntry(purpose);
        List<Certificate> result = entry.getCertificateChain();
        // Do not return the dummy certificate
        if (result.size() == 1) {
            if (result.get(0) instanceof X509Certificate) {
                if (((X509Certificate) result.get(0)).getSubjectDN().getName()
                        .contains(SUBJECT_DUMMY)) {
                    result = null;
                }
            }
        }
        return result;
    }

    /**
     * @see ICryptoToken#genCertificateRequest(
     *  org.signserver.common.ISignerCertReqInfo, boolean)
     */
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info, 
            final boolean explicitEccParameters, final boolean defaultKey)
            throws CryptoTokenOfflineException {
        LOG.debug(">genCertificateRequest");
        Base64SignerCertReqData retval = null;
        if (info instanceof PKCS10CertReqInfo) {
            PKCS10CertReqInfo reqInfo = (PKCS10CertReqInfo) info;
            PKCS10CertificationRequest pkcs10;
            final int purpose = defaultKey
                    ? PURPOSE_SIGN : PURPOSE_NEXTKEY;
            if (LOG.isDebugEnabled()) {
                LOG.debug("Purpose: " + purpose);
                LOG.debug("signatureAlgorithm: "
                        + reqInfo.getSignatureAlgorithm());
                LOG.debug("subjectDN: " + reqInfo.getSubjectDN());
                LOG.debug("explicitEccParameters: " + explicitEccParameters);
            }
            try {
                PublicKey publicKey = getPublicKey(purpose);

                // Handle ECDSA key with explicit parameters
                if (explicitEccParameters
                        && publicKey.getAlgorithm().contains("ECDSA")) {
                     publicKey = ECKeyUtil.publicToExplicitParameters(publicKey,
                             "BC");
                }

                // Generate request
                pkcs10 = new PKCS10CertificationRequest(
                        reqInfo.getSignatureAlgorithm(),
                        CertTools.stringToBcX509Name(reqInfo.getSubjectDN()),
                        publicKey, reqInfo.getAttributes(), getPrivateKey(purpose), getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));
                retval = new Base64SignerCertReqData(Base64.encode(pkcs10.getEncoded()));
            } catch (InvalidKeyException e) {
                LOG.error("Certificate request error: " + e.getMessage(), e);
            } catch (NoSuchAlgorithmException e) {
                LOG.error("Certificate request error: " + e.getMessage(), e);
            } catch (NoSuchProviderException e) {
                LOG.error("Certificate request error: " + e.getMessage(), e);
            } catch (SignatureException e) {
                LOG.error("Certificate request error: " + e.getMessage(), e);
            }

        }
        LOG.debug("<genCertificateRequest");
        return retval;
    }


    /**
     * Method not supported
     */
    public boolean destroyKey(int purpose) {
        return false;
    }

    public Collection<KeyTestResult> testKey(final String alias,
            final char[] authCode) throws CryptoTokenOfflineException,
            KeyStoreException {
        LOG.debug(">testKey");

        final Collection<KeyTestResult> result
                = new LinkedList<KeyTestResult>();

        final byte signInput[] = "Lillan gick on the roaden ut.".getBytes();

        try {

            final KeyStore keystore = getKeystore(keystoretype, keystorepath,
                    authCode == null ? authenticationCode : authCode);

            final Enumeration<String> e = keystore.aliases();
            while( e.hasMoreElements() ) {
                final String keyAlias = e.nextElement();
                if (alias.equalsIgnoreCase(ICryptoToken.ALL_KEYS)
                        || alias.equals(keyAlias)) {
                    if (keystore.isKeyEntry(keyAlias)) {
                        LOG.debug("--keyEntry: " + keyAlias);
                        String status;
                        String publicKeyHash = null;
                        boolean success = false;
                        try {
                            final PrivateKey privateKey = (PrivateKey)
                                    keystore.getKey(keyAlias, authCode);
                            final Certificate entryCert =
                                    keystore.getCertificate(keyAlias);
                            if (entryCert != null) {
                                final KeyPair keyPair = new KeyPair(
                                        entryCert.getPublicKey(), privateKey);
                                publicKeyHash = CryptoTokenBase
                                        .createKeyHash(keyPair.getPublic());
                                final String sigAlg = CryptoTokenBase
                                        .suggestSigAlg(keyPair.getPublic());
                                if (sigAlg == null) {
                                    status = "Unknown key algorithm: "
                                        + keyPair.getPublic().getAlgorithm();
                                } else {
                                    Signature signature = Signature.getInstance(
                                            sigAlg, keystore.getProvider());
                                    signature.initSign(keyPair.getPrivate());
                                    signature.update(signInput);
                                    byte[] signBA = signature.sign();

                                    Signature verifySignature = Signature.getInstance(sigAlg);
                                    verifySignature.initVerify(keyPair.getPublic());
                                    verifySignature.update(signInput);
                                    success = verifySignature.verify(signBA);
                                    status = success
                                            ? "" : "Test signature inconsistent";
                                }
                            } else {
                                status = "Not testing keys with alias "
                                        + keyAlias + ". No certificate exists.";
                            }
                        } catch (ClassCastException ce) {
                            status = "Not testing keys with alias "
                                    + keyAlias + ". Not a private key.";
                        } catch (Exception ex) {
                            LOG.error("Error testing key: " + keyAlias, ex);
                            status = ex.getMessage();
                        }
                        result.add(new KeyTestResult(keyAlias, success, status,
                                publicKeyHash));
                    }
                }
            }
        } catch (CertificateException ex) {
            throw new CryptoTokenOfflineException(ex);
        } catch (NoSuchProviderException ex) {
            throw new CryptoTokenOfflineException(ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoTokenOfflineException(ex);
        } catch (FileNotFoundException ex) {
            throw new CryptoTokenOfflineException(ex);
        } catch (IOException ex) {
            throw new CryptoTokenOfflineException(ex);
        } catch (KeyStoreException ex) {
            throw new CryptoTokenOfflineException(ex);
        }

        return result;
    }

    public void generateKey(String keyAlgorithm, String keySpec, String alias, char[] authCode) throws CryptoTokenOfflineException, IllegalArgumentException {
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

            final KeyStore keystore = getKeystore(keystoretype, keystorepath, 
                    authenticationCode);
            final Provider prov = keystore.getProvider();
            if (LOG.isDebugEnabled()) {
                LOG.debug("provider: " + prov);
            }

            // Generate the key pair
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                        keyAlgorithm, prov);
            
            if ("ECDSA".equals(keyAlgorithm)) {
                kpg.initialize(ECNamedCurveTable.getParameterSpec(keySpec));
            } else {
                kpg.initialize(Integer.valueOf(keySpec));
            }
            
            final String sigAlgName = "SHA1With" + keyAlgorithm;

            LOG.debug("generating...");
            final KeyPair keyPair = kpg.generateKeyPair();
            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = getSelfCertificate("CN=" + alias + ", " + SUBJECT_DUMMY
                    + ", C=SE",
                                      (long)30*24*60*60*365, sigAlgName, keyPair);
            LOG.debug("Creating certificate with entry "+alias+'.');

            keystore.setKeyEntry(alias, keyPair.getPrivate(), authCode, chain);

            keystore.store(new FileOutputStream(new File(keystorepath)), 
                    authenticationCode);

        } catch (Exception ex) {
            LOG.error(ex, ex);
            throw new CryptoTokenOfflineException(ex);
        }
    }

    public KeyStore getKeyStore() throws UnsupportedOperationException,
            CryptoTokenOfflineException, KeyStoreException {
        return ks; // TODO: Should we load it first
    }

    private X509Certificate getSelfCertificate (String myname,
                                                long validity,
                                                String sigAlg,
                                                KeyPair keyPair) throws Exception {
        final long currentTime = new Date().getTime();
        final Date firstDate = new Date(currentTime-24*60*60*1000);
        final Date lastDate = new Date(currentTime + validity * 1000);
        X509V3CertificateGenerator cg = new X509V3CertificateGenerator();
        // Add all mandatory attributes
        cg.setSerialNumber(BigInteger.valueOf(firstDate.getTime()));
        LOG.debug("keystore signing algorithm "+sigAlg);
        cg.setSignatureAlgorithm(sigAlg);
        cg.setSubjectDN(new X500Principal(myname));
        final PublicKey publicKey = keyPair.getPublic();
        if ( publicKey==null ) {
            throw new Exception("Public key is null");
        }
        cg.setPublicKey(publicKey);
        cg.setNotBefore(firstDate);
        cg.setNotAfter(lastDate);
        cg.setIssuerDN(new X500Principal(myname));
        return cg.generate(keyPair.getPrivate(),
                getProvider(PROVIDERUSAGE_SIGN));
    }

    private static KeyStore getKeystore(final String type, final String path,
            final char[] authCode) throws
            KeyStoreException, CertificateException, NoSuchProviderException,
            NoSuchAlgorithmException, FileNotFoundException, IOException {
        final KeyStore result;
        if (TYPE_PKCS12.equalsIgnoreCase(type)) {
            result = KeyStore.getInstance("PKCS12", "BC");
        } else {
            result = KeyStore.getInstance("JKS");
        }

        if (path == null) {
            throw new FileNotFoundException("Missing property "
                    + KeystoreCryptoToken.KEYSTOREPATH + ".");
        }
        InputStream in = null;
        try {
            in = new FileInputStream(path);
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

    private static class KeyEntry {
        private final PrivateKey privateKey;
        private final Certificate certificate;
        private final List<Certificate> certificateChain;

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
        
    }
}
