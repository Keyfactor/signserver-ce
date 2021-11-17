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
package org.signserver.client.cli.defaultimpl;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.ResourceBundle;
import javax.net.ssl.*;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.common.SignServerUtil;

/**
 * Handles keystore and truststore options from the command line as well
 * as setting them up for use with SSL.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class KeyStoreOptions {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(KeyStoreOptions.class);

    /** ResourceBundle with internationalized StringS. */
    private static final ResourceBundle TEXTS = ResourceBundle.getBundle(
            "org/signserver/client/cli/defaultimpl/ResourceBundle");

    /** Default host */
    public static final String DEFAULT_HOST = "localhost";

    /** Default HTTP port. */
    public static final int DEFAULT_HTTP_PORT = 8080;

    /** Default public HTTPS port. */
    public static final int DEFAULT_PUBLIC_HTTPS_PORT = 8442;

    /** Default private HTTPS port. */
    public static final int DEFAULT_PRIVATE_HTTPS_PORT = 8443;

    /** Option TRUSTSTORE. */
    public static final String TRUSTSTORE = "truststore";

    /** Option TRUSTSTOREPWD. */
    public static final String TRUSTSTOREPWD = "truststorepwd";

    /** Option KEYSTORE. */
    public static final String KEYSTORE = "keystore";

    /** Option KEYSTOREPWD. */
    public static final String KEYSTOREPWD = "keystorepwd";

    /** Option KEYALIAS. */
    public static final String KEYALIAS = "keyalias";

    /** Option KEYALIASPROMPT. */
    public static final String KEYALIASPROMPT = "keyaliasprompt";

    /** Option SIGNKEYALIAS. */
    public static final String SIGNKEYALIAS = "signkeyalias";

    /** Option SIGNKEYALIASPROMPT. */
    public static final String SIGNKEYALIASPROMPT = "signkeyaliasprompt";
    
    /** Option KEYSTORETYPE. */
    public static final String KEYSTORETYPE = "keystoretype";

    /** Option SIGN_REQUEST. */
    public static final String SIGN_REQUEST = "signrequest";

    public static final String PASSWORDFROMSTDIN = "passwordfromstdin";

    /** Option NOHTTPS. */
    public static final String NOHTTPS = "nohttps";

    public static List<Option> getKeyStoreOptions() {
        return Arrays.asList(
            new Option(KeyStoreOptions.TRUSTSTORE, true, TEXTS.getString("TRUSTSTORE_DESCRIPTION")),
            new Option(KeyStoreOptions.TRUSTSTOREPWD, true, TEXTS.getString("TRUSTSTOREPWD_DESCRIPTION")),
            new Option(KeyStoreOptions.KEYSTORE, true, TEXTS.getString("KEYSTORE_DESCRIPTION")),
            new Option(KeyStoreOptions.KEYSTOREPWD, true, TEXTS.getString("KEYSTOREPWD_DESCRIPTION")),
            new Option(KeyStoreOptions.KEYALIAS, true, TEXTS.getString("KEYALIAS_DESCRIPTION")),
            new Option(KeyStoreOptions.KEYALIASPROMPT, false, TEXTS.getString("KEYALIASPROMPT_DESCRIPTION")),
            new Option(KeyStoreOptions.SIGNKEYALIAS, true, TEXTS.getString("SIGNKEYALIAS_DESCRIPTION")),
            new Option(KeyStoreOptions.SIGNKEYALIASPROMPT, false, TEXTS.getString("SIGNKEYALIASPROMPT_DESCRIPTION")),
            new Option(KeyStoreOptions.KEYSTORETYPE, true, TEXTS.getString("KEYSTORETYPE_DESCRIPTION")),
            new Option(KeyStoreOptions.PASSWORDFROMSTDIN, false, TEXTS.getString("PASSWORDFROMSTDIN_DESCRIPTION")),
            new Option(KeyStoreOptions.SIGN_REQUEST, false, TEXTS.getString("SIGN_REQUEST_DESCRIPTION")),
            new Option(KeyStoreOptions.NOHTTPS, false, TEXTS.getString("NOHTTPS_DESCRIPTION"))
        );
    }

    private File truststoreFile;
    private String truststorePassword;
    private File keystoreFile;
    private String keystorePassword;
    private String keyAlias;
    private boolean keyAliasPrompt;
    private String signKeyAlias;
    private boolean signKeyAliasPrompt;
    private boolean signRequest;

    private KeystoreType keystoreType;
    private boolean passwordFromStdin;

    private KeyStore truststore;
    private KeyStore keystore;
    private boolean useHTTPS;
    private boolean usePrivateHTTPS;
    private boolean noHTTPS;
    
    private SSLSocketFactory socketFactory;

    public enum KeystoreType {
        JKS,
        PKCS11,
        PKCS11_CONFIG
    }

    public void parseCommandLine(CommandLine line, ConsolePasswordReader passwordReader, PrintStream out)
            throws IOException, NoSuchAlgorithmException, CertificateException,
                   KeyStoreException, CommandFailureException, IllegalCommandArgumentsException {
        if (line.hasOption(KeyStoreOptions.TRUSTSTORE)) {
            truststoreFile = new File(line.getOptionValue(KeyStoreOptions.TRUSTSTORE, null));
        }
        if (line.hasOption(KeyStoreOptions.TRUSTSTOREPWD)) {
            truststorePassword = line.getOptionValue(KeyStoreOptions.TRUSTSTOREPWD, null);
        }
        if (line.hasOption(KeyStoreOptions.KEYSTORE)) {
            keystoreFile = new File(line.getOptionValue(KeyStoreOptions.KEYSTORE, null));
        }
        if (line.hasOption(KeyStoreOptions.KEYSTOREPWD)) {
            keystorePassword = line.getOptionValue(KeyStoreOptions.KEYSTOREPWD, null);
        }
        if (line.hasOption(KeyStoreOptions.KEYALIAS)) {
            keyAlias = line.getOptionValue(KeyStoreOptions.KEYALIAS, null);
        }
        if (line.hasOption(KeyStoreOptions.KEYALIASPROMPT)) {
            keyAliasPrompt = true;

            if (line.hasOption(KeyStoreOptions.KEYALIAS)) {
                throw new IllegalCommandArgumentsException("Can not supply both -keyalias and -keyaliasprompt");
            }
        }
        if (line.hasOption(KeyStoreOptions.SIGNKEYALIAS)) {
            signKeyAlias = line.getOptionValue(KeyStoreOptions.SIGNKEYALIAS, null);
        }
        if (line.hasOption(KeyStoreOptions.SIGNKEYALIASPROMPT)) {
            signKeyAliasPrompt = true;

            if (line.hasOption(KeyStoreOptions.SIGNKEYALIAS)) {
                throw new IllegalCommandArgumentsException("Can not supply both -signkeyalias and -signkeyaliasprompt");
            }
        }
        if (line.hasOption(KeyStoreOptions.SIGN_REQUEST)) {
            signRequest = true;
        }
        if (line.hasOption(KeyStoreOptions.NOHTTPS)) {
            noHTTPS = true;
        }
        if (line.hasOption(KeyStoreOptions.KEYSTORETYPE)) {
            try {
                keystoreType = KeystoreType.valueOf(line.getOptionValue(KeyStoreOptions.KEYSTORETYPE, null));
            } catch (IllegalArgumentException ex) {
                throw new IllegalCommandArgumentsException("Unsupported keystore type. Supported values are: " + Arrays.toString(KeystoreType.values()));
            }
        }
        if (line.hasOption(KeyStoreOptions.PASSWORDFROMSTDIN)) {
            passwordFromStdin = true;
        }

        if (passwordReader != null || passwordFromStdin) {
            // Prompt for truststore password if not given
            if (truststoreFile != null && truststorePassword == null) {
                final String truststorePasswordPrompt = passwordFromStdin ?
                              "Password for truststore (will be echoed): " :
                              "Password for truststore: ";
                for (int i = 0; i < 3; i++) {
                    out.print(truststorePasswordPrompt);
                    out.flush();
                    if (passwordFromStdin) {
                        final BufferedReader reader =
                                new BufferedReader(new InputStreamReader(System.in,
                                                                         StandardCharsets.UTF_8));
                        truststorePassword = reader.readLine();
                    } else {
                        truststorePassword = new String(passwordReader.readPassword());
                    }
                    try {
                        KeyStore keystore = KeyStore.getInstance("JKS");
                        keystore.load(new FileInputStream(truststoreFile), truststorePassword.toCharArray());
                        break;
                    } catch (IOException ex) {
                        if (ex.getCause() instanceof UnrecoverableKeyException) {
                            if (i >= 2) {
                                throw ex;
                            }
                            continue;
                        } else {
                            throw ex;
                        }
                    }
                }
            }
            // Prompt for keystore password if not given
            if (keystoreFile != null && keystorePassword == null && !KeystoreType.PKCS11.equals(keystoreType) && !KeystoreType.PKCS11_CONFIG.equals(keystoreType)) {
                final String keystorePasswordPrompt = passwordFromStdin ?
                              "Password for keystore (will be echoed): " :
                              "Password for keystore: ";

                for (int i = 0; i < 3; i++) {
                    out.print(keystorePasswordPrompt);
                    out.flush();

                    if (passwordFromStdin) {
                        final BufferedReader reader =
                                new BufferedReader(new InputStreamReader(System.in,
                                                                         StandardCharsets.UTF_8));
                        keystorePassword = reader.readLine();
                    } else {
                        keystorePassword = new String(passwordReader.readPassword());
                    }

                    try {
                        KeyStore keystore = KeyStore.getInstance("JKS");
                        keystore.load(new FileInputStream(keystoreFile), keystorePassword.toCharArray());
                        break;
                    } catch (IOException ex) {
                        if (ex.getCause() instanceof UnrecoverableKeyException) {
                            if (i >= 2) {
                                throw ex;
                            }
                            continue;
                        } else {
                            throw ex;
                        }
                    }
                }
            }
        }
    }

    public void validateOptions() throws IllegalCommandArgumentsException {
        if (truststoreFile != null && truststorePassword == null) {
            throw new IllegalCommandArgumentsException("Missing -truststorepwd");
        } else if (keystoreFile != null && keystorePassword == null && !KeystoreType.PKCS11.equals(keystoreType) && !KeystoreType.PKCS11_CONFIG.equals(keystoreType)) {
            throw new IllegalCommandArgumentsException("Missing -keystorepwd");
        }
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public File getKeystoreFile() {
        return keystoreFile;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public File getTruststoreFile() {
        return truststoreFile;
    }

    public String getTruststorePassword() {
        return truststorePassword;
    }

    public boolean isSignRequest() {
        return signRequest;
    }

    private static InputStream createConfigInputStream(KeystoreType keystoreType, File library) throws FileNotFoundException {
        switch (keystoreType) {
            case PKCS11:
                return new ByteArrayInputStream(new StringBuilder()
                        .append("name=PKCS11").append("\n")
                        .append("library=").append(library.getAbsolutePath()).append("\n")
                        .toString().getBytes(StandardCharsets.ISO_8859_1));
            case PKCS11_CONFIG:
                return new BufferedInputStream(new FileInputStream(library));
            default:
                throw new IllegalArgumentException("Unsupported PKCS#11 keystore type: " + keystoreType);
        }
    }

    /**
     * Get the selected client certificate from the keystore, or null if
     * none is selected (no -keystore and -keyalias or -keyaliasprompt)
     *
     * @return The used client certificate from -keystore
     * @throws KeyStoreException 
     */
    public List<Certificate> getClientCertificateChain() throws KeyStoreException {
        return getCertificateChainForAliasOrFirst(keyAlias);
    }

    /**
     * Get the selected request signing certificate from the keystore, or null if
     * none is selected (no -keystore and -keyalias or -keyaliasprompt)
     *
     * @return The used client certificate from -keystore
     * @throws KeyStoreException 
     */
    public List<Certificate> getSignCertificateChain() throws KeyStoreException {
        return getCertificateChainForAliasOrFirst(signKeyAlias);
    }

    /**
     * Gets the certificate chain for a specified key alias, or the chain for
     * the first found alias, if none specified.
     *
     * @param alias alias to return chain for, or null to get first available
     * @return certificate chain, or null if the keystore is not loaded
     * @throws KeyStoreException 
     */
    private List<Certificate> getCertificateChainForAliasOrFirst(final String alias)
            throws KeyStoreException {
        if (keystore != null) {
            final String aliasToUse =
                    alias != null ? alias : keystore.aliases().nextElement();
            final Certificate[] certs = keystore.getCertificateChain(aliasToUse);
            
            return certs != null ? Arrays.asList(certs) : null;
        } else {
            return null;
        }
    }

    public PrivateKey getPrivateKey() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return getPrivateKeyForAliasOrFirst(keyAlias);
    }

    public PrivateKey getSignPrivateKey() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return getPrivateKeyForAliasOrFirst(signKeyAlias);
    }
    
    private PrivateKey getPrivateKeyForAliasOrFirst(final String alias)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (keystore != null) {
            final String aliasToUse =
                    alias != null ? alias : keystore.aliases().nextElement();

            if (LOG.isDebugEnabled()) {
                LOG.debug("Attempting to use alias: " + aliasToUse);
            }

            return (PrivateKey) keystore.getKey(aliasToUse,
                                                keystorePassword.toCharArray());
        } else {
            return null;
        }
    }
    
    /**
     * Suggest a signature algorithm expected to work with the provided public
     * key.
     *
     * @param publicKey public key the algorithm should work with
     * @return an algorithm name
     */
    public static String suggestSignatureAlgorithm(PublicKey publicKey) {
        final String result;
        final String digestAlgorithm = "SHA256";
        switch (publicKey.getAlgorithm()) {
            case "EC":
            case "ECDSA":
                result = digestAlgorithm + "withECDSA";
                break;
            case "DSA":
                result = digestAlgorithm + "withDSA";
                break;
            case "RSA":
                result = digestAlgorithm + "withRSA";
                break;
            default:
                throw new UnsupportedOperationException("Unsupported algorithm: " + publicKey.getAlgorithm());
        }
        return result;
    }

    /**
     * Setup HTTPS with or without client authentication if it has not already been done.
     * 
     * Note: this method is thread-safe and only the first call actually setups HTTPS.
     *
     * @param passwordReader to ask for password and which key alias to use etc
     * @param out to write out question about password etc
     * @return the SSLSocketFactory
     */
    public synchronized SSLSocketFactory setupHTTPS(final ConsolePasswordReader passwordReader, final PrintStream out) {
        if (socketFactory == null) {
            // If we should use HTTPS
            if (truststoreFile != null) {
                try {
                    truststore = loadKeyStore(truststoreFile, truststorePassword);
                } catch (KeyStoreException | NoSuchAlgorithmException |
                         CertificateException | IOException ex) {
                    throw new RuntimeException("Could not load truststore", ex);
                }
            }

            SignServerUtil.installBCProvider();

            // If we should use client authenticated HTTPS
            if (keystoreFile != null) {
                try {
                    if (KeystoreType.PKCS11.equals(keystoreType) || KeystoreType.PKCS11_CONFIG.equals(keystoreType)) {
                        final KeyStore.ProtectionParameter pp;
                        if (keystorePassword == null) {
                            pp = new KeyStore.CallbackHandlerProtection(new CallbackHandler() {

                                @Override
                                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                                    for (Callback callback : callbacks) {
                                        if (callback instanceof PasswordCallback) {
                                            try {
                                                final PasswordCallback pc = (PasswordCallback) callback;
                                                final String keystorePasswordPrompt =
                                                        passwordFromStdin ?
                                                        "Password for PKCS#11 keystore (" + keystoreFile.getName() + "): (will be echoed): " :
                                                        "Password for PKCS#11 keystore (" + keystoreFile.getName() + "): ";
                                                out.print(keystorePasswordPrompt);
                                                out.flush();

                                                if (passwordFromStdin) {
                                                    final BufferedReader reader =
                                                            new BufferedReader(new InputStreamReader(System.in,
                                                                         StandardCharsets.UTF_8));
                                                    keystorePassword = reader.readLine();
                                                } else {
                                                    keystorePassword = new String(passwordReader.readPassword());
                                                }

                                                if (keystorePassword != null) {
                                                    pc.setPassword(keystorePassword.toCharArray());
                                                }
                                            } catch (CommandFailureException ex) {
                                                throw new IOException(ex);
                                            }
                                        } else {
                                            throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
                                        }
                                    }
                                }
                            });
                        } else {
                            pp = new KeyStore.PasswordProtection(keystorePassword.toCharArray());
                        }
                        keystore = getLoadedKeystorePKCS11(keystoreType, keystoreFile, keystorePassword != null ? keystorePassword.toCharArray() : null, pp);
                    } else {
                        keystore = loadKeyStore(keystoreFile, keystorePassword);
                    }
                } catch (KeyStoreException | NoSuchAlgorithmException |
                         CertificateException | IOException ex) {
                    throw new RuntimeException("Could not load keystore", ex);
                }
            }

            if (noHTTPS) {
                useHTTPS = false;
            } else if (truststore == null && keystore == null) {
                useHTTPS = false;
            } else if (keystore == null) {
                useHTTPS = true;
            } else {
                if (truststore == null) {
                    truststore = keystore;
                }
                useHTTPS = true;
                usePrivateHTTPS = true;
            }

            if (useHTTPS) {
                try {
                    this.socketFactory = setDefaultSocketFactory(truststore, keystore, keyAlias, keyAliasPrompt,
                        keystorePassword == null ? null : keystorePassword.toCharArray(), out);
                } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException | UnrecoverableKeyException ex) {
                    throw new RuntimeException("Could not setup HTTPS", ex);
                }
            }
        }

        if (signKeyAliasPrompt && signKeyAlias == null) {
            try {
                final String[] validAliases =
                        Collections.list(keystore.aliases()).toArray(new String[0]);
                final String selectedAlias =
                        PromptUtils.chooseAlias(validAliases, out,
                                                "Choose private key to sign request with: ");

                if (selectedAlias != null) {
                    signKeyAlias = selectedAlias;
                }
            } catch (KeyStoreException ex) {
                throw new RuntimeException("Could not load keystore", ex);
            }
        }
        
        return this.socketFactory;
    }

    private static KeyStore loadKeyStore(final File truststoreFile,
            final String truststorePassword) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(truststoreFile), truststorePassword.toCharArray());
        return keystore;
    }

    private static SSLSocketFactory setDefaultSocketFactory(final KeyStore truststore,
            final KeyStore keystore, String keyAlias, boolean keyAliasPrompt, char[] keystorePassword, PrintStream out) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, UnrecoverableKeyException {

        final TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(truststore);

        final KeyManager[] keyManagers;
        if (keystore == null) {
            keyManagers = null;
        } else {
            final KeyManagerFactory kKeyManagerFactory
                    = KeyManagerFactory.getInstance("SunX509");
            kKeyManagerFactory.init(keystore, keystorePassword);
            keyManagers = kKeyManagerFactory.getKeyManagers();

            
            if (keyAliasPrompt) {
                for (int i = 0; i < keyManagers.length; i++) {
                    if (keyManagers[i] instanceof X509KeyManager) {
                        keyManagers[i] = new CliKeyManager(
                                (X509KeyManager) keyManagers[i], out);
                    }
                }
            } else {
                if (keyAlias == null) {
                    keyAlias = keystore.aliases().nextElement();
                }
                for (int i = 0; i < keyManagers.length; i++) {
                    if (keyManagers[i] instanceof X509KeyManager) {
                        keyManagers[i] = new AliasKeyManager(
                                (X509KeyManager) keyManagers[i], keyAlias);
                    }
                }
            }
        }

        final SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagers, tmf.getTrustManagers(), new SecureRandom());

        SSLSocketFactory factory = context.getSocketFactory();

        return factory;
    }

    public boolean isUseHTTPS() {
        return useHTTPS;
    }

    public boolean isUsePrivateHTTPS() {
        return usePrivateHTTPS;
    }

    public void setUsePrivateHTTPS(boolean usePrivateHTTPS) {
        this.usePrivateHTTPS = usePrivateHTTPS;
    }

    public KeystoreType getKeystoreType() {
        return keystoreType;
    }

    public void setKeystoreType(KeystoreType keystoreType) {
        this.keystoreType = keystoreType;
    }

    private static KeyStore getLoadedKeystorePKCS11(final KeystoreType keystoreType, final File library, final char[] authCode, final KeyStore.ProtectionParameter protectionParameter) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keystore;

        try (final InputStream config = createConfigInputStream(keystoreType, library)) {
                final Class<?> klass = Class.forName("sun.security.pkcs11.SunPKCS11");
                Provider provider;

                try {
                    /* try getting the Java 9+ configure method first
                     * if this fails, fall back to the old way, calling the
                     * constructor
                     */
                    final Class[] paramString = new Class[1];
                    paramString[0] = String.class;
                    final Method method =
                            Provider.class.getDeclaredMethod("configure",
                                                             paramString);
                    final String configString =
                            getSunP11ConfigStringFromInputStream(config);

                    provider = getPKCS11ProviderUsingConfigMethod(method, configString);
                } catch (NoSuchMethodException e) {
                    // find constructor taking one argument of type InputStream
                    Class<?>[] parTypes = new Class[1];
                    parTypes[0] = InputStream.class;

                    Constructor<?> ctor = klass.getConstructor(parTypes);
                    Object[] argList = new Object[1];
                    argList[0] = config;
                    provider = (Provider) ctor.newInstance(argList);
                }

                Security.addProvider(provider);

                final KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11",
                        provider, protectionParameter);

                keystore = builder.getKeyStore();
                keystore.load(null, authCode);

                final Enumeration<String> e = keystore.aliases();
                while( e.hasMoreElements() ) {
                    final String keyAlias = e.nextElement();
                    if (LOG.isDebugEnabled()) {
                        X509Certificate cert = (X509Certificate) keystore.getCertificate(keyAlias);
                        LOG.debug("******* keyAlias: " + keyAlias
                                + ", certificate: "
                                + (cert == null ? "null" : cert.getSubjectDN().getName()));
                    }
                }
                //LOADED_KESTORES.put(keystoreName, keystore);
        } catch (NoSuchMethodException nsme) {
            throw new KeyStoreException("Could not find constructor for keystore provider", nsme);
        } catch (InstantiationException ie) {
            throw new KeyStoreException("Failed to instantiate keystore provider", ie);
        } catch (ClassNotFoundException ncdfe) {
            throw new KeyStoreException("Unsupported keystore provider", ncdfe);
        } catch (InvocationTargetException ite) {
            throw new KeyStoreException("Could not initialize provider", ite);
        } catch (Exception e) {
            throw new KeyStoreException("Error", e);
        }

        return keystore;
    }

    private static Provider getPKCS11ProviderUsingConfigMethod(final Method configMethod,
                                                               final String config)
            throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        final Provider prototype = Security.getProvider("SunPKCS11");
        final Provider provider = (Provider) configMethod.invoke(prototype, config);

        return provider;
    }

    private static String getSunP11ConfigStringFromInputStream(final InputStream is) throws IOException {
        final StringBuilder configBuilder = new StringBuilder();

        /* we need to prepend -- to indicate to the configure() method
         * that the config is treated as a string
         */
        configBuilder.append("--").append(IOUtils.toString(is, StandardCharsets.ISO_8859_1));

        return configBuilder.toString();
    }
}
