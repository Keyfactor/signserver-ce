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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;
import javax.net.ssl.*;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.signserver.cli.spi.CommandFailureException;

/**
 * Handles keystore and truststore options from the command line as well
 * as setting them up for use with SSL.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class KeyStoreOptions {

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

    public static List<Option> getKeyStoreOptions() {
        return Arrays.asList(
            new Option(KeyStoreOptions.TRUSTSTORE, true, TEXTS.getString("TRUSTSTORE_DESCRIPTION")),
            new Option(KeyStoreOptions.TRUSTSTOREPWD, true, TEXTS.getString("TRUSTSTOREPWD_DESCRIPTION")),
            new Option(KeyStoreOptions.KEYSTORE, true, TEXTS.getString("KEYSTORE_DESCRIPTION")),
            new Option(KeyStoreOptions.KEYSTOREPWD, true, TEXTS.getString("KEYSTOREPWD_DESCRIPTION")),
            new Option(KeyStoreOptions.KEYALIAS, true, TEXTS.getString("KEYALIAS_DESCRIPTION"))
        );
    }

    private File truststoreFile;
    private String truststorePassword;
    private File keystoreFile;
    private String keystorePassword;
    private String keyAlias;

    private KeyStore truststore;
    private KeyStore keystore;
    private boolean useHTTPS;
    private boolean usePrivateHTTPS;

    public void parseCommandLine(CommandLine line, ConsolePasswordReader passwordReader, PrintStream out)
            throws IOException, NoSuchAlgorithmException, CertificateException,
                   KeyStoreException, CommandFailureException {
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
        if (passwordReader != null) {
            // Prompt for truststore password if not given
            if (truststoreFile != null && truststorePassword == null) {
                for (int i = 0; i < 3; i++) {
                    out.print("Password for truststore: "); 
                    out.flush();
                    truststorePassword = new String(passwordReader.readPassword());
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
            if (keystoreFile != null && keystorePassword == null) {
                for (int i = 0; i < 3; i++) {
                    out.print("Password for keystore: ");
                    out.flush();
                    
                    keystorePassword = new String(passwordReader.readPassword());
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
    
    public void validateOptions() throws IllegalArgumentException {
        if (truststoreFile != null && truststorePassword == null) {
            throw new IllegalArgumentException("Missing -truststorepwd");
        } else if (keystoreFile != null && keystorePassword == null) {
            throw new IllegalArgumentException("Missing -keystorepwd");
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

    public SSLSocketFactory setupHTTPS() {
        // If we should use HTTPS
        if (truststoreFile != null) {
            try {
                truststore = loadKeyStore(truststoreFile, truststorePassword);
            } catch (KeyStoreException | NoSuchAlgorithmException |
                     CertificateException | IOException ex) {
                throw new RuntimeException("Could not load truststore", ex);
            }
        }

        // If we should use client authenticated HTTPS
        if (keystoreFile != null) {
            try {
                keystore = loadKeyStore(keystoreFile, keystorePassword);
            } catch (KeyStoreException | NoSuchAlgorithmException |
                     CertificateException | IOException ex) {
                throw new RuntimeException("Could not load keystore", ex);
            }
        }

        if (truststore == null && keystore == null) {
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
                return setDefaultSocketFactory(truststore, keystore, keyAlias,
                    keystorePassword == null ? null : keystorePassword.toCharArray());
            } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException | UnrecoverableKeyException ex) {
                throw new RuntimeException("Could not setup HTTPS", ex);
            }
        } else {
            return null;
        }
    }

    private static KeyStore loadKeyStore(final File truststoreFile,
            final String truststorePassword) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(truststoreFile), truststorePassword.toCharArray());
        return keystore;
    }

    private static SSLSocketFactory setDefaultSocketFactory(final KeyStore truststore,
            final KeyStore keystore, String keyAlias, char[] keystorePassword) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, UnrecoverableKeyException {

        final TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(truststore);

        final KeyManager[] keyManagers;
        if (keystore == null) {
            keyManagers = null;
        } else {
            if (keyAlias == null) {
                keyAlias = keystore.aliases().nextElement();
            }
            final KeyManagerFactory kKeyManagerFactory
                    = KeyManagerFactory.getInstance("SunX509");
            kKeyManagerFactory.init(keystore, keystorePassword);
            keyManagers = kKeyManagerFactory.getKeyManagers();
            for (int i = 0; i < keyManagers.length; i++) {
                if (keyManagers[i] instanceof X509KeyManager) {
                    keyManagers[i] = new AliasKeyManager(
                            (X509KeyManager) keyManagers[i], keyAlias);
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
    
}
