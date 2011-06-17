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
package org.signserver.client.cli;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.xml.ws.soap.SOAPFaultException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;

/**
 * Command Line Interface (CLI) for signing documents.
 *
 * @author Markus Kilas
 * @version $Id$
 */
public class DocumentSignerCLI {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DocumentSignerCLI.class);

    /** ResourceBundle with internationalized StringS. */
    private static final ResourceBundle TEXTS = ResourceBundle.getBundle(
            "org/signserver/client/cli/ResourceBundle");

    /** System-specific new line characters. **/
    private static final String NL = System.getProperty("line.separator");

    /** The name of this command. */
    private static final String COMMAND = "signdocument";

    /** Option WORKERID. */
    public static final String WORKERID = "workerid";

    /** Option WORKERNAME. */
    public static final String WORKERNAME = "workername";

    /** Option DATA. */
    public static final String DATA = "data";

    /** Option HOST. */
    public static final String HOST = "host";

    /** Option INFILE. */
    public static final String INFILE = "infile";

    /** Option OUTFILE. */
    public static final String OUTFILE = "outfile";

    /** Option PORT. */
    public static final String PORT = "port";

    public static final String SERVLET = "servlet";

    /** Option PROTOCOL. */
    public static final String PROTOCOL = "protocol";

    /** Option USERNAME. */
    public static final String USERNAME = "username";

    /** Option PASSWORD. */
    public static final String PASSWORD = "password";

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

    /** Default host */
    private static final String DEFAULT_HOST = "localhost";

    /** Default HTTP port. */
    private static final int DEFAULT_HTTP_PORT = 8080;

    /** Default public HTTPS port. */
    private static final int DEFAULT_PUBLIC_HTTPS_PORT = 8442;

    /** Default private HTTPS port. */
    private static final int DEFAULT_PRIVATE_HTTPS_PORT = 8443;

    /** The command line options. */
    private static final Options OPTIONS;

    /**
     * Protocols that can be used for accessing SignServer.
     */
    public static enum Protocol {
        /** The Web Services interface. */
        WEBSERVICES,

        /** The HTTP interface. */
        HTTP
    }

    static {
        OPTIONS = new Options();
        OPTIONS.addOption(WORKERID, true,
                TEXTS.getString("WORKERID_DESCRIPTION"));
        OPTIONS.addOption(WORKERNAME, true,
                TEXTS.getString("WORKERNAME_DESCRIPTION"));
        OPTIONS.addOption(DATA, true,
                TEXTS.getString("DATA_DESCRIPTION"));
        OPTIONS.addOption(INFILE, true,
                TEXTS.getString("INFILE_DESCRIPTION"));
        OPTIONS.addOption(OUTFILE, true,
                TEXTS.getString("OUTFILE_DESCRIPTION"));
        OPTIONS.addOption(HOST, true,
                TEXTS.getString("HOST_DESCRIPTION"));
        OPTIONS.addOption(PORT, true,
                TEXTS.getString("PORT_DESCRIPTION"));
        OPTIONS.addOption(SERVLET, true,
                TEXTS.getString("SERVLET_DESCRIPTION"));
        OPTIONS.addOption(PROTOCOL, true,
                TEXTS.getString("PROTOCOL_DESCRIPTION"));
        OPTIONS.addOption(TRUSTSTORE, true,
                TEXTS.getString("TRUSTSTORE_DESCRIPTION"));
        OPTIONS.addOption(TRUSTSTOREPWD, true,
                TEXTS.getString("TRUSTSTOREPWD_DESCRIPTION"));
        OPTIONS.addOption(KEYSTORE, true,
                TEXTS.getString("KEYSTORE_DESCRIPTION"));
        OPTIONS.addOption(KEYSTOREPWD, true,
                TEXTS.getString("KEYSTOREPWD_DESCRIPTION"));
        OPTIONS.addOption(KEYALIAS, true,
                TEXTS.getString("KEYALIAS_DESCRIPTION"));
        OPTIONS.addOption(USERNAME, true, "Username for authentication.");
        OPTIONS.addOption(PASSWORD, true, "Password for authentication.");
    }

    /** ID of worker who should perform the operation. */
    private transient int workerId;

    /** Name of worker who should perform the operation. */
    private transient String workerName;

    /** Data to sign. */
    private transient String data;

    /** Hostname or IP address of the SignServer host. */
    private transient String host;

    /** TCP port number of the SignServer host. */
    private transient Integer port;

    private transient String servlet = "/signserver/process";

    /** File to read the data from. */
    private transient File inFile;

    /** File to read the signed data to. */
    private transient File outFile;

    /** Protocol to use for contacting SignServer. */
    private transient Protocol protocol;

    private transient String username;
    private transient String password;

    private transient File truststoreFile;
    private transient String truststorePassword;

    private transient File keystoreFile;
    private transient String keystorePassword;
    private transient String keyAlias;

    /**
     * Creates an instance of DocumentSignerCLI.
     *
     * @param args Command line arguments
     */
    public DocumentSignerCLI(final String[] args) {
        try {
            // Parse the command line
            parseCommandLine(new GnuParser().parse(OPTIONS, args));
        } catch (ParseException ex) {
            throw new IllegalArgumentException(ex.getLocalizedMessage(), ex);
        }
        validateOptions();
    }

    /**
     * Reads all the options from the command line.
     *
     * @param line The command line to read from
     */
    private void parseCommandLine(final CommandLine line) {
        if (line.hasOption(WORKERID)) {
                workerId = Integer.parseInt(line.getOptionValue(
                    WORKERID, null));
        }
        if (line.hasOption(WORKERNAME)) {
            workerName = line.getOptionValue(WORKERNAME, null);
        }
        if (line.hasOption(WORKERID)) {
            workerId = Integer.parseInt(line.getOptionValue(WORKERID, null));
        }
        host = line.getOptionValue(HOST, DEFAULT_HOST);
        if (line.hasOption(PORT)) {
            port = Integer.parseInt(line.getOptionValue(PORT));
        }
        if (line.hasOption(SERVLET)) {
            servlet = line.getOptionValue(SERVLET, null);
        }
        if (line.hasOption(DATA)) {
            data = line.getOptionValue(DATA, null);
        }
        if (line.hasOption(INFILE)) {
            inFile = new File(line.getOptionValue(INFILE, null));
        }
        if (line.hasOption(OUTFILE)) {
            outFile = new File(line.getOptionValue(OUTFILE, null));
        }
        if (line.hasOption(PROTOCOL)) {
            protocol = Protocol.valueOf(line.getOptionValue(
                    PROTOCOL, null));
        }
        if (line.hasOption(USERNAME)) {
            username = line.getOptionValue(USERNAME, null);
        }
        if (line.hasOption(PASSWORD)) {
            password = line.getOptionValue(PASSWORD, null);
        }
        if (line.hasOption(TRUSTSTORE)) {
            truststoreFile = new File(line.getOptionValue(TRUSTSTORE, null));
        }
        if (line.hasOption(TRUSTSTOREPWD)) {
            truststorePassword = line.getOptionValue(TRUSTSTOREPWD, null);
        }
        if (line.hasOption(KEYSTORE)) {
            keystoreFile = new File(line.getOptionValue(KEYSTORE, null));
        }
        if (line.hasOption(KEYSTOREPWD)) {
            keystorePassword = line.getOptionValue(KEYSTOREPWD, null);
        }
        if (line.hasOption(KEYALIAS)) {
            keyAlias = line.getOptionValue(KEYALIAS, null);
        }
    }

    /**
     * Checks that all mandadory options are given.
     */
    private void validateOptions() {
        if (workerName == null && workerId == 0) {
            throw new IllegalArgumentException(
                    "Missing -workername or -workerid");
        } else if (data == null && inFile == null) {
            throw new IllegalArgumentException("Missing -data or -infile");
        } else if (truststoreFile != null && truststorePassword == null) {
            throw new IllegalArgumentException("Missing -truststorepwd");
        } else if (keystoreFile != null && keystorePassword == null) {
            throw new IllegalArgumentException("Missing -keystorepwd");
        }
    }

    /**
     * Creates a DocumentSigner using the choosen protocol.
     *
     * @return a DocumentSigner using the choosen protocol
     * @throws MalformedURLException in case an URL can not be constructed
     * using the given host and port
     */
    private DocumentSigner createSigner() throws MalformedURLException {
        final DocumentSigner signer;
        
        final String workerIdOrName;
        if (workerId == 0) {
            workerIdOrName = workerName;
        } else {
            workerIdOrName = String.valueOf(workerId);
        }

        // If we should use HTTPS
        KeyStore truststore = null;
        if (truststoreFile != null) {
            try {
                truststore = loadKeyStore(truststoreFile, truststorePassword);
            } catch (KeyStoreException ex) {
                throw new RuntimeException("Could not load truststore", ex);
            } catch (FileNotFoundException ex) {
                throw new RuntimeException("Could not load truststore", ex);
            } catch (IOException ex) {
                throw new RuntimeException("Could not load truststore", ex);
            } catch (NoSuchAlgorithmException ex) {
                throw new RuntimeException("Could not load truststore", ex);
            } catch (CertificateException ex) {
                throw new RuntimeException("Could not load truststore", ex);
            }
        }

        // If we should use client authenticated HTTPS
        KeyStore keystore = null;
        if (keystoreFile != null) {
            try {
                keystore = loadKeyStore(keystoreFile, keystorePassword);
            } catch (KeyStoreException ex) {
                throw new RuntimeException("Could not load keystore", ex);
            } catch (FileNotFoundException ex) {
                throw new RuntimeException("Could not load keystore", ex);
            } catch (IOException ex) {
                throw new RuntimeException("Could not load keystore", ex);
            } catch (NoSuchAlgorithmException ex) {
                throw new RuntimeException("Could not load keystore", ex);
            } catch (CertificateException ex) {
                throw new RuntimeException("Could not load keystore", ex);
            }
        }

        final boolean useHTTPS;

        if (truststore == null && keystore == null) {
            useHTTPS = false;
            if (port == null) {
                port = DEFAULT_HTTP_PORT;
            }
        } else if (keystore == null) {
            useHTTPS = true;
            if (port == null) {
                port = DEFAULT_PUBLIC_HTTPS_PORT;
            }
        } else {
            if (truststore == null) {
                truststore = keystore;
            }
            useHTTPS = true;
            if (port == null) {
                port = DEFAULT_PRIVATE_HTTPS_PORT;
            }
        }

        if (useHTTPS) {
            try {
                setDefaultSocketFactory(truststore, keystore, keyAlias,
                        keystorePassword.toCharArray());
            } catch (NoSuchAlgorithmException ex) {
                throw new RuntimeException("Could not setup HTTPS", ex);
            } catch (KeyStoreException ex) {
                throw new RuntimeException("Could not setup HTTPS", ex);
            } catch (KeyManagementException ex) {
                throw new RuntimeException("Could not setup HTTPS", ex);
            } catch (UnrecoverableKeyException ex) {
                throw new RuntimeException("Could not setup HTTPS", ex);
            }
        }

        if (Protocol.WEBSERVICES.equals(protocol)) {
            LOG.debug("Using WebServices as procotol");
            signer = new WebServicesDocumentSigner(
                host,
                port,
                workerIdOrName,
                useHTTPS,
                username,
                password);
        } else {
            LOG.debug("Using HTTP as procotol");
            signer = new HTTPDocumentSigner(
                new URL(useHTTPS ? "https" : "http", host, port, servlet),
                workerIdOrName, username, password);
        }
        return signer;
    }

    private KeyStore loadKeyStore(final File truststoreFile,
            final String truststorePassword) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(truststoreFile), truststorePassword.toCharArray());
        return keystore;
    }

    private static void setDefaultSocketFactory(final KeyStore truststore,
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
        HttpsURLConnection.setDefaultSSLSocketFactory(factory);
    }

    /**
     * Execute the signing operation.
     */
    public final void run() {
        FileInputStream fin = null;
        try {
            final byte[] bytes;

            Map<String, Object> requestContext = new HashMap<String, Object>();
            if (inFile == null) {
                bytes = data.getBytes();
            } else {
                requestContext.put("FILENAME", inFile.getName());
                fin = new FileInputStream(inFile);
                bytes = new byte[(int) inFile.length()];
                fin.read(bytes);
            }

            OutputStream out = null;
            try {
                if (outFile == null) {
                    out = System.out;
                } else {
                    out = new FileOutputStream(outFile);
                }
                createSigner().sign(bytes, out, requestContext);
            } finally {
                if (out != null) {
                    out.close();
                }
            }

        } catch (FileNotFoundException ex) {
            LOG.error(MessageFormat.format(TEXTS.getString("FILE_NOT_FOUND:"),
                    ex.getLocalizedMessage()));
        } catch (IllegalRequestException ex) {
            LOG.error(ex);
        } catch (CryptoTokenOfflineException ex) {
            LOG.error(ex);
        } catch (SignServerException ex) {
            LOG.error(ex);
        } catch (SOAPFaultException ex) {
            if (ex.getCause() instanceof AuthorizationRequiredException) {
                final AuthorizationRequiredException authEx =
                        (AuthorizationRequiredException) ex.getCause();
                LOG.error("Authorization required: " + authEx.getMessage());
            }
            LOG.error(ex);
        } catch (IOException ex) {
            LOG.error(ex);
        } finally {
            if (fin != null) {
                try {
                    fin.close();
                } catch (IOException ex) {
                    LOG.error("Error closing file", ex);
                }
            }
        }
    }

    /**
     * @param args the command line arguments
     */
    public static void main(final String[] args) {
        try {
            final DocumentSignerCLI cli = new DocumentSignerCLI(args);
            cli.run();
        } catch (IllegalArgumentException ex) {
            LOG.error(ex);
            final StringBuilder buff = new StringBuilder();
            buff.append(NL)
                .append("Sample usages:").append(NL)
                .append("a) ").append(COMMAND).append(" -workername XMLSigner -data \"<root/>\"").append(NL)
                .append("b) ").append(COMMAND).append(" -workername XMLSigner -infile /tmp/document.xml").append(NL)
                .append("c) ").append(COMMAND).append(" -workerid 2 -data \"<root/>\" -truststore truststore.jks -truststorepwd changeit").append(NL)
                .append("d) ").append(COMMAND).append(" -workerid 2 -data \"<root/>\" -keystore superadmin.jks -truststorepwd foo123").append(NL);
            final String footer = buff.toString();
            final HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("signdocument <-workername WORKERNAME | -workerid WORKERID> [options]", 
                    "Request a document to be signed by SignServer", OPTIONS, footer);
        }
    }
}
