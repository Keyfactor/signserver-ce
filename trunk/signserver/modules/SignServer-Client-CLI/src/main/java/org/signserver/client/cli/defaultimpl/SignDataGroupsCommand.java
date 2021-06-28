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

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import org.apache.commons.cli.*;
import org.apache.log4j.Logger;
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.client.cli.ClientCLI;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;

/**
 * Command Line Interface (CLI) for signing MRTD SODs.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SignDataGroupsCommand extends AbstractCommand {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SignDataGroupsCommand.class);

    /** ResourceBundle with internationalized StringS. */
    private static final ResourceBundle TEXTS = ResourceBundle.getBundle(
            "org/signserver/client/cli/defaultimpl/ResourceBundle");

    /** System-specific new line characters. **/
    private static final String NL = System.getProperty("line.separator");

    /** The name of this command. */
    private static final String COMMAND = "signdatagroups";

    /** Option WORKERID. */
    public static final String WORKERID = "workerid";

    /** Option WORKERNAME. */
    public static final String WORKERNAME = "workername";

    /** Option DATA. */
    public static final String DATA = "data";

    /** Option ENCODING. */
    public static final String ENCODING = "encoding";

    /** Option HOST. */
    public static final String HOST = "host";

    /** Option PORT. */
    public static final String PORT = "port";

    public static final String SERVLET = "servlet";

    /** Option PROTOCOL. */
    public static final String PROTOCOL = "protocol";

    /** Option USERNAME. */
    public static final String USERNAME = "username";

    /** Option PASSWORD. */
    public static final String PASSWORD = "password";

    /** Option REPEAT. */
    public static final String REPEAT = "repeat";
    
    /** Option METADATA. */
    public static final String METADATA = "metadata";

    /** The command line options. */
    private static final Options OPTIONS;
    
    private static final String DEFAULT_CLIENTWS_WSDL_URL = "/signserver/ClientWSService/ClientWS?wsdl";

    /**
     * Protocols that can be used for accessing SignServer.
     */
    public static enum Protocol {
        /** The HTTP interface. */
        HTTP,
        
        /** The ClientWS interface. */
        CLIENTWS
    }

    static {
        OPTIONS = new Options();
        OPTIONS.addOption(WORKERID, true,
                TEXTS.getString("WORKERID_DESCRIPTION"));
        OPTIONS.addOption(WORKERNAME, true,
                TEXTS.getString("WORKERNAME_DESCRIPTION"));
        OPTIONS.addOption(DATA, true,
                TEXTS.getString("DATA_DESCRIPTION"));
        OPTIONS.addOption(ENCODING, true,
                TEXTS.getString("ENCODING_DESCRIPTION"));
        OPTIONS.addOption(HOST, true,
                TEXTS.getString("HOST_DESCRIPTION"));
        OPTIONS.addOption(PORT, true,
                TEXTS.getString("PORT_DESCRIPTION"));
        OPTIONS.addOption(SERVLET, true,
                TEXTS.getString("SERVLET_SOD_DESCRIPTION"));
        OPTIONS.addOption(PROTOCOL, true,
                TEXTS.getString("PROTOCOL_SOD_DESCRIPTION"));
        OPTIONS.addOption(USERNAME, true, TEXTS.getString("USERNAME_DESCRIPTION"));
        OPTIONS.addOption(PASSWORD, true, TEXTS.getString("PASSWORD_DESCRIPTION"));
        OPTIONS.addOption(REPEAT, true, TEXTS.getString("REPEAT_DESCRIPTION"));
        OPTIONS.addOption(METADATA, true,
                TEXTS.getString("METADATA_DESCRIPTION"));
        for (Option option : KeyStoreOptions.getKeyStoreOptions()) {
            OPTIONS.addOption(option);
        }
    }

    /** ID of worker who should perform the operation. */
    private int workerId;

    /** Name of worker who should perform the operation. */
    private String workerName;

    /** Data to sign. */
    private String data;

    /** Encoding of the data, if the data should be decoded before signing. */
    private String encoding;

    /** Hostname or IP address of the SignServer host. */
    private String host;

    /** TCP port number of the SignServer host. */
    private Integer port;

    private String servlet;
    
    private static final String DEFAULT_SERVLET = "/signserver/sod";

    /** File to read the data from. */
    private File inFile;  //NOPMD //TODO Add support for reading from file

    /** Protocol to use for contacting SignServer. */
    private Protocol protocol = Protocol.HTTP;

    private String username;

    private String password;

    private Map<Integer,byte[]> dataGroups;

    private int repeat = 1;

    private final KeyStoreOptions keyStoreOptions = new KeyStoreOptions();

    private Map<String, String> metadata;

    @Override
    public String getDescription() {
        return "Request MRTD data groups to be signed";
    }

    @Override
    public String getUsages() {
        StringBuilder footer = new StringBuilder();
        footer.append(NL)
                .append("Sample usages:").append(NL)
                .append("a) ").append(COMMAND).append(" -workername MRTDSODSigner -data \"1=value1&2=value2&3=value3\"").append(NL)
                .append("b) ").append(COMMAND).append(" -workername MRTDSODSigner -data \"1=PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=&2=BTfUgfc6dXM0MoBS2jr5YmztlwKOILhJ9hFcIs12UZc=&3=idxq5/Bqn0a1Za8D6rDs4L9gJNNlm346HQNXPP6wtZ0=\"").append(NL)
                .append("c) ").append(COMMAND).append(" -workername MRTDSODSigner -data \"1=value1&2=value2&3=value3\" -metadata param1=value1 -metadata param2=value2").append(NL);
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        final HelpFormatter formatter = new HelpFormatter();
        try (PrintWriter pw = new PrintWriter(bout)) {
            formatter.printHelp(pw, HelpFormatter.DEFAULT_WIDTH, "signdatagroups <options>", getDescription(), OPTIONS, HelpFormatter.DEFAULT_LEFT_PAD, HelpFormatter.DEFAULT_DESC_PAD, footer.toString());
        }
        return bout.toString();
    }

    /**
     * Reads all the options from the command line.
     *
     * @param line The command line to read from
     */
    private void parseCommandLine(final CommandLine line)
            throws IllegalCommandArgumentsException, CommandFailureException {
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
        host = line.getOptionValue(HOST, KeyStoreOptions.DEFAULT_HOST);
        if (line.hasOption(PORT)) {
            port = Integer.parseInt(line.getOptionValue(PORT));
        }
        if (line.hasOption(SERVLET)) {
            servlet = line.getOptionValue(SERVLET, null);
        }
        if (line.hasOption(DATA)) {
            data = line.getOptionValue(DATA, "");

            dataGroups = new HashMap<>();

            final String[] groups = data.split("\\&");
            for(final String group : groups) {
                final String[] entry = group.split("=", 2);
                if (entry.length != 2) {
                    throw new IllegalCommandArgumentsException("Malformed data group argument: " + group);
                }
                dataGroups.put(new Integer(entry[0]), entry[1].getBytes());
            }
        }
        if (line.hasOption(PROTOCOL)) {
            protocol = Protocol.valueOf(line.getOptionValue(
                    PROTOCOL, null));
            
            if ((Protocol.CLIENTWS.equals(protocol)) &&
            	!line.hasOption(SERVLET)) {
            	servlet = DEFAULT_CLIENTWS_WSDL_URL;
            }
        }
        if (line.hasOption(USERNAME)) {
            username = line.getOptionValue(USERNAME, null);
        }
        if (line.hasOption(PASSWORD)) {
            password = line.getOptionValue(PASSWORD, null);
        }
        if (line.hasOption(ENCODING)) {
            encoding = line.getOptionValue(ENCODING, null);
        }
        if (line.hasOption(REPEAT)) {
            repeat = Integer.parseInt(line.getOptionValue(REPEAT));
        }
        if (line.hasOption(METADATA)) {
            metadata = MetadataParser.parseMetadata(line.getOptionValues(METADATA));
        }
        try {
            final ConsolePasswordReader passwordReader = createConsolePasswordReader();
            keyStoreOptions.parseCommandLine(line, passwordReader, out);

            // Prompt for user password if not given
            if (username != null && password == null) {
                out.print("Password for user '" + username + "': ");
                out.flush();
                password = new String(passwordReader.readPassword());
            }
        } catch (IOException ex) {
            throw new IllegalCommandArgumentsException("Failed to read password: " + ex.getLocalizedMessage());
        } catch (NoSuchAlgorithmException | CertificateException | KeyStoreException ex) {
            throw new IllegalCommandArgumentsException("Failure setting up keystores: " + ex.getMessage());
        }
    }
    
    /**
     * @return a ConsolePasswordReader that can be used to read passwords
     */
    protected ConsolePasswordReader createConsolePasswordReader() {
        return new DefaultConsolePasswordReader();
    }

    /**
     * Checks that all mandatory options are given.
     */
    private void validateOptions() throws ParseException, IllegalCommandArgumentsException {
        if (workerName == null && workerId == 0) {
            throw new ParseException(
                    "Missing -workername or -workerid");
        } else if (data == null) {
            throw new ParseException("Missing -data");
        }
        keyStoreOptions.validateOptions();
    }

    /**
     * Creates a DocumentSigner using the choosen protocol.
     *
     * @return a DocumentSigner using the choosen protocol
     * @throws MalformedURLException in case an URL can not be constructed
     * using the given host and port
     */
    private SODSigner createSigner() throws MalformedURLException {
        final SODSigner signer;

        final SSLSocketFactory sf = keyStoreOptions.setupHTTPS(createConsolePasswordReader(), out);
        
        if (sf != null) {
            HttpsURLConnection.setDefaultSSLSocketFactory(sf);
        }

        if (port == null) {
            if (keyStoreOptions.isUsePrivateHTTPS()) {
                port = KeyStoreOptions.DEFAULT_PRIVATE_HTTPS_PORT;
            } else if (keyStoreOptions.isUseHTTPS()) {
                port = KeyStoreOptions.DEFAULT_PUBLIC_HTTPS_PORT;
            } else {
                port = KeyStoreOptions.DEFAULT_HTTP_PORT;
            }
        }

        switch (protocol) {
            case CLIENTWS: {
                LOG.debug("Using ClientWS as procotol");
            
                final String workerIdOrName;
                if (workerId == 0) {
                    workerIdOrName = workerName;
                } else {
                    workerIdOrName = String.valueOf(workerId);
                }

                signer = new ClientWSSODSigner(
                    host,
                    port,
                    servlet,
                    workerIdOrName,
                    keyStoreOptions.isUseHTTPS(),
                    username, password, metadata, sf);
                break;
            }
            case HTTP:
            default: {
                LOG.debug("Using HTTP as procotol");
                final URL url = new URL(keyStoreOptions.isUseHTTPS() ? "https" : "http", host, port, servlet == null ? DEFAULT_SERVLET : servlet);
                
                if (workerId == 0) {
                    signer = new HTTPSODSigner(url, workerName, username, password, metadata);
                } else {
                    signer = new HTTPSODSigner(url, workerId, username, password, metadata);
                }
            }
        }

        return signer;
    }

    /**
     * Execute the signing operation.
     */
    public final void run() throws CommandFailureException, IllegalCommandArgumentsException {
            final int NUM_WORKERS = 1;
        Worker workers[] = new Worker[NUM_WORKERS];
        PrintStream outputStream = getOutputStream();
        if (outputStream == null) {
            outputStream = System.out;
        }
        
        final SODSigner signer;
        try {
            signer = createSigner();
        } catch (MalformedURLException ex) {
            throw new IllegalCommandArgumentsException("Malformed URL: " + ex.getMessage());
        }
        
        for(int i = 0; i < NUM_WORKERS; i++) {
            workers[i] = new Worker("Worker " + i, signer,
                    dataGroups, encoding, repeat, outputStream);
        }

        // Start workers
        for(Worker worker : workers) {
            worker.start();
        }

        // Wait for worker
        for(Worker worker : workers) {
            System.err.println("Waiting for " +  worker);
            try {
                worker.join();
            } catch (InterruptedException ex) {
                System.err.println("Interrupted!");
            }
        }

            // Check for error, XXX: Yes this is ugly and we should remove this stress test feature from here
        for (Worker worker : workers) {
            final Exception exception = worker.getException();
            if (exception != null) {
                if (exception.getCause() instanceof AuthorizationRequiredException) {
                final AuthorizationRequiredException authEx =
                    (AuthorizationRequiredException) exception.getCause();
                LOG.error("Authorization required: " + authEx.getMessage());
                } else if (exception instanceof HTTPException) {
                    final HTTPException httpException = (HTTPException) exception;
                    throw new CommandFailureException("Failure: HTTP error: " +
                            httpException.getResponseCode() + ": " +
                            httpException.getResponseMessage());
                } else {
                    LOG.error("Failed", worker.getException());
                }
                    throw new CommandFailureException(worker.getException().getMessage(), ClientCLI.RETURN_ERROR);
            }
        }

        System.err.println("Done");
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException {
        try {
            // Parse the command line
            parseCommandLine(new GnuParser().parse(OPTIONS, args));
            
            validateOptions();
            run();
            return 0;
        } catch (ParseException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());
        }
    }

    // XXX: This stress test feature does not belong here. Consider removing it!
    @SuppressWarnings("PMD.DoNotUseThreads") // Not an JEE application
    private static class Worker extends Thread {

        private SODSigner signer;
        private Map<Integer,byte[]> dataGroups;
        private String encoding;
        private int repeat;
        private OutputStream out;
        private Exception exception;

        public Worker(String name, SODSigner signer, Map<Integer,byte[]> dataGroups,
                String encoding, int repeat, OutputStream out) {
            super(name);
            this.signer = signer;
            this.dataGroups = dataGroups;
            this.encoding = encoding;
            this.repeat = repeat;
            this.out = out;
        }

        @Override
        public void run() {
            try {
                for (int i = 0; i < repeat || repeat == -1; i++) {
                    signer.sign(dataGroups, encoding, out);
                }
            } catch (IOException | IllegalRequestException | CryptoTokenOfflineException | SignServerException ex) {
                exception = ex;
            }
            LOG.info("Finished");
        }
        
        public Exception getException() {
            return exception;
        }
    }
}
