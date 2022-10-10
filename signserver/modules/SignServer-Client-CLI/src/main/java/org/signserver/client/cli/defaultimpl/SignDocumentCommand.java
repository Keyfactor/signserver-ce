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
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.concurrent.TimeUnit;
import javax.xml.ws.soap.SOAPFaultException;
import org.apache.commons.cli.*;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.client.cli.spi.FileSpecificHandlerFactory;
import org.signserver.common.AccessDeniedException;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.protocol.ws.client.SignServerWSClientFactory;
import static org.signserver.client.cli.defaultimpl.HTTPDocumentSigner.DEFAULT_LOAD_BALANCING;
import static org.signserver.client.cli.defaultimpl.HTTPDocumentSigner.ROUND_ROBIN_LOAD_BALANCING;
import org.signserver.common.RequestContext;
import org.signserver.common.signedrequest.SignedRequestException;
import org.signserver.common.signedrequest.SignedRequestSigningHelper;

/**
 * Command Line Interface (CLI) for signing documents.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SignDocumentCommand extends AbstractCommand implements ConsolePasswordProvider {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SignDocumentCommand.class);

    /** ResourceBundle with internationalized StringS. */
    private static final ResourceBundle TEXTS = ResourceBundle.getBundle(
            "org/signserver/client/cli/defaultimpl/ResourceBundle");

    private static final String DEFAULT_CLIENTWS_WSDL_URL = "/signserver/ClientWSService/ClientWS?wsdl";
    
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
    
    /** Option HOSTS. */
    public static final String HOSTS = "hosts";

    /** Option INFILE. */
    public static final String INFILE = "infile";

    /** Option OUTFILE. */
    public static final String OUTFILE = "outfile";

    /** Option INDIR. */
    public static final String INDIR = "indir";

    /** Option OUTDIR. */
    public static final String OUTDIR = "outdir";
    
    /** Option THREADS. */
    public static final String THREADS = "threads";
    
    /** Option REMOVEFROMINDIR. */
    public static final String REMOVEFROMINDIR = "removefromindir";
    
    /** Option ONEFIRST. */
    public static final String ONEFIRST = "onefirst";
    
    /** Option STARTALL. */
    public static final String STARTALL = "startall";

    /** Option PORT. */
    public static final String PORT = "port";

    public static final String SERVLET = "servlet";

    /** Option PROTOCOL. */
    public static final String PROTOCOL = "protocol";

    /** Option USERNAME. */
    public static final String USERNAME = "username";

    /** Option PASSWORD. */
    public static final String PASSWORD = "password";

    /** Option ACCESSTOKEN. */
    public static final String ACCESSTOKEN = "accesstoken";
    
    /** Option PDFPASSWORD. */
    public static final String PDFPASSWORD = "pdfpassword";

    /** Option METADATA. */
    public static final String METADATA = "metadata";
    
    /** Option CLIENTSIDE. */
    public static final String CLIENTSIDE = "clientside";
    
    /** Option DIGESTALGORITHM. */
    public static final String DIGESTALGORITHM = "digestalgorithm";

    /** Option FILETYPE. */
    public static final String FILETYPE = "filetype";
    
    /** Option EXTRAOPTION. */
    public static final String EXTRAOPTION = "extraoption";
    
    /** Option TIMEOUT. */
    public static final String TIMEOUT = "timeout";
    
    /** Option LOAD_BALANCING. */
    public static final String LOAD_BALANCING = "loadbalancing";
    
    /** The command line options. */
    private static final Options OPTIONS;

    private static final int DEFAULT_THREADS = 1;

    /**
     * Protocols that can be used for accessing SignServer.
     */
    public static enum Protocol {
        /** The SignServerWS interface. */
        WEBSERVICES,
        
        /** The ClientWS interface. */
        CLIENTWS,

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
        OPTIONS.addOption(HOSTS, true,
                TEXTS.getString("HOSTS_DESCRIPTION"));
        OPTIONS.addOption(PORT, true,
                TEXTS.getString("PORT_DESCRIPTION"));
        OPTIONS.addOption(SERVLET, true,
                TEXTS.getString("SERVLET_DESCRIPTION"));
        OPTIONS.addOption(PROTOCOL, true,
                TEXTS.getString("PROTOCOL_DESCRIPTION"));
        OPTIONS.addOption(USERNAME, true,
                TEXTS.getString("USERNAME_DESCRIPTION"));
        OPTIONS.addOption(PASSWORD, true,
                TEXTS.getString("PASSWORD_DESCRIPTION"));
        OPTIONS.addOption(ACCESSTOKEN, true,
                TEXTS.getString("ACCESSTOKEN_DESCRIPTION"));
        OPTIONS.addOption(PDFPASSWORD, true,
                TEXTS.getString("PDFPASSWORD_DESCRIPTION"));
        OPTIONS.addOption(METADATA, true,
                TEXTS.getString("METADATA_DESCRIPTION"));
        OPTIONS.addOption(INDIR, true,
                TEXTS.getString("INDIR_DESCRIPTION"));
        OPTIONS.addOption(OUTDIR, true,
                TEXTS.getString("OUTDIR_DESCRIPTION"));
        OPTIONS.addOption(THREADS, true,
                TEXTS.getString("THREADS_DESCRIPTION"));
        OPTIONS.addOption(REMOVEFROMINDIR, false,
                TEXTS.getString("REMOVEFROMINDIR_DESCRIPTION"));
        OPTIONS.addOption(ONEFIRST, false,
                TEXTS.getString("ONEFIRST_DESCRIPTION"));
        OPTIONS.addOption(STARTALL, false,
                TEXTS.getString("STARTALL_DESCRIPTION"));
        OPTIONS.addOption(CLIENTSIDE, false,
                TEXTS.getString("CLIENTSIDE_DESCRIPTION"));
        OPTIONS.addOption(DIGESTALGORITHM, true,
                TEXTS.getString("DIGESTALGORITHM_DESCRIPTION"));
        OPTIONS.addOption(FILETYPE, true,
                TEXTS.getString("FILETYPE_DESCRIPTION"));
        OPTIONS.addOption(EXTRAOPTION, true,
                TEXTS.getString("EXTRAOPTION_DESCRIPTION"));
        OPTIONS.addOption(TIMEOUT, true,
                TEXTS.getString("TIMEOUT_DESCRIPTION"));
        OPTIONS.addOption(LOAD_BALANCING, true,
                TEXTS.getString("LOAD_BALANCING_DESCRIPTION"));
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

    /** Hostname or IP address of the SignServer host. */
    private String host;

    /** List of host names to try to connect to, or distribute load on for
     *  load balancing
     */
    private List<String> hosts;
    
    /** TCP port number of the SignServer host. */
    private Integer port;

    private String servlet = "/signserver/process";

    /** File to read the data from. */
    private File inFile;

    /** File to read the signed data to. */
    private File outFile;

    /** Directory to read files from. */
    private File inDir;
    
    /** Directory to write files to. */
    private File outDir;
    
    /** Number of threads to use when running in batch mode. */
    private Integer threads;
    
    /** If the successfully processed files should be removed from indir. */
    private boolean removeFromIndir;
    
    /** If one request should be set first before starting the remaining threads. */
    private boolean oneFirst;
    
    /** If all should be started directly (ie not oneFirst). */
    private boolean startAll;

    /** Protocol to use for contacting SignServer. */
    private Protocol protocol = Protocol.HTTP;

    private String username;
    private String password;
    private boolean promptForPassword;

    private String accessToken;
    
    private String pdfPassword;
    
    private boolean clientside;
    private String digestAlgorithm;
    private String fileType;
    private String timeOutString;
    private int timeOutLimit;    
    private boolean useLoadBalancing;
    private String loadBalancing;
    
    private final KeyStoreOptions keyStoreOptions = new KeyStoreOptions();

    /** Meta data parameters passed in */
    private Map<String, String> metadata;
    
    /** Extra option parameters passed in */
    private Map<String, String> extraOptions;
    
    private FileSpecificHandlerFactory handlerFactory;
    
    private HostManager hostsManager;
    
    @Override
    public String getDescription() {
        return "Request a document to be signed by SignServer";
    }

    @Override
    public String getUsages() {
        StringBuilder footer = new StringBuilder();
        footer.append(NL)
            .append("Sample usages:").append(NL)
            .append("a) ").append(COMMAND).append(" -workername XMLSigner -data \"<root/>\"").append(NL)
            .append("b) ").append(COMMAND).append(" -workername XMLSigner -infile /tmp/document.xml").append(NL)
            .append("c) ").append(COMMAND).append(" -workerid 2 -data \"<root/>\" -truststore truststore.jks -truststorepwd changeit").append(NL)
            .append("d) ").append(COMMAND).append(" -workerid 2 -data \"<root/>\" -keystore superadmin.jks -keystorepwd foo123").append(NL)
            .append("e) ").append(COMMAND).append(" -workerid 2 -data \"<root/>\" -metadata param1=value1 -metadata param2=value2").append(NL)
            .append("f) ").append(COMMAND).append(" -workerid 3 -indir ./input/ -removefromindir -outdir ./output/ -threads 5").append(NL)
            .append("g) ").append(COMMAND).append(" -workerid 3 -indir ./input/ -outdir ./output/ -threads 5 -hosts primaryhost,secondaryhost").append(NL)
            .append("h) ").append(COMMAND).append(" -workerid 3 -indir ./input/ -outdir ./output/ -threads 5 -hosts primaryhost,secondaryhost,otherhost -timeout 5000").append(NL)
            .append("i) ").append(COMMAND).append(" -workerid 3 -indir ./input/ -outdir ./output/ -threads 5 -hosts host1,host2,host3 -loadbalancing ROUND_ROBIN -timeout 5000").append(NL)
            .append("j) ").append(COMMAND).append(" -workerid 2 -data \"<root/>\" -keystoretype PKCS11 -keystore libcryptoki.so").append(NL)
            .append("k) ").append(COMMAND).append(" -workerid 2 -data \"<root/>\" -keystoretype PKCS11 -keystore libcryptoki.so -keyaliasprompt").append(NL)
            .append("l) ").append(COMMAND).append(" -workerid 2 -data \"<root/>\" -keystoretype PKCS11 -keystore libcryptoki.so -keyalias admin3").append(NL)
            .append("m) ").append(COMMAND).append(" -workerid 2 -data \"<root/>\" -keystoretype PKCS11_CONFIG -keystore sunpkcs11.cfg").append(NL)
            .append("n) ").append(COMMAND).append(" -data \"<root/>\" -servlet /signserver/worker/XMLSigner").append(NL); 

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        final HelpFormatter formatter = new HelpFormatter();
        
        try (PrintWriter pw = new PrintWriter(bout)) {
            formatter.printHelp(pw, HelpFormatter.DEFAULT_WIDTH, "signdocument <-workername WORKERNAME | -workerid WORKERID> [options]",  getDescription(), OPTIONS, HelpFormatter.DEFAULT_LEFT_PAD, HelpFormatter.DEFAULT_DESC_PAD, footer.toString());
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
        if (line.hasOption(WORKERNAME)) {
            workerName = line.getOptionValue(WORKERNAME, null);
        }
        if (line.hasOption(WORKERID)) {
            workerId = Integer.parseInt(line.getOptionValue(WORKERID, null));
        }
        host = line.getOptionValue(HOST);
                
        if (line.hasOption(HOSTS)) {
            final String hostsString = line.getOptionValue(HOSTS);
            
            hosts = new LinkedList<>();
            for (final String hostString : hostsString.split(",")) {
                final String hostTrim = hostString.trim();
                
                if (!hostTrim.isEmpty()) {
                    hosts.add(hostTrim);
                }
            }
        }
        
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
        if (line.hasOption(INDIR)) {
            inDir = new File(line.getOptionValue(INDIR, null));
        }
        if (line.hasOption(OUTDIR)) {
            outDir = new File(line.getOptionValue(OUTDIR, null));
        }
        if (line.hasOption(THREADS)) {
            threads = Integer.parseInt(line.getOptionValue(THREADS, null));
        }
        if (line.hasOption(REMOVEFROMINDIR)) {
            removeFromIndir = true;
        }
        if (line.hasOption(ONEFIRST)) {
            oneFirst = true;
        }
        if (line.hasOption(STARTALL)) {
            startAll = true;
        }
        if (line.hasOption(PROTOCOL)) {
            protocol = Protocol.valueOf(line.getOptionValue(
                    PROTOCOL, null));
            
            // if the protocol is WS and -servlet is not set, override the servlet URL
            // with the default one for the WS servlet
            if (Protocol.WEBSERVICES.equals(protocol) &&
            	!line.hasOption(SERVLET)) {
            	servlet = SignServerWSClientFactory.DEFAULT_WSDL_URL;
            }
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
        if (line.hasOption(ACCESSTOKEN)) {
            accessToken = line.getOptionValue(ACCESSTOKEN, null);
        }
        if (line.hasOption(PDFPASSWORD)) {
            pdfPassword = line.getOptionValue(PDFPASSWORD, null);
        }
        
        if (line.hasOption(METADATA)) {
            metadata = MetadataParser.parseMetadata(line.getOptionValues(METADATA));
        } else {
            metadata = new HashMap<>();
        }

        if (line.hasOption(EXTRAOPTION)) {
            extraOptions = MetadataParser.parseMetadata(line.getOptionValues(EXTRAOPTION));
        } else {
            extraOptions = new HashMap<>();
        }
        
        if (line.hasOption(CLIENTSIDE)) {
            clientside = true;
        }
        
        if (line.hasOption(DIGESTALGORITHM)) {
            digestAlgorithm = line.getOptionValue(DIGESTALGORITHM);
            if (digestAlgorithm != null) {
                switch (digestAlgorithm.toUpperCase()) {
                    case "MD5":
                    case "MD-5":
                        digestAlgorithm = "MD5";
                        break;
                    case "SHA1":
                    case "SHA-1":
                        digestAlgorithm = "SHA-1";
                        break;
                    case "SHA224":
                    case "SHA-224":
                        digestAlgorithm = "SHA-224";
                        break;
                    case "SHA256":
                    case "SHA-256":
                        digestAlgorithm = "SHA-256";
                        break;
                    case "SHA384":
                    case "SHA-384":
                        digestAlgorithm = "SHA-384";
                        break;
                    case "SHA512":
                    case "SHA-512":
                        digestAlgorithm = "SHA-512";
                        break;
                    default:
                        break;
                }
            }
        }

        if (line.hasOption(FILETYPE)) {
            fileType = line.getOptionValue(FILETYPE);
        }

        timeOutString = line.getOptionValue(TIMEOUT);      
                
        loadBalancing = line.getOptionValue(LOAD_BALANCING, DEFAULT_LOAD_BALANCING);

        try {
            final ConsolePasswordReader passwordReader = createConsolePasswordReader();
            keyStoreOptions.parseCommandLine(line, passwordReader, out);

            // Prompt for user password if not given
            if (username != null && password == null) {
                promptForPassword = true;
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
    @Override
    public ConsolePasswordReader createConsolePasswordReader() {
        return new DefaultConsolePasswordReader();
    }

    /**
     * Checks that all mandatory options are given.
     */
    private void validateOptions() throws IllegalCommandArgumentsException {
        if (workerName == null && workerId == 0 && protocol != Protocol.HTTP) {
            throw new IllegalCommandArgumentsException("Must specify -workername or -workerid when not using protocol HTTP");
        }

        if (data == null && inFile == null && inDir == null && outDir == null) {
            throw new IllegalCommandArgumentsException("Missing -data, -infile or -indir");
        }
        
        if (inDir != null && outDir == null) {
            throw new IllegalCommandArgumentsException("Missing -outdir");
        }
        if (data != null && inFile != null) {
            throw new IllegalCommandArgumentsException("Can not specify both -data and -infile");
        }
        if (data != null && inDir != null) {
            throw new IllegalCommandArgumentsException("Can not specify both -data and -indir");
        }
        if (inFile != null && inDir != null) {
            throw new IllegalCommandArgumentsException("Can not specify both -infile and -indir");
        }
        if (inFile != null && outDir != null) {
            throw new IllegalCommandArgumentsException("Can not specify both -infile and -outdir");
        }

        if (inDir != null && inDir.equals(outDir)) {
            throw new IllegalCommandArgumentsException("Can not specify the same directory as -indir and -outdir");
        }
        
        if (inDir == null & threads != null) {
            throw new IllegalCommandArgumentsException("Can not specify -threads unless -indir");
        }

        if (threads != null && threads < 1) {
            throw new IllegalCommandArgumentsException("Number of threads must be > 0");
        }
        
        if (startAll && oneFirst) {
            throw new IllegalCommandArgumentsException("Can not specify both -onefirst and -startall");
        }
        
        if ((startAll || oneFirst) && (inDir == null)) {
            throw new IllegalCommandArgumentsException("The options -onefirst and -startall only supported in batch mode. Specify -indir.");
        }
        
        // Default to use oneFirst if username is specified and not startall
        if(!startAll && username != null) {
            oneFirst = true;
        }
        
        // check client-side options
        if (clientside) {
            if (digestAlgorithm == null) {
                throw new IllegalCommandArgumentsException("Must specify -digestalgorithm when using -clientside");
            }

            // check that outfile is provided with client-side option
            if (outFile == null && outDir == null) {
                throw new IllegalCommandArgumentsException("Must specify -outfile or -outdir when using -clientside");
            }

            if (inFile == null && inDir == null) {
                throw new IllegalCommandArgumentsException("Can only use -clientside with -infile or -indir");
            }
        } else {
            if (digestAlgorithm != null) {
                throw new IllegalCommandArgumentsException("Can only use -digestalgorithm with -clientside");
            }

            if (fileType != null) {
                throw new IllegalCommandArgumentsException("Can only use -filetype with -clientside");
            }
        }

        if (host != null && hosts != null) {
            throw new IllegalCommandArgumentsException("Can only specify one of -host and -hosts");
        }
        
        if (hosts != null && protocol != Protocol.HTTP) {
            throw new IllegalCommandArgumentsException("Can only use -hosts with protocol HTTP");
        }
        
        if (!loadBalancing.equals(DEFAULT_LOAD_BALANCING) && protocol != Protocol.HTTP) {
            throw new IllegalCommandArgumentsException("Can only use -loadbalancing with protocol HTTP");
        }

        if (timeOutString != null && protocol != Protocol.HTTP) {
            throw new IllegalCommandArgumentsException("Can only use -timeout with protocol HTTP");
        }
        
        if (host != null) {
            if (host.trim().isEmpty()) {
                throw new IllegalCommandArgumentsException("-host can not be empty");
            }
            hosts = Collections.singletonList(host);
        } else if (hosts == null && host == null) {
            hosts = Collections.singletonList(KeyStoreOptions.DEFAULT_HOST);
            host = KeyStoreOptions.DEFAULT_HOST;
        }
        
        if (hosts.isEmpty()) {
            throw new IllegalCommandArgumentsException("-hosts can not be empty");
        }
        
        if (loadBalancing.trim().isEmpty()) {
            throw new IllegalCommandArgumentsException("-loadbalancing can not be empty");
        }

        if (!Arrays.asList(DEFAULT_LOAD_BALANCING, ROUND_ROBIN_LOAD_BALANCING).contains(loadBalancing)) {
            throw new IllegalCommandArgumentsException("Not supported -loadbalancing: " + loadBalancing);
        }     
                           
        keyStoreOptions.validateOptions();
        
        if (timeOutString != null) {
            try {
                timeOutLimit = Integer.parseInt(timeOutString);
                if (timeOutLimit < 0) {
                    throw new IllegalCommandArgumentsException("Time out limit can not be negative");
                }
            } catch (NumberFormatException ex) {
                throw new IllegalCommandArgumentsException("Illegal time out limit: " + timeOutString);
            }
        } else {
            timeOutLimit = -1;
        }
        
        useLoadBalancing = loadBalancing.equals(ROUND_ROBIN_LOAD_BALANCING);

        //  it is right time to initialize HostsManager after all validations
        hostsManager = new HostManager(hosts, useLoadBalancing);

        // don't allow both -username and -access-token at the same time
        if (username != null && accessToken != null) {
            throw new IllegalCommandArgumentsException("Can not specify both -username and -accesstoken");
        }

        // only support JWT auth with HTTP
        if (accessToken != null && protocol != Protocol.HTTP) {
            throw new IllegalCommandArgumentsException("Can only use -accesstoken with protocol HTTP");
        }

        // -signrequest reuires -keystore
        if (keyStoreOptions.isSignRequest() && keyStoreOptions.getKeystoreFile() == null) {
            throw new IllegalCommandArgumentsException("-signrequest requires -keystore");
        }
    }

    /**
     * Execute the signing operation.
     * @param manager for managing the threads
     * @param inFile directory
     * @param outFile directory
     * @return True if success or False if there is a failure and there is no TransferManager to register the failure on
     */
    protected boolean runBatch(TransferManager manager, final File inFile, final File outFile) {
        final byte[] bytes;
        final long size;
        
        Map<String, Object> requestContext = new HashMap<>();
        if (inFile == null) {
            bytes = data.getBytes();
            size = bytes.length;
            requestContext.put("FILENAME", "noname.dat");
        } else {
            if (!inFile.exists()) {
                LOG.error(MessageFormat.format(TEXTS.getString("FILE_NOT_FOUND:"),
                                               inFile.getAbsolutePath()));
                return false;
            }
            requestContext.put("FILENAME", inFile.getName());
            bytes = null;
            size = inFile.length();
        }
        return runFile(manager, requestContext, inFile, bytes, size, outFile);
    }
    
    private void initFileSpecificHandlerFactory()
            throws CommandFailureException {
        final ServiceLoader<? extends FileSpecificHandlerFactory> factoryLoader =
                ServiceLoader.load(FileSpecificHandlerFactory.class);
        boolean rejectedFileType = false;
        
        try {
            for (final FileSpecificHandlerFactory factory : factoryLoader) {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("Trying factory: " + factory.getClass().getName());
                }
                if (!clientside ||
                    (clientside && factory.canCreateClientSideCapableHandler())) {
                    if (fileType != null && !factory.canHandleFileType(fileType)) {
                        rejectedFileType = true;
                    } else {
                        this.handlerFactory = factory;
                        return;
                    }
                }
            }
        } catch (ServiceConfigurationError e) {
            throw new CommandFailureException("Error loading command factories: " + e.getLocalizedMessage());
        }

        if (rejectedFileType) {
            throw new CommandFailureException("Could not find file handler factory supporting file type: " + fileType);
        } else {
            throw new CommandFailureException("Client-side hashing and contruction is not supported");
        }
    }

    protected DocumentSignerFactory createDocumentSignerFactory(final Protocol protocol,
                                                                final KeyStoreOptions keyStoreOptions,
                                                                final String host,
                                                                final String servlet,
                                                                final Integer port,
                                                                final String digestAlgorithm,
                                                                final String username,
                                                                final String currentPassword,
                                                                final String accessToken,
                                                                final String pdfPassword,
                                                                final HostManager hostsManager,
                                                                final int timeoutLimit) {
        return new DocumentSignerFactory(protocol, keyStoreOptions, host,
                                              servlet, port,
                                              digestAlgorithm, username,
                                              currentPassword, accessToken,
                                              pdfPassword,
                                              hostsManager, timeOutLimit);
    }
    
    /**
     * Runs the signing operation for one file.
     *
     * @param manager for the threads
     * @param requestContext for the request
     * @param inFile directory
     * @param bytes to sign
     * @param outFile directory
     * @return True if success or False if there is a failure and there is no TransferManager to register the failure on
     */
    private boolean runFile(final TransferManager manager,
                            final Map<String, Object> requestContext,
                            final File inFile,
                            final byte[] bytes, final long size,
                            final File outFile) {  // TODO: merge with runBatch ?, inFile here is only used when removing the file
        boolean success = true;
        boolean cleanUpOutputFileOnFailure = false;

        final String currentPassword =
                manager == null ? password : manager.getPassword();
        final DocumentSignerFactory signerFactory =
                    createDocumentSignerFactory(protocol, keyStoreOptions, host,
                                                servlet, port,
                                                digestAlgorithm, username,
                                                currentPassword, accessToken,
                                                pdfPassword,
                                                hostsManager, timeOutLimit);

        try {
            OutputStream outStream = null;

            try (final FileSpecificHandler handler =
                    inFile != null ?
                    createFileSpecificHandler(handlerFactory, signerFactory,
                                              requestContext,
                                              inFile, outFile, extraOptions) :
                    createFileSpecificHandler(handlerFactory,
                                              bytes, size, outFile,
                                              extraOptions)) {
                // Take start time
                final long startTime = System.nanoTime();
                
                // Perform pre-request if used by the handler
                final InputSource preInputSource = handler.producePreRequestInput();
                if (preInputSource != null) {
                    final OutputStream os = new ByteArrayOutputStream();
                    sign(preInputSource, os, signerFactory, handler, requestContext);
                    handler.assemblePreResponse(new OutputCollector(os, clientside));
                }
                
                // Perform the real request
                final InputSource inputSource = handler.produceSignatureInput(digestAlgorithm);

                if (clientside) {
                    outStream = new ByteArrayOutputStream();
                } else {
                    if (outFile == null) {
                        outStream = System.out;
                    } else {
                        outStream = new FileOutputStream(outFile);
                    }
                }
                if (inputSource != null) {
                    sign(inputSource, outStream, signerFactory, handler, requestContext);
                }
                handler.assemble(new OutputCollector(outStream, clientside));

                // Take stop time
                final long estimatedTime = System.nanoTime() - startTime;
                
                if (LOG.isInfoEnabled()) {
                    LOG.info("Wrote " + outFile + ".");
                    LOG.info("Processing " + (inFile == null ? "" : inFile.getName()) + " took "
                        + TimeUnit.NANOSECONDS.toMillis(estimatedTime) + " ms.");
                }
            } catch (IllegalArgumentException ex) {
                LOG.error("Failed: " + ex.getLocalizedMessage());
                success = false;
                cleanUpOutputFileOnFailure = true;
            } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                LOG.error("Digest algorithm not supported: " + digestAlgorithm);
                success = false;
                cleanUpOutputFileOnFailure = true;
            } finally {
                if (outStream != null && outStream != System.out) {
                    outStream.close();
                }
            }

            if (removeFromIndir && inFile != null && inFile.exists()) {
                if (inFile.delete()) {
                    LOG.info("Removed " + inFile);
                } else {
                    LOG.error("Could not remove " + inFile);
                    if (manager != null) {
                        manager.registerFailure();
                    } else {
                        success = false;
                    }
                }
            }
            if (manager != null) {
                manager.registerSuccess(); // Login must have worked
            }
        } catch (FileNotFoundException ex) {
            LOG.error("Failure for " + (inFile == null ? "" : inFile.getName()) + ": " + MessageFormat.format(TEXTS.getString("FILE_NOT_FOUND:"),
                    ex.getLocalizedMessage()));
            if (manager != null) {
                manager.registerFailure();
                cleanUpOutputFileOnFailure = true;
            } else {
                success = false;
                cleanUpOutputFileOnFailure = true;
            }
        } catch (SOAPFaultException ex) {
            if (ex.getCause() instanceof AuthorizationRequiredException) {
                final AuthorizationRequiredException authEx =
                        (AuthorizationRequiredException) ex.getCause();
                LOG.error("Authorization failure for " + (inFile == null ? "" : inFile.getName()) + ": " + authEx.getMessage());
            } else if (ex.getCause() instanceof AccessDeniedException) {
                final AccessDeniedException authEx =
                        (AccessDeniedException) ex.getCause();
                LOG.error("Access defined failure for " + (inFile == null ? "" : inFile.getName()) + ": " + authEx.getMessage());
            }
            LOG.error(ex);
            success = false;
            cleanUpOutputFileOnFailure = true;
        } catch (HTTPException ex) {
            LOG.error("Failure for " + (inFile == null ? "" : inFile.getName()) + ": HTTP Error " + ex.getResponseCode() + ": " + ex.getResponseMessage());
            
            if (manager != null) {
                if (ex.getResponseCode() == 401) { // Only abort for authentication failure
                    if (promptForPassword) {
                        // If password was not specified at command line, ask again for it
                        manager.tryAgainWithNewPassword(inFile);
                    } else {
                        manager.abort();
                    }
                } else {
                    manager.registerFailure();
                    cleanUpOutputFileOnFailure = true;
                }
            } else {
                success = false;
                cleanUpOutputFileOnFailure = true;
            }
        } catch (IllegalRequestException | CryptoTokenOfflineException | SignServerException | IOException ex) {
            LOG.error("Failure for " + (inFile == null ? "" : inFile.getName()) + ": " + ex.getMessage());
            if (manager != null) {
                manager.registerFailure();
                cleanUpOutputFileOnFailure=true;
            } else {
                success = false;
                cleanUpOutputFileOnFailure=true;
            }
        }
        if (cleanUpOutputFileOnFailure) {
            cleanUpOutputFileOnFailure(outFile);
        }
        return success;
    }
    
    private void sign(final InputSource inputSource, final OutputStream os,
                      final DocumentSignerFactory signerFactory,
                      final FileSpecificHandler handler,
                      final Map<String, Object> requestContext)
            throws MalformedURLException, IllegalRequestException,
                   CryptoTokenOfflineException, SignServerException, IOException {
        final DocumentSigner signer;

        if (workerId == 0) {
            signer = signerFactory.createSigner(workerName, metadata, clientside,
                                                handler.isSignatureInputHash(),
                                                handler.getFileTypeIdentifier());
        } else {
            signer = signerFactory.createSigner(workerId, metadata, clientside,
                                                handler.isSignatureInputHash(),
                                                handler.getFileTypeIdentifier());
        }
        
        /* add addional metadata from the file handler to the request
         * context
         */
        final Map<String, String> extraMetadata =
                inputSource.getMetadata();

        if (extraMetadata != null) {
            metadata.putAll(extraMetadata);
        }

        if (keyStoreOptions.isSignRequest()) {
            try {
                final String fileName;
                if (requestContext.get(RequestContext.FILENAME) != null) {
                    fileName = (String) requestContext.get(RequestContext.FILENAME);
                } else {
                    fileName = null;
                }

                final List<Certificate> signCertChain =
                    keyStoreOptions.getSignCertificateChain();

                if (signCertChain == null) {
                    throw new SignServerException("Could not find certificate chain matching signing key");
                }

                final String signatureAlgorithm =
                    KeyStoreOptions.suggestSignatureAlgorithm(signCertChain.get(0).getPublicKey());
                final PrivateKey privateKey = keyStoreOptions.getSignPrivateKey();
                
                final byte[] requestDataDigest = inputSource.getHash("SHA-256"); 

                SignedRequestSigningHelper.addRequestSignature("SHA-256",
                                                               requestDataDigest,
                                                               metadata,
                                                               fileName,
                                                               workerName,
                                                               workerId,
                                                               signatureAlgorithm,
                                                               privateKey,
                                                               signCertChain);

            } catch (KeyStoreException | SignedRequestException |
                     NoSuchAlgorithmException | UnrecoverableKeyException |
                     NoSuchProviderException ex) {
                LOG.error("Could not sign signature request", ex);
                throw new SignServerException("Could not sign signature request", ex);
            }
        }
   
        // Get the data signed
        signer.sign(inputSource.getInputStream(), inputSource.getSize(), os, requestContext);
    }
    
    private FileSpecificHandler createFileSpecificHandler(final FileSpecificHandlerFactory handlerFactory,
                                                          final DocumentSignerFactory signerFactory,
                                                          final Map<String, Object> requestContext,
                                                          final File inFile,
                                                          final File outFile, Map<String, String> extraOptions)
            throws IOException {
        if (fileType != null) {
            if (workerName != null) {
                return handlerFactory.createHandler(fileType, inFile, outFile,
                                                    clientside, extraOptions,
                                                    workerName, signerFactory,
                                                    requestContext, metadata);
            } else {
                return handlerFactory.createHandler(fileType, inFile, outFile,
                                                    clientside, extraOptions,
                                                    workerId, signerFactory,
                                                    requestContext, metadata);
            }
        } else {
            if (workerName != null) {
                return handlerFactory.createHandler(inFile, outFile, clientside,
                                                    extraOptions, workerName,
                                                    signerFactory,
                                                    requestContext, metadata);
            } else {
                return handlerFactory.createHandler(inFile, outFile, clientside,
                                                    extraOptions, workerId,
                                                    signerFactory,
                                                    requestContext, metadata);
            }
        }
    }
    
    private FileSpecificHandler createFileSpecificHandler(final FileSpecificHandlerFactory handlerFactory,
                                                          final byte[] inData,
                                                          final long size,
                                                          final File outFile, Map<String, String> extraOptions)
            throws IOException {
        if (fileType != null) {
            return handlerFactory.createHandler(fileType, inData, outFile,
                                                clientside, extraOptions);
        } else {
            return handlerFactory.createHandler(inData, outFile,
                                                clientside, extraOptions);
        }
    }
    
    /**
     * Removes output file in case of failure.
     *
     * @param outFile representing output file on disk
     *
     */
    private void cleanUpOutputFileOnFailure(final File outFile) {
        if (outFile != null && outFile.exists()) {
            if (FileUtils.deleteQuietly(outFile)) {
                LOG.info("Removed output file " + outFile);
            } else {
                LOG.error("Could not remove output file " + outFile);
            }
        }        
    }
    
    @Override
    public int execute(String[] args) throws IllegalCommandArgumentsException, CommandFailureException {
        try {
            // Parse the command line
            parseCommandLine(new GnuParser().parse(OPTIONS, args));
            validateOptions();
            initFileSpecificHandlerFactory();
            
            if (inFile != null) {
                LOG.debug("Will request for single file " + inFile);
                if (!runBatch(null, inFile, outFile)) {
                    throw new CommandFailureException("There was a failure");
                }
            } else if(inDir != null) {
                LOG.debug("Will request for each file in directory " + inDir);
                File[] inFiles = inDir.listFiles(new FileFilter() {
                    @Override
                    public boolean accept(File file) {
                        if (file.isDirectory()) {
                            LOG.warn("Skipping directory: " + file.getName());
                            return false;
                        }
                        return true;
                    }
                });
                if (inFiles == null || inFiles.length == 0) {
                    LOG.error("No input files");
                    return 1;
                }
                final TransferManager producer = new TransferManager(inFiles, username, password, this, out, oneFirst);
                
                if (threads == null) {
                    threads = DEFAULT_THREADS;
                }
                final int threadCount = threads > inFiles.length ? inFiles.length : threads;
                final ArrayList<TransferThread> consumers = new ArrayList<>();
                
                final Thread.UncaughtExceptionHandler handler = new Thread.UncaughtExceptionHandler() {
                    @Override
                    public void uncaughtException(Thread t, Throwable e) {                        
                        LOG.error("Unexpected failure in thread " + t.getName() + ". Aborting.", e);
                        producer.abort();
                    }
                };
                
                for (int i = 0; i < threadCount; i++) {
                    final TransferThread t = new TransferThread(i, producer, hostsManager);
                    t.setUncaughtExceptionHandler(handler);
                    consumers.add(t);
                }
                
                // Start the threads
                for (TransferThread consumer : consumers) {
                    consumer.start();
                }
                
                // Wait for the threads to finish
                try {
                    for (TransferThread w : consumers) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Waiting for thread " + w.getName());
                        }
                        w.join();
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Thread " + w.getName() + " stopped");
                        }
                    }
                } catch (InterruptedException ex) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Interupted when waiting for thread: " + ex.getMessage());
                    }
                }
                
                if (producer.isAborted()) {
                    throw new CommandFailureException("Aborted due to failure.");
                }
                
                if (producer.hasFailures()) {
                    throw new CommandFailureException("At least one file failed.");
                }
                
            } else {
                LOG.debug("Will requst for the specified data");
                if (!runBatch(null, null, outFile)) {
                    throw new CommandFailureException("There was a failure");
                }
            }

            return 0;
        } catch (ParseException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());
        }
    }
    
    /**
     * Thread for running the upload/download of the data.
     */
    @SuppressWarnings("PMD.DoNotUseThreads") // Not an JEE application
    private class TransferThread extends Thread {
        private final int id;
        private final TransferManager producer;
        private final HostManager hostsUtil;

        public TransferThread(int id, TransferManager producer, HostManager hostsUtil) {
            super("transfer-" + id);
            this.id = id;
            this.producer = producer;
            this.hostsUtil = hostsUtil;
        }
        
        @Override
        public void run() {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Starting " + getName() + "...");
            }
            File file;
            while ((file = producer.nextFile()) != null && hostsUtil.hasHost()) {
                if (LOG.isInfoEnabled()) {
                    LOG.info("Sending " + file + "...");
                }
                runBatch(producer, file, new File(outDir, file.getName()));
            }
            if (LOG.isTraceEnabled()) {
                LOG.trace(id + ": No more work.");
            }
        }
    }
    
}