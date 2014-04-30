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
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;
import javax.xml.ws.soap.SOAPFaultException;
import org.apache.commons.cli.*;
import org.apache.log4j.Logger;
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.protocol.ws.client.SignServerWSClientFactory;

/**
 * Command Line Interface (CLI) for validating documents.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ValidateDocumentCommand extends AbstractCommand {

    /** Logger for this class. */
    private static final Logger LOG =
            Logger.getLogger(ValidateDocumentCommand.class);

    /** ResourceBundle with internationalized StringS. */
    private static final ResourceBundle TEXTS = ResourceBundle.getBundle(
            "org/signserver/client/cli/defaultimpl/ResourceBundle");

    /** System-specific new line characters. **/
    private static final String NL = System.getProperty("line.separator");

    /** The name of this command. */
    private static final String COMMAND = "validatedocument";

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

    /** Option PORT. */
    public static final String PORT = "port";

    /** Option PROTOCOL. */
    public static final String PROTOCOL = "protocol";

    /** Option USERNAME. */
    public static final String USERNAME = "username";

    /** Option PASSWORD. */
    public static final String PASSWORD = "password";

    /** Option SERVLET. */
    public static final String SERVLET = "servlet";
    
    /** Option METADATA. */
    public static final String METADATA = "metadata";
    
    /** The command line options. */
    private static final Options OPTIONS;

    /**
     * Protocols that can be used for accessing SignServer.
     */
    public static enum Protocol {
        /** The Web Services interface. */
        WEBSERVICES,
        /** HTTP servlet protocol. */
        HTTP,
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
        OPTIONS.addOption(HOST, true,
                TEXTS.getString("HOST_DESCRIPTION"));
        OPTIONS.addOption(PORT, true,
                TEXTS.getString("PORT_DESCRIPTION"));
        OPTIONS.addOption(PROTOCOL, true,
                TEXTS.getString("PROTOCOL_DESCRIPTION_VALIDATE"));
        OPTIONS.addOption(USERNAME, true, "Username for authentication.");
        OPTIONS.addOption(PASSWORD, true, "Password for authentication.");
        OPTIONS.addOption(SERVLET, true, "URL to the webservice servlet. Default: " +
        		SignServerWSClientFactory.DEFAULT_WSDL_URL);
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

    /** Hostname or IP address of the SignServer host. */
    private String host = KeyStoreOptions.DEFAULT_HOST;

    /** TCP port number of the SignServer host. */
    private Integer port;

    /** File to read the data from. */
    private File inFile;

    private String username;
    private String password;

    /** Servlet URL */
    private String servlet;
    
    private Map<String, String> metadata;
    
    private Protocol protocol = Protocol.WEBSERVICES;
    
    private KeyStoreOptions keyStoreOptions = new KeyStoreOptions();

    @Override
    public String getDescription() {
        return "Request a document to be validated by SignServer";
    }

    @Override
    public String getUsages() {

        StringBuilder footer = new StringBuilder();
        footer.append(NL)
            .append("Sample usages:").append(NL)
            .append("a) ").append(COMMAND).append(" -workername XMLValidator -data \"<root><Signature...").append(NL)
            .append("b) ").append(COMMAND).append(" -workername XMLValidator -infile /tmp/signed.xml").append(NL)
            .append("c) ").append(COMMAND).append(" -workerid 2 -infile /tmp/signed.xml -truststore truststore.jks -truststorepwd changeit").append(NL)
            .append("d) ").append(COMMAND).append(" -workerid 2 -infile /tmp/signed.xml -keystore superadmin.jks -keystorepwd foo123").append(NL)
            .append("e) ").append(COMMAND).append(" -workername XMLValidator -protocol HTTP -infile /tmp/signed.xml").append(NL)
            .append("f) ").append(COMMAND).append(" -workername XMLValidator -infile /tmp/signed.xml -metadata param1=value1 -metadata param2=value2").append(NL);

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        final HelpFormatter formatter = new HelpFormatter();
        PrintWriter pw = new PrintWriter(bout);
        formatter.printHelp(pw, HelpFormatter.DEFAULT_WIDTH, "validatedocument <-workername WORKERNAME | -workerid WORKERID> [options]",
                "Request a document to be validated by SignServer", OPTIONS, HelpFormatter.DEFAULT_LEFT_PAD, HelpFormatter.DEFAULT_DESC_PAD, footer.toString());
        pw.close();
        return bout.toString();
    }

    /**
     * Reads all the options from the command line.
     *
     * @param line The command line to read from
     */
    private void parseCommandLine(final CommandLine line)
        throws IllegalCommandArgumentsException {
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
        if (line.hasOption(DATA)) {
            data = line.getOptionValue(DATA, null);
        }
        if (line.hasOption(INFILE)) {
            inFile = new File(line.getOptionValue(INFILE, null));
        }
        if (line.hasOption(USERNAME)) {
            username = line.getOptionValue(USERNAME, null);
        }
        if (line.hasOption(PASSWORD)) {
            password = line.getOptionValue(PASSWORD, null);
        }
        servlet = SignServerWSClientFactory.DEFAULT_WSDL_URL;
        if (line.hasOption(SERVLET)) {
        	servlet = line.getOptionValue(SERVLET);
        }
        if (line.hasOption(PROTOCOL)) {
            protocol = Protocol.valueOf(line.getOptionValue(
                    PROTOCOL, null));
            // override default servlet URL (if not set manually) for HTTP
            if (Protocol.HTTP.equals(protocol) &&
                    !line.hasOption(SERVLET)) {
                servlet = "/signserver/process";
            }
        }
        
        if (line.hasOption(METADATA)) {
            metadata = MetadataParser.parseMetadata(line.getOptionValues(METADATA));
        }
        
        keyStoreOptions.parseCommandLine(line);
    }

    /**
     * Checks that all mandadory options are given.
     */
    private void validateOptions() throws ParseException {
        if (workerName == null && workerId == 0) {
            throw new ParseException(
                    "Missing -workername or -workerid");
        } else if (data == null && inFile == null) {
            throw new ParseException("Missing -data or -infile");
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
    private DocumentValidator createValidator() throws MalformedURLException, IllegalArgumentException {
        final DocumentValidator validator;
        
        final String workerIdOrName;
        if (workerId == 0) {
            workerIdOrName = workerName;
        } else {
            workerIdOrName = String.valueOf(workerId);
        }

        keyStoreOptions.setupHTTPS();

        if (port == null) {
            if (keyStoreOptions.isUsePrivateHTTPS()) {
                port = KeyStoreOptions.DEFAULT_PRIVATE_HTTPS_PORT;
            } else if (keyStoreOptions.isUseHTTPS()) {
                port = KeyStoreOptions.DEFAULT_PUBLIC_HTTPS_PORT;
            } else {
                port = KeyStoreOptions.DEFAULT_HTTP_PORT;
            }
        }

        LOG.debug("Using WebServices as procotol");
        switch (protocol) {
        case WEBSERVICES:
            validator = new WebServicesDocumentValidator(
                    host,
                    port,
                    servlet,
                    keyStoreOptions.isUseHTTPS(),
                    workerIdOrName,
                    username,
                    password,
                    metadata);
            break;
        case HTTP:
            final URL url = new URL(keyStoreOptions.isUseHTTPS() ? "https" : "http", host, port, servlet);
            if (workerId == 0) {
                validator = new HTTPDocumentValidator(url, workerName, username, password, metadata);
            } else {
                validator = new HTTPDocumentValidator(url, workerId, username, password, metadata);
            }
            break;
        default:
            throw new IllegalArgumentException("Unknown protocol: " + protocol.toString());
        };
        return validator;
    }

    /**
     * Execute the signing operation.
     */
    public final void run() {
        FileInputStream fin = null;
        try {
            final byte[] bytes;
            final Map<String, Object> requestContext = new HashMap<String, Object>();
            
            if (inFile == null) {
                bytes = data.getBytes();
            } else {
                requestContext.put("FILENAME", inFile.getName());
                fin = new FileInputStream(inFile);
                bytes = new byte[(int) inFile.length()];
                fin.read(bytes);
            }
            createValidator().validate(bytes, requestContext);

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
}
