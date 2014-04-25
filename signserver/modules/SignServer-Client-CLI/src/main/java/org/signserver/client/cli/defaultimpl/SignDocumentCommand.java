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
import org.signserver.common.AccessDeniedException;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.protocol.ws.client.SignServerWSClientFactory;

/**
 * Command Line Interface (CLI) for signing documents.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SignDocumentCommand extends AbstractCommand {

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

    /** Option PDFPASSWORD. */
    public static final String PDFPASSWORD = "pdfpassword";

    /** Option METADATA. */
    public static final String METADATA = "metadata";

    /** The command line options. */
    private static final Options OPTIONS;

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
        OPTIONS.addOption(PDFPASSWORD, true,
                TEXTS.getString("PDFPASSWORD_DESCRIPTION"));
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
    private String host;

    /** TCP port number of the SignServer host. */
    private Integer port;

    private String servlet = "/signserver/process";

    /** File to read the data from. */
    private File inFile;

    /** File to read the signed data to. */
    private File outFile;

    /** Protocol to use for contacting SignServer. */
    private Protocol protocol = Protocol.HTTP;

    private String username;
    private String password;

    private String pdfPassword;

    private KeyStoreOptions keyStoreOptions = new KeyStoreOptions();

    /** Meta data parameters passed in */
    private Map<String, String> metadata = new HashMap<String, String>();
    
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
            .append("d) ").append(COMMAND).append(" -workerid 2 -data \"<root/>\" -keystore superadmin.jks -keystorepwd foo123").append(NL);
                
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        final HelpFormatter formatter = new HelpFormatter();
        
        PrintWriter pw = new PrintWriter(bout);
        formatter.printHelp(pw, HelpFormatter.DEFAULT_WIDTH, "signdocument <-workername WORKERNAME | -workerid WORKERID> [options]",  getDescription(), OPTIONS, HelpFormatter.DEFAULT_LEFT_PAD, HelpFormatter.DEFAULT_DESC_PAD, footer.toString());
        pw.close();
        
        return bout.toString();
    }

    /**
     * Reads all the options from the command line.
     *
     * @param line The command line to read from
     */
    private void parseCommandLine(final CommandLine line) {
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
        if (line.hasOption(PDFPASSWORD)) {
            pdfPassword = line.getOptionValue(PDFPASSWORD, null);
        }
        
        if (line.hasOption(METADATA)) {
            final String[] values = line.getOptionValues(METADATA);
            
            for (final String value : values) {
                final String[] valueSplit = value.split("=");
                
                if (valueSplit.length != 2) {
                    throw new IllegalArgumentException("Meta data parameters must be specified as KEY=VALUE");
                }
                
                metadata.put(valueSplit[0].trim(),
                        valueSplit[1].trim());
            }
        }
        
        keyStoreOptions.parseCommandLine(line);
    }

    /**
     * Checks that all mandadory options are given.
     */
    private void validateOptions() throws IllegalCommandArgumentsException {
        if (workerName == null && workerId == 0) {
            throw new IllegalCommandArgumentsException(
                    "Missing -workername or -workerid");
        } else if (data == null && inFile == null) {
            throw new IllegalArgumentException("Missing -data or -infile");
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
    private DocumentSigner createSigner() throws MalformedURLException {
        final DocumentSigner signer;

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

        switch (protocol) {
            case WEBSERVICES: {
                LOG.debug("Using SignServerWS as procotol");
            
                final String workerIdOrName;
                if (workerId == 0) {
                    workerIdOrName = workerName;
                } else {
                    workerIdOrName = String.valueOf(workerId);
                }

                signer = new WebServicesDocumentSigner(
                    host,
                    port,
                    servlet,
                    workerIdOrName,
                    keyStoreOptions.isUseHTTPS(),
                    username, password,
                    pdfPassword);
                break;
            }
            case CLIENTWS: {
                LOG.debug("Using ClientWS as procotol");
            
                final String workerIdOrName;
                if (workerId == 0) {
                    workerIdOrName = workerName;
                } else {
                    workerIdOrName = String.valueOf(workerId);
                }

                signer = new ClientWSDocumentSigner(
                    host,
                    port,
                    servlet,
                    workerIdOrName,
                    keyStoreOptions.isUseHTTPS(),
                    username, password,
                    pdfPassword);
                break;
            }
            case HTTP:
            default: {
                LOG.debug("Using HTTP as procotol");
                final URL url = new URL(keyStoreOptions.isUseHTTPS() ? "https" : "http", host, port, servlet);
                if (workerId == 0) {
                    signer = new HTTPDocumentSigner(url, workerName, username, password, pdfPassword);
                } else {
                    signer = new HTTPDocumentSigner(url, workerId, username, password, pdfPassword);
                }
            }
        }
        return signer;
    }

    /**
     * Execute the signing operation.
     */
    private void run() {
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
                if (out != null && out != System.out) {
                    out.close();
                }
            }

        } catch (FileNotFoundException ex) {
            LOG.error(MessageFormat.format(TEXTS.getString("FILE_NOT_FOUND:"),
                    ex.getLocalizedMessage()));
        } catch (IllegalRequestException ex) {
            LOG.error(ex.getLocalizedMessage());
        } catch (CryptoTokenOfflineException ex) {
            LOG.error(ex.getLocalizedMessage());
        } catch (SignServerException ex) {
            LOG.error(ex.getLocalizedMessage());
        } catch (SOAPFaultException ex) {
            if (ex.getCause() instanceof AuthorizationRequiredException) {
                final AuthorizationRequiredException authEx =
                        (AuthorizationRequiredException) ex.getCause();
                LOG.error("Authorization required: " + authEx.getMessage());
            } else if (ex.getCause() instanceof AccessDeniedException) {
                final AccessDeniedException authEx =
                        (AccessDeniedException) ex.getCause();
                LOG.error("Access denied: " + authEx.getMessage());
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
    public int execute(String[] args) throws IllegalCommandArgumentsException, CommandFailureException {
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
