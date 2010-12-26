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
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;
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

    /** Option INFILE. */
    public static final String INFILE = "infile";

    /** Option OUTFILE. */
    public static final String OUTFILE = "outfile";

    /** Option PORT. */
    public static final String PORT = "port";

    public static final String SERVLET = "servlet";

    /** Option PROTOCOL. */
    public static final String PROTOCOL = "protocol";

    public static final String USERNAME = "username";

    public static final String PASSWORD = "password";

    /** Default host */
    private static final String DEFAULT_HOST = "localhost";

    /** Default port */
    private static final String DEFAULT_PORT = "8080";

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
        OPTIONS.addOption(ENCODING, true,
                TEXTS.getString("ENCODING_DESCRIPTION"));
        OPTIONS.addOption(HOST, true,
                TEXTS.getString("HOST_DESCRIPTION"));
        OPTIONS.addOption(PORT, true,
                TEXTS.getString("PORT_DESCRIPTION"));
        OPTIONS.addOption(SERVLET, true,
                TEXTS.getString("SERVLET_DESCRIPTION"));
        OPTIONS.addOption(PROTOCOL, true,
                TEXTS.getString("PROTOCOL_DESCRIPTION"));
        OPTIONS.addOption(USERNAME, true, "Username for authentication.");
        OPTIONS.addOption(PASSWORD, true, "Password for authentication.");
    }

    /** ID of worker who should perform the operation. */
    private transient int workerId;

    /** Name of worker who should perform the operation. */
    private transient String workerName;

    /** Data to sign. */
    private transient String data;

    /** Encoding of the data, if the data should be decoded before signing. */
    private transient String encoding;

    /** Hostname or IP address of the SignServer host. */
    private transient String host;

    /** TCP port number of the SignServer host. */
    private transient int port;

    private transient String servlet = "/signserver/process";

    /** File to read the data from. */
    private transient File inFile;

    /** File to read the signed data to. */
    private transient File outFile;

    /** Protocol to use for contacting SignServer. */
    private transient Protocol protocol;

    private transient String username;

    private transient String password;

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
        port = Integer.parseInt(line.getOptionValue(PORT, DEFAULT_PORT));
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
    }

    /**
     * Checks that all mandadory options are given.
     */
    private void validateOptions() {
        if (host == null) {
            throw new IllegalArgumentException("Missing -host");
        } else if (port == 0) {
            throw new IllegalArgumentException("Missing -port");
        } else if (workerName == null && workerId == 0) {
            throw new IllegalArgumentException(
                    "Missing -workername or -workerid");
        } else if (data == null && inFile == null) {
            throw new IllegalArgumentException("Missing -data or -infile");
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

        if (Protocol.HTTP.equals(protocol)) {
            LOG.debug("Using HTTP as procotol");
            signer = new HTTPDocumentSigner(
                new URL("http", host, port, servlet),
                workerIdOrName, username, password);
        } else {
            LOG.debug("Using WebServices as procotol");
            signer = new WebServicesDocumentSigner(
                host,
                port,
                workerIdOrName,
                username,
                password);
        }
        return signer;
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
            final HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("signdocument <options>", OPTIONS);
        }
    }
}
