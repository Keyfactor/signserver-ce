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
package org.signserver.client.cli.validationservice;

import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import javax.net.ssl.SSLSocketFactory;
import org.apache.commons.cli.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.ejbca.util.CertTools;
import org.signserver.cli.CommandLineInterface;
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.client.cli.defaultimpl.ValidateDocumentCommand.Protocol;
import org.signserver.common.RequestAndResponseManager;
import org.signserver.common.SignServerUtil;
import org.signserver.protocol.ws.ProcessRequestWS;
import org.signserver.protocol.ws.ProcessResponseWS;
import org.signserver.protocol.ws.client.*;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.Validation.Status;

/**
 * TODO: Document!
 * 
 * @author Philip Vendil 13 sep 2008
 *
 * @version $Id$
 */
public class ValidateCertificateCommand extends AbstractCommand {

    private static final int DEFAULT_PORT = 8080;
    private static final int DEFAULT_SSLPORT = 8442;
    
    /** System-specific new line characters. **/
    private static final String NL = System.getProperty("line.separator");
    
    /** The name of this command. */
    private static final String COMMAND = "validatecertificate";
    
    public static final String OPTION_HELP = "help";
    public static final String OPTION_SERVICE = "service";
    public static final String OPTION_CERT = "cert";
    public static final String OPTION_SILENT = "silent";
    public static final String OPTION_PEM = "pem";
    public static final String OPTION_DER = "der";
    public static final String OPTION_HOSTS = "hosts";
    public static final String OPTION_PORT = "port";
    public static final String OPTION_CERTPURPOSES = "certpurposes";
    public static final String OPTION_TRUSTSTORE = "truststore";
    public static final String OPTION_TRUSTSTOREPWD = "truststorepwd";
    public static final String OPTION_SERVLET = "servlet";
    public static final String OPTION_PROTOCOL = "protocol";
    
    public static final int RETURN_ERROR = CommandLineInterface.RETURN_ERROR;
    public static final int RETURN_BADARGUMENT = CommandLineInterface.RETURN_INVALID_ARGUMENTS;
    public static final int RETURN_VALID = 0;
    public static final int RETURN_REVOKED = 1;
    public static final int RETURN_NOTYETVALID = 2;
    public static final int RETURN_EXPIRED = 3;
    public static final int RETURN_DONTVERIFY = 4;
    public static final int RETURN_CAREVOKED = 5;
    public static final int RETURN_CANOTYETVALID = 6;
    public static final int RETURN_CAEXPIRED = 7;
    public static final int RETURN_BADCERTPURPOSE = 8;
    
    public static final String CRLF = "\r\n";
    private static final String BOUNDARY = "------------------signserver";
    
    /**
     * Protocols that can be used for accessing SignServer.
     */
    public static enum Protocol {
        /** The Web Services interface. */
        WEBSERVICES,
        /** HTTP servlet protocol. */
        HTTP,
    }
    
    private boolean pemFlag = false;
    private boolean derFlag = false;
    private boolean silentMode = false;
    private String[] hosts = null;
    private int port = DEFAULT_PORT;
    private File certPath = null;
    private String trustStorePath = null;
    private String trustStorePwd = null;
    private boolean useSSL = false;
    private String usages = null;
    private String service = null;
    private Protocol protocol;
    
    Options options = new Options();
	private String servlet;

    public ValidateCertificateCommand() {
        Option help = new Option(OPTION_HELP, false, "Display this info");
        Option silent = new Option(OPTION_SILENT, false, "Don't produce any output, only return value.");
        Option pem = new Option(OPTION_PEM, false, "Certificate is in PEM format (Default).");
        Option der = new Option(OPTION_DER, false, "Certificate is in DER format.");

        OptionBuilder.withArgName("service-name");
        OptionBuilder.hasArg();
        OptionBuilder.withDescription("The name or id of the validation service to process request. (Required)");
        Option serviceOption = OptionBuilder.create(OPTION_SERVICE);

        OptionBuilder.withArgName("cert-file");
        OptionBuilder.hasArg();
        OptionBuilder.withDescription("Path to certificate file (DER or PEM) (Required).");
        Option certOption = OptionBuilder.create(OPTION_CERT);

        OptionBuilder.withArgName("hosts");
        OptionBuilder.hasArg();
        OptionBuilder.withDescription("A ',' separated string containing the hostnames of the validation service nodes. Ex 'host1.someorg.org,host2.someorg.org' (Required).");
        Option hostsOption = OptionBuilder.create(OPTION_HOSTS);

        OptionBuilder.withArgName("port");
        OptionBuilder.hasArg();
        OptionBuilder.withDescription("Remote port of service (Default is 8080 or 8442 for SSL).");
        Option portOption = OptionBuilder.create(OPTION_PORT);

        OptionBuilder.withArgName("certpurposes");
        OptionBuilder.hasArg();
        OptionBuilder.withDescription("A ',' separated string containing requested certificate purposes.");
        Option usagesOption = OptionBuilder.create(OPTION_CERTPURPOSES);

        OptionBuilder.withArgName("jks-file");
        OptionBuilder.hasArg();
        OptionBuilder.withDescription("Path to JKS truststore containing trusted CA for SSL Server certificates.");
        Option truststore = OptionBuilder.create(OPTION_TRUSTSTORE);

        OptionBuilder.withArgName("password");
        OptionBuilder.hasArg();
        OptionBuilder.withDescription("Password to unlock the truststore.");
        Option truststorepwd = OptionBuilder.create(OPTION_TRUSTSTOREPWD);
        
        OptionBuilder.withArgName("servlet-url");
        OptionBuilder.hasArg();
        OptionBuilder.withDescription("URL to the webservice servlet. Default: " +
        		SignServerWSClientFactory.DEFAULT_WSDL_URL + " when using the webservice protocol, otherwise /signserver/process");
        Option servlet = OptionBuilder.create(OPTION_SERVLET);
        
        OptionBuilder.withArgName("protocol");
        OptionBuilder.hasArg();
        OptionBuilder.withDescription("Protocol to use, either WEBSERVICES or HTTP. Default: WEBSERVICES.");
        Option protocol = OptionBuilder.create(OPTION_PROTOCOL);
        
        options.addOption(help);
        options.addOption(serviceOption);
        options.addOption(certOption);
        options.addOption(hostsOption);
        options.addOption(portOption);
        options.addOption(usagesOption);
        options.addOption(pem);
        options.addOption(der);
        options.addOption(silent);
        options.addOption(truststore);
        options.addOption(truststorepwd);
        options.addOption(servlet);
        options.addOption(protocol);
    }

    @Override
    public String getDescription() {
        return "Request a certificate to get validated";
    }

    @Override
    public String getUsages() {
        final StringBuilder footer = new StringBuilder();
        footer.append(NL).append("The following values is returned by the program that can be used when scripting.").append(NL).append("  -2   : Error happened during execution").append(NL).append("  -1   : Bad arguments").append(NL).append("   0   : Certificate is valid").append(NL).append("   1   : Certificate is revoked").append(NL).append("   2   : Certificate is not yet valid").append(NL).append("   3   : Certificate have expired").append(NL).append("   4   : Certificate doesn't verify").append(NL).append("   5   : CA Certificate have been revoked").append(NL).append("   6   : CA Certificate is not yet valid").append(NL).append("   7   : CA Certificate have expired.").append(NL).append("   8   : Certificate have no valid certificate purpose.").append(NL).append(NL).append("Sample usages:").append(NL).append("a) ").append(COMMAND).append(" -service CertValidationWorker -hosts localhost -cert").append(NL).append("    certificate.pem").append(NL).append("b) ").append(COMMAND).append(" -service 5806 -hosts localhost -cert certificate.pem").append(NL).append("    -truststore p12/truststore.jks -truststorepwd changeit").append(NL);

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        final HelpFormatter formatter = new HelpFormatter();
        
        PrintWriter pw = new PrintWriter(bout);
        formatter.printHelp(pw, HelpFormatter.DEFAULT_WIDTH, "Usage: signclient validatecertificate <options>\n", null, options, HelpFormatter.DEFAULT_LEFT_PAD, HelpFormatter.DEFAULT_DESC_PAD, footer.toString(), false);        
        pw.close();
        return bout.toString();
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException {
        int result = RETURN_BADARGUMENT;
        try {
            SignServerUtil.installBCProvider();

            CommandLineParser parser = new GnuParser();
            try {
                CommandLine cmd = parser.parse(options, args);
                if (cmd.hasOption(OPTION_HELP)) {
                    printUsage();
                    return RETURN_BADARGUMENT;
                }

                silentMode = cmd.hasOption(OPTION_SILENT);
                derFlag = cmd.hasOption(OPTION_DER);
                pemFlag = cmd.hasOption(OPTION_PEM);

                if (derFlag && pemFlag) {
                    err.println("Error, only one of -pem and -der options can be specified.");
                    printUsage();
                    return RETURN_BADARGUMENT;
                }

                if (!derFlag) {
                    pemFlag = true;
                }

                if (cmd.hasOption(OPTION_SERVICE) && cmd.getOptionValue(OPTION_SERVICE) != null) {
                    service = cmd.getOptionValue(OPTION_SERVICE);
                } else {
                    err.println("Error, an name or id of the validation service must be specified with the -" + OPTION_SERVICE + " option.");
                    printUsage();
                    return RETURN_BADARGUMENT;
                }

                if (cmd.hasOption(OPTION_TRUSTSTORE)) {
                    trustStorePath = cmd.getOptionValue(OPTION_TRUSTSTORE);
                    if (trustStorePath != null) {
                        File f = new File(trustStorePath);
                        if (!f.exists() || !f.canRead() || f.isDirectory()) {
                            err.println("Error, a path to the truststore must point to a readable JKS file.");
                            printUsage();
                            return RETURN_BADARGUMENT;
                        }
                    } else {
                        err.println("Error, a path to the truststore must be supplied to the -" + OPTION_TRUSTSTORE + " option.");
                        printUsage();
                        return RETURN_BADARGUMENT;
                    }
                }

                if (cmd.hasOption(OPTION_TRUSTSTOREPWD)) {
                    trustStorePwd = cmd.getOptionValue(OPTION_TRUSTSTOREPWD);
                    if (trustStorePwd == null) {
                        err.println("Error, a truststore password must be supplied to the -" + OPTION_TRUSTSTOREPWD + " option.");
                        printUsage();
                        return RETURN_BADARGUMENT;
                    }
                }

                if (trustStorePath == null ^ trustStorePwd == null) {
                    err.println("Error, if HTTPS is going to be used must both the options -" + OPTION_TRUSTSTORE + " and -" + OPTION_TRUSTSTOREPWD + " be specified");
                    printUsage();
                    return RETURN_BADARGUMENT;
                }

                useSSL = trustStorePath != null;

                if (cmd.hasOption(OPTION_HOSTS) && cmd.getOptionValue(OPTION_HOSTS) != null) {
                    hosts = cmd.getOptionValue(OPTION_HOSTS).split(",");
                } else {
                    err.println("Error, at least one validation service host must be specified.");
                    printUsage();
                    return RETURN_BADARGUMENT;
                }

                if (cmd.hasOption(OPTION_PORT)) {
                    String portString = cmd.getOptionValue(OPTION_PORT);
                    if (portString != null) {
                        try {
                            port = Integer.parseInt(portString);
                        } catch (NumberFormatException e) {
                            err.println("Error, port value must be an integer for option -" + OPTION_PORT + ".");
                            printUsage();
                            return RETURN_BADARGUMENT;
                        }
                    } else {
                        err.println("Error, a port value must be supplied to the -" + OPTION_PORT + " option.");
                        printUsage();
                        return RETURN_BADARGUMENT;
                    }
                } else {
                    if (useSSL) {
                        port = DEFAULT_SSLPORT;
                    } else {
                        port = DEFAULT_PORT;
                    }
                }

                if (cmd.hasOption(OPTION_CERTPURPOSES)) {
                    if (cmd.getOptionValue(OPTION_CERTPURPOSES) != null) {
                        usages = cmd.getOptionValue(OPTION_CERTPURPOSES);
                    } else {
                        err.println("Error, at least one usage must be specified with the -" + OPTION_CERTPURPOSES + " option.");
                        printUsage();
                        return RETURN_BADARGUMENT;
                    }
                }

                if (cmd.hasOption(OPTION_CERT) && cmd.getOptionValue(OPTION_CERT) != null) {
                    certPath = new File(cmd.getOptionValue(OPTION_CERT));
                    if (!certPath.exists() || !certPath.canRead() || certPath.isDirectory()) {
                        err.println("Error, the certificate file must exist and be readable by the user.");
                        printUsage();
                        return RETURN_BADARGUMENT;
                    }
                } else {
                    err.println("Error, the certificate to validate must be specified with the -" + OPTION_CERT + " option.");
                    printUsage();
                    return RETURN_BADARGUMENT;
                }
                
                // set the default servlet URL value
                servlet = SignServerWSClientFactory.DEFAULT_WSDL_URL;
                
                if (cmd.hasOption(OPTION_SERVLET) &&
                		cmd.getOptionValue(OPTION_SERVLET) != null) {
                	servlet = cmd.getOptionValue(OPTION_SERVLET);
                }
                
                if (cmd.hasOption(OPTION_PROTOCOL)) {
                    protocol = Protocol.valueOf(cmd.getOptionValue(OPTION_PROTOCOL));
                    // override default servlet URL (if not set manually) for HTTP
                    if (Protocol.HTTP.equals(protocol) &&
                            !cmd.hasOption(OPTION_SERVLET)) {
                        servlet = "/signserver/process";
                    }
                }


            } catch (ParseException e) {
                err.println("Error occurred when parsing options.  Reason: " + e.getMessage());
                printUsage();
                return RETURN_BADARGUMENT;
            }

            if (args.length < 1) {
                printUsage();
                return RETURN_BADARGUMENT;
            }
            result = run();
        } catch (Exception e) {
            if (!e.getClass().getSimpleName().equals("ExitException")) {
                
                err.println("Error occured during validation : " + e.getClass().getName());
                if (e.getMessage() != null) {
                    err.println("  Message : " + e.getMessage());
                }
                result = RETURN_ERROR;
            }
        }
        return result;
    }

    private int run() throws Exception {

        
        // read certificate
        X509Certificate cert = null;
        FileInputStream fis = new FileInputStream(certPath);
        try {
            if (pemFlag) {
                Collection<?> certs = CertTools.getCertsFromPEM(fis);
                if (certs.iterator().hasNext()) {
                    cert = (X509Certificate) certs.iterator().next();
                }
            } else {
                byte[] data = new byte[fis.available()];
                fis.read(data, 0, fis.available());
                cert = (X509Certificate) CertTools.getCertfromByteArray(data);
            }
        } finally {
            fis.close();
        }

        if (cert == null) {
            println("Error, Certificate in file " + certPath + " not read succesfully.");
        }

        println("\n\nValidating certificate with: ");
        println("  Subject    : " + cert.getSubjectDN().toString());
        println("  Issuer     : " + cert.getIssuerDN().toString());
        println("  Valid From : " + cert.getNotBefore());
        println("  Valid To   : " + cert.getNotAfter());

        println("\n");
        
        // validate
        final ValidateResponse vresp;
        switch (protocol) {
        case WEBSERVICES:
            // set up trust
            SSLSocketFactory sslf = null;
            if (trustStorePath != null) {
                sslf = WSClientUtil.genCustomSSLSocketFactory(null, null, trustStorePath, trustStorePwd);
            }

            vresp = runWS(sslf, cert);
            break;
        case HTTP:
            vresp = runHTTP(cert);
            break;
        default:
            throw new IllegalArgumentException("Unknown protocol: " + protocol.toString());
        };
        
        
        // output result
        String certificatePurposes = vresp.getValidCertificatePurposes();
        println("Valid Certificate Purposes:\n  " + (certificatePurposes == null ? "" : certificatePurposes));
        Validation validation = vresp.getValidation();
        println("Certificate Status:\n  " + validation.getStatus());

        return getReturnValue(validation.getStatus());
    }
    
    /**
     * Run validation using the webservice interface.
     * 
     * @param sslf SSL socket factory
     * @param cert Certificate to validate
     * @return The validation response
     * @throws CertificateEncodingException
     * @throws IOException
     */
    private ValidateResponse runWS(final SSLSocketFactory sslf, final X509Certificate cert)
            throws CertificateEncodingException, IOException {
        SignServerWSClientFactory fact = new SignServerWSClientFactory();
        ISignServerWSClient client = fact.generateSignServerWSClient(SignServerWSClientFactory.CLIENTTYPE_CALLFIRSTNODEWITHSTATUSOK,
                hosts, useSSL,
                new LogErrorCallback(),
                port, SignServerWSClientFactory.DEFAULT_TIMEOUT,
                servlet,
                sslf);

        ValidateRequest vr = new ValidateRequest(cert, usages);

        ArrayList<ProcessRequestWS> requests = new ArrayList<ProcessRequestWS>();
        requests.add(new ProcessRequestWS(vr));
        List<ProcessResponseWS> response = client.process(service, requests);
        if (response == null) {
            throw new IOException("Error communicating with valdation servers, no server in the cluster seem available.");
        }
        ValidateResponse vresp = (ValidateResponse) RequestAndResponseManager.parseProcessResponse(response.get(0).getResponseData());

        return vresp;
    }
    
    private ValidateResponse runHTTP(final X509Certificate cert) throws Exception {
        
        final URL processServlet = new URL(useSSL ? "https" : "http", hosts[0], port, servlet);
        
        OutputStream out = null;
        InputStream in = null;
        
        try {
            final URLConnection conn = processServlet.openConnection();
        
            conn.setDoOutput(true);
            conn.setAllowUserInteraction(false);
            
            final StringBuilder sb = new StringBuilder();
            sb.append("--" + BOUNDARY);
            sb.append(CRLF);
            
            try {
                final int workerId = Integer.parseInt(service);
                
                sb.append("Content-Disposition: form-data; name=\"workerId\"");
                sb.append(CRLF);
                sb.append(CRLF);
                sb.append(workerId);
            } catch (NumberFormatException e) {
                sb.append("Content-Disposition: form-data; name=\"workerName\"");
                sb.append(CRLF);
                sb.append(CRLF);
                sb.append(service);
            }

            sb.append(CRLF);
            sb.append("--" + BOUNDARY);
            sb.append(CRLF);
            
            sb.append("Content-Disposition: form-data; name=\"processType\"");
            sb.append(CRLF);
            sb.append(CRLF);
            sb.append("validateCertificate");
            sb.append(CRLF);
            sb.append("--" + BOUNDARY);
            sb.append(CRLF);
            sb.append("Content-Disposition: form-data; name=\"datafile\"");
            sb.append("; filename=\"");
            sb.append(certPath.getAbsolutePath());
            sb.append("\"");
            sb.append(CRLF);
            
            sb.append("Content-Type: application/octet-stream");
            sb.append(CRLF);
            sb.append("Content-Transfer-Encoding: binary");
            sb.append(CRLF);
            sb.append(CRLF);

            conn.addRequestProperty("Content-Type",
                    "multipart/form-data; boundary=" + BOUNDARY);
            conn.addRequestProperty("Content-Length", String.valueOf(
                    sb.toString().length() + BOUNDARY.length() + 8-1));
            
            out = conn.getOutputStream();
            
            out.write(sb.toString().getBytes());
            
            out.write(cert.getEncoded());
            
            out.write(("\r\n--" + BOUNDARY + "--\r\n").getBytes());
            out.flush();
            
            // Get the response
            in = conn.getInputStream();
            final ByteArrayOutputStream os = new ByteArrayOutputStream();
            int len;
            final byte[] buf = new byte[1024];
            while ((len = in.read(buf)) > 0) {
                os.write(buf, 0, len);
            }
            os.close();
            
            // read string from response
            final String response = os.toString();
            final String[] responseParts = response.split(";");
            
            // last part of the response string can by empty (revocation date)
            if (responseParts.length < 4 || responseParts.length > 5) {
                throw new IOException("Malformed HTTP response");
            }
            
            final String revocationDateString = responseParts.length == 4 ? null : responseParts[4];
            final Date revocationDate =
                    revocationDateString != null && revocationDateString.length() > 0 ?
                            new Date(Integer.valueOf(revocationDateString)) : null;
            final Validation validation =
                    new Validation(cert, null, Validation.Status.valueOf(responseParts[0]), responseParts[2],
                            revocationDate, Integer.valueOf(responseParts[3]));
            final ValidateResponse validateResponse = new ValidateResponse(validation, responseParts[1].split(","));
            
            return validateResponse;
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }
        }
    }

    private void println(String string) {
        if (!silentMode) {
            out.println(string);
        }

    }

    private int getReturnValue(Status status) {
        if (status == Status.VALID) {
            return RETURN_VALID;
        }
        if (status == Status.REVOKED) {
            return RETURN_REVOKED;
        }
        if (status == Status.NOTYETVALID) {
            return RETURN_NOTYETVALID;
        }
        if (status == Status.EXPIRED) {
            return RETURN_EXPIRED;
        }
        if (status == Status.DONTVERIFY) {
            return RETURN_DONTVERIFY;
        }
        if (status == Status.CAREVOKED) {
            return RETURN_CAREVOKED;
        }
        if (status == Status.CANOTYETVALID) {
            return RETURN_CANOTYETVALID;
        }
        if (status == Status.CAEXPIRED) {
            return RETURN_CAEXPIRED;
        }
        if (status == Status.BADCERTPURPOSE) {
            return RETURN_BADCERTPURPOSE;
        }
        return RETURN_ERROR;
    }

    class LogErrorCallback implements IFaultCallback {

        @SuppressWarnings("synthetic-access")
        public void addCommunicationError(ICommunicationFault error) {
            final String s = "Error communication with host : " + error.getHostName() + ", " + error.getDescription();
            if (error.getThrowed() != null) {
                out.println(s);
                error.getThrowed().printStackTrace();
            } else {
                out.println(s);
            }
        }
    }

    private void printUsage() {
        out.println(getUsages());
    }
   
}
