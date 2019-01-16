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
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import org.apache.commons.cli.*;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.*;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.cli.CommandLineInterface;
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;

/**
 * Class making a simple timestamp request to a timestamp server and tries to
 * validate it.
 *
 *
 * @author philip
 * @version $Id$
 */
public class TimeStampCommand extends AbstractCommand {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TimeStampCommand.class);

    /** System-specific new line characters. **/
    private static final String NL = System.getProperty("line.separator");

    /** The name of this command. */
    private static final String COMMAND = "timestamp";

    private static final int PARAM_URL = 0;

    /** Begin key for certificates in PEM format. */
    private static final String PEM_BEGIN = "-----BEGIN CERTIFICATE-----";

    /** End key for certificates in PEM format. */
    private static final String PEM_END = "-----END CERTIFICATE-----";
    
    /** OID for the ETSI qualified timestamping extension value. */
    private static final ASN1ObjectIdentifier ID_ETSI_TSTS;
    
    /**
     * OID for default digest algorithm to be used while creating timestamp
     * request.
     */
    private static final ASN1ObjectIdentifier DEFAULT_DIGEST_ALGORITHM = TSPAlgorithms.SHA256;
    private static final int DEFAULT_DIGEST_ALGORITHM_OUTPUT_LENGTH = 32; //SHA-256;

    private String urlstring;

    private String outrepstring;

    private String inrepstring;

    /** Filename to read a pre-formatted request from. */
    private String inreqstring;

    private String outreqstring;

    private String instring;

    private String infilestring;

    private String signerfilestring;
    
    private String digestalgorithm;

    private boolean base64;

    private boolean verify;
    private boolean print;

    /** Number of milliseconds to sleep after a request. */
    private int sleep = 1000;

    private boolean certReq;
    private String reqPolicy;
    
    private final Options options = new Options();
    
    private final KeyStoreOptions keyStoreOptions = new KeyStoreOptions();
    
    static {
        ID_ETSI_TSTS = new ASN1ObjectIdentifier("0.4.0.19422.1.1");
    }
    
    public TimeStampCommand() {
        // Create options
        final Option help = new Option("help", false, "Print this message.");
        final Option b64 = new Option("base64", false,
                "Give this option if the stored request/reply should be "
                + "base64 encoded, default is not.");
        final Option verifyopt = new Option("verify", false,
                "Give this option if verification of a stored reply should "
                + "be done, work together with inrep and cafile. If given, no "
                + "request to the TSA will happen.");
        final Option printopt = new Option("print", false,
                "Prints content of a request, response and/or token");

        OptionBuilder.hasArg();
        OptionBuilder.withDescription("Url of TSA, e.g. "
                + "http://127.0.0.1:8080/signserver/process?workerId=1.");
        OptionBuilder.withArgName("url");
        final Option url = OptionBuilder.create("url");

        OptionBuilder.hasArg();
        OptionBuilder.withArgName("file");
        OptionBuilder.withDescription("Output file to store the recevied TSA "
                + "reply, if not given the reply is not stored.");
        final Option outrep = OptionBuilder.create("outrep");

        OptionBuilder.hasArg();
        OptionBuilder.withArgName("file");
        OptionBuilder.withDescription("Input file containing an earlier stored "
                + "base64 encoded response, to verify."
                + "You must specify the verify flag also.");
        final Option inrep = OptionBuilder.create("inrep");

        OptionBuilder.hasArg();
        OptionBuilder.withArgName("file");
        OptionBuilder.withDescription("Input file containing the PEM encoded "
                + "certificate of the TSA signer."
                + "Used to verify a stored response.");
        final Option cafileopt = OptionBuilder.create("signerfile");

        OptionBuilder.hasArg();
        OptionBuilder.withArgName("file");
        OptionBuilder.withDescription("Output file to store the sent TSA "
                + "request, if not given the request is not stored.");
        final Option outreq = OptionBuilder.create("outreq");

        OptionBuilder.hasArg();
        OptionBuilder.withArgName("file");
        OptionBuilder.withDescription("File containing message to time stamp.");
        final Option infile = OptionBuilder.create("infile");

        OptionBuilder.hasArg();
        OptionBuilder.withArgName("string");
        OptionBuilder.withDescription("String to be time stamped, if neither "
                + "instr or infile is given, the client works in test-mode "
                + "generating it's own message.");
        final Option instr = OptionBuilder.create("instr");

        OptionBuilder.hasArg();
        OptionBuilder.withArgName("file");
        OptionBuilder.withDescription("Input file containing an earlier stored "
                + "request to use instead of creating a new. "
                + "You must specify the request flag also.");
        final Option inreq = OptionBuilder.create("inreq");
        
        OptionBuilder.hasArg();
        OptionBuilder.withArgName("string");
        OptionBuilder.withDescription("Digest algorithm used for creating timestamp request hash. Default SHA256");
        final Option digestAlgorithm = OptionBuilder.create("digestalgorithm");

        OptionBuilder.hasArg();
        OptionBuilder.withArgName("num");
        OptionBuilder.withDescription("Sleep a number of milliseconds after "
                + "each request. Default 1000 ms.");
        final Option optionSleep = OptionBuilder.create("sleep");
        
        OptionBuilder.hasArg(false);
        OptionBuilder.withDescription("Request signer certificate");
        final Option certReqOption = OptionBuilder.create("certreq");
        
        OptionBuilder.hasArg();
        OptionBuilder.withArgName("oid");
        OptionBuilder.withDescription("Request timestamp issued under a policy OID");
        final Option reqPolicyOption = OptionBuilder.create("reqpolicy");
        
        // Add options
        options.addOption(help);
        options.addOption(verifyopt);
        options.addOption(printopt);
        options.addOption(url);
        options.addOption(outrep);
        options.addOption(inrep);
        options.addOption(cafileopt);
        options.addOption(outreq);
        options.addOption(b64);
        options.addOption(infile);
        options.addOption(instr);
        options.addOption(inreq);
        options.addOption(optionSleep);
        options.addOption(certReqOption);
        options.addOption(reqPolicyOption);
        options.addOption(digestAlgorithm);
       
        for (Option option : KeyStoreOptions.getKeyStoreOptions()) {
            options.addOption(option);
        }
    }

    @Override
    public String getDescription() {
        return "Send time stamp requests to a TSA";
    }

    @Override
    public String getUsages() {
        return usage(options);
    }
    
    private String usage(final Options options) {
        // automatically generate the help statement
        final HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("timestamp <options> [url]",
                options);
        final StringBuilder footer = new StringBuilder();
        footer.append(NL)
            .append("Sample usages:").append(NL)
            .append("a) ").append(COMMAND).append(" -url http://localhost:8080/signserver/tsa?workerName=TimeStampSigner").append(NL)
            .append("b) ").append(COMMAND).append(" -print -inreq query.tsq").append(NL)
            .append("c) ").append(COMMAND).append(" -print -inrep reply.tsr").append(NL);
        return footer.toString();
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {

        final CommandLineParser parser = new GnuParser();
        try {
            final CommandLine cmd = parser.parse(options, args);
            if (cmd.hasOption("help")) {
                out.println(usage(options));
                return CommandLineInterface.RETURN_SUCCESS;
            }
            if (cmd.hasOption("url")) {
                urlstring = cmd.getOptionValue("url");
            }
            if (cmd.hasOption("instr")) {
                instring = cmd.getOptionValue("instr");
            }
            if (cmd.hasOption("infile")) {
                infilestring = cmd.getOptionValue("infile");
            }
            if (cmd.hasOption("outrep")) {
                outrepstring = cmd.getOptionValue("outrep");
            }
            if (cmd.hasOption("inrep")) {
                inrepstring = cmd.getOptionValue("inrep");
            }
            if (cmd.hasOption("signerfile")) {
                signerfilestring = cmd.getOptionValue("signerfile");
            }
            if (cmd.hasOption("outreq")) {
                outreqstring = cmd.getOptionValue("outreq");
            }
            if (cmd.hasOption("base64")) {
                base64 = true;
            }
            if (cmd.hasOption("verify")) {
                verify = true;
            }
            if (cmd.hasOption("print")) {
                print = true;
            }
            if (cmd.hasOption("inreq")) {
                inreqstring = cmd.getOptionValue("inreq");
            }
            if (cmd.hasOption("sleep")) {
                sleep = Integer.parseInt(cmd.getOptionValue("sleep"));
            }
            final String[] strargs = cmd.getArgs();
            if (strargs.length > 0) {
                urlstring = strargs[PARAM_URL];
            }
            if (cmd.hasOption("certreq")) {
                certReq = true;
            }
            if (cmd.hasOption("reqpolicy")) {
                reqPolicy = cmd.getOptionValue("reqpolicy");
            }
            if (cmd.hasOption("digestalgorithm")) {
                digestalgorithm = cmd.getOptionValue("digestalgorithm");
            }
            
            try {
                final ConsolePasswordReader passwordReader = createConsolePasswordReader();
                keyStoreOptions.parseCommandLine(cmd, passwordReader, out);

                // TODO: Add when implementing username/password auth support:
                // Prompt for user password if not given
                //if (username != null && password == null) {
                //    out.print("Password for user '" + username + "': ");
                //    out.flush();
                //    password = new String(passwordReader.readPassword());
                //}
            } catch (IOException ex) {
                throw new IllegalCommandArgumentsException("Failed to read password: " + ex.getLocalizedMessage());
            }

            if (print && inreqstring == null && inrepstring == null) {
                LOG.error("Missing -inreq or -inrep");
                out.println(usage(options));
                return CommandLineInterface.RETURN_INVALID_ARGUMENTS;
            }
            
            if (args.length < 1) {
                out.println(usage(options));
                return CommandLineInterface.RETURN_INVALID_ARGUMENTS;
            } else if (urlstring == null && !verify && !print) {
                LOG.error("Missing URL");
                out.println(usage(options));
                return CommandLineInterface.RETURN_INVALID_ARGUMENTS;
            } else { 
                keyStoreOptions.validateOptions();
                
                if (Security.addProvider(new BouncyCastleProvider()) < 0) {
                    LOG.error("Could not install BC provider");
                    // If already installed, remove so we can handle redeploy
                    Security.removeProvider("BC");
                    if (Security.addProvider(new BouncyCastleProvider()) < 0) {
                        LOG.error("Cannot even install BC provider again!");
                    }
                }
                
                run();
                return CommandLineInterface.RETURN_SUCCESS;
            }
        } catch (ParseException e) {
            // oops, something went wrong
            out.println(usage(options));
            return CommandLineInterface.RETURN_INVALID_ARGUMENTS;
        } catch (HTTPException ex) {
            err.println("Failure: HTTP error: " + ex.getResponseCode() + ": " +
                    ex.getResponseMessage());
            return CommandLineInterface.RETURN_ERROR;
        } catch (Exception ex) {
            throw new UnexpectedCommandFailureException(ex);
        }
    }
    
    /**
     * @return a ConsolePasswordReader that can be used to read passwords
     */
    protected ConsolePasswordReader createConsolePasswordReader() {
        return new DefaultConsolePasswordReader();
    }

    private void run() throws Exception {
        // Take start time
        final long startTime = System.nanoTime();
        
        if (print) {
            tsaPrint();
        }
        else if (verify) {
            tsaVerify();
        } else {
            tsaRequest();
        }

        // Take stop time
        final long estimatedTime = System.nanoTime() - startTime;

        LOG.info("Processing took "
                + TimeUnit.NANOSECONDS.toMillis(estimatedTime) + " ms");
    }
    
    private void tsaPrint() throws Exception {

        if (inrepstring == null) {
            tsaPrintQuery();
        } else {
            tsaPrintReply();
        }
    }
    
    private void tsaPrintReply() throws Exception {
        final byte[] bytes = readFiletoBuffer(inrepstring);

        TimeStampResponse response = null;
        out.println("Time-stamp response {");
        try {
            response = new TimeStampResponse(bytes);
            out.println("  Status:                           " + response.getStatus());
            out.println("  Status message:                   " + response.getStatusString());
        } catch (TSPException ex) {
            out.println("  Not a response");
        }
        if (response != null) {
            PKIFailureInfo failureInfo = response.getFailInfo();
            if (failureInfo != null) {
                out.print("  Failure info:                          ");
                out.println(failureInfo.intValue());
            }
        }

        final TimeStampToken token;
        if (response == null) {
            token = new TimeStampToken(new CMSSignedData(bytes));
        } else {
            token = response.getTimeStampToken();
        }          
        if (token != null) {
            out.println("  Time-stamp token:");
            TimeStampTokenInfo info = token.getTimeStampInfo();
            if (info != null) {
                out.println("      Info:");
                out.print("         " + "Gen Time:                  ");
                out.println(info.getGenTime());

                out.print("         " + "Gen Time Accuracy:         ");
                out.println(info.getGenTimeAccuracy());

                out.print("         " + "Message imprint digest:    ");
                out.println(new String(Hex.encode(info.getMessageImprintDigest())));

                out.print("         " + "Message imprint algorithm: ");
                out.println(info.getMessageImprintAlgOID());

                out.print("         " + "Nonce:                     ");
                out.println(info.getNonce() != null ? info.getNonce().toString(16) : "(null)");

                out.print("         " + "Serial Number:             ");
                out.println(info.getSerialNumber() != null ? info.getSerialNumber().toString(16) : "(null)");

                out.print("         " + "TSA:                       ");
                out.println(info.getTsa() != null ? info.getTsa() : "(null)");

                out.print("         " + "Policy:                    ");
                out.println(info.getPolicy());
                
                
                final Extensions exts = info.toASN1Structure().getExtensions();
                
                if (exts != null) {
                    out.println("      Extensions: ");
                    for (final ASN1ObjectIdentifier oid : exts.getExtensionOIDs()) {
                        final Extension extension = exts.getExtension(oid);
                        
                        out.println("        OID: " + oid.getId());
                        out.println("        Critical: " +
                                    (extension.isCritical() ? "yes" : "no"));
                        
                        if (oid.equals(Extension.qCStatements)) {
                            printQualifiedStatement(extension);
                        }
                    }
                    
                }
            }
            out.println("      Signer ID: ");
            out.println("         Serial Number:             " + token.getSID().getSerialNumber().toString(16));
            out.println("         Issuer:                    " + token.getSID().getIssuer());

            out.println("      Signer certificate:           ");

            Store  certs = token.getCertificates();             
            Selector signerSelector = new AttributeCertificateHolder(token.getSID().getIssuer(), token.getSID().getSerialNumber());

            Collection certCollection = certs.getMatches(signerSelector);
            for (Object o : certCollection) {
                if (o instanceof X509CertificateHolder) {
                    X509CertificateHolder cert = (X509CertificateHolder) o;
                    out.println("         Certificate: ");
                    out.println("            Serial Number:          " + cert.getSerialNumber().toString(16));
                    out.println("            Subject:                " + cert.getSubject());
                    out.println("            Issuer:                 " + cert.getIssuer());
                } else {
                    out.println("Not an X.509 certificate: " + o);
                }
            }

            out.println("      Other certificates: ");
            certCollection = certs.getMatches(new InvertedSelector(signerSelector));
            for (Object o : certCollection) {
                if (o instanceof X509CertificateHolder) {
                    X509CertificateHolder cert = (X509CertificateHolder) o;
                    out.println("         Certificate: ");
                    out.println("            Serial Number:          " + cert.getSerialNumber().toString(16));
                    out.println("            Subject:                " + cert.getSubject());
                    out.println("            Issuer:                 " + cert.getIssuer());
                } else {
                    out.println("Not an X.509 certificate: " + o);
                }
            }
        }
        out.println("}");
    }
    
    private void printQualifiedStatement(final Extension extension)
        throws IOException {
        out.println("          Qualified statement");
        
        try {
            final ASN1Sequence seq =
                    ASN1Sequence.getInstance(extension.getExtnValue().getOctets());

            if (seq != null) {
                final QCStatement statement =
                        QCStatement.getInstance(seq.getObjectAt(0));

                if (statement != null) {
                    final ASN1Encodable statementInfo =
                            statement.getStatementInfo();
                    final ASN1ObjectIdentifier oid =
                            statement.getStatementId();

                    out.print("          Statement ID: " + oid.getId());

                    if (ID_ETSI_TSTS.equals(oid)) {
                        out.println(" (ETSI EN 319 422 compliant)");
                    }

                    out.println();

                    if (statementInfo != null) {
                        out.println("          Statement info: " +
                                    Hex.toHexString(statementInfo.toASN1Primitive().getEncoded()));
                    }
                }
            }
        } catch (IllegalArgumentException ex) {
            out.println("          Failed to parse extension value: " +
                        ex.getMessage());
        }
    }
    
    private void tsaPrintQuery() throws Exception {
        final byte[] bytes = readFiletoBuffer(inreqstring);

        final TimeStampRequest request;
        out.println("Time-stamp request {");
        
        request = new TimeStampRequest(bytes);
        out.println("  Version:                          " + request.getVersion());

        out.print("  Message imprint digest:           ");
        out.println(new String(Hex.encode(request.getMessageImprintDigest())));

        out.print("  Message imprint algorithm:        ");
        out.println(request.getMessageImprintAlgOID());

        out.print("  Policy:                           ");
        out.println(request.getReqPolicy() != null ? request.getReqPolicy() : "(null)");

        out.print("  Nonce:                            ");
        out.println(request.getNonce() != null ? request.getNonce().toString(16) : "(null)");

        out.print("  Request certificates:             ");
        out.println(request.getCertReq());

        if (request.hasExtensions()) {
            out.print("  Extensions: ");
            for (Object oid : request.getExtensionOIDs()) {
                final ASN1ObjectIdentifier asn1Oid =
                        (ASN1ObjectIdentifier) oid;
                final Extension ext = request.getExtension(asn1Oid);
                out.print("    " + oid + ": ");
                out.println(new String(Hex.encode(ext.getEncoded())));

                if (asn1Oid.equals(Extension.qCStatements)) {
                    printQualifiedStatement(ext);
                }
            }
        }
                
        out.println("}");
    }
    
    private static class InvertedSelector implements Selector {

        private final Selector delegate;
        
        public InvertedSelector(Selector delegate) {
            this.delegate = delegate;
        }
        
        @Override
        public boolean match(Object cert) {
            return !delegate.match(cert);
        }

        @Override
        @SuppressWarnings({"CloneDeclaresCloneNotSupported", "CloneDoesntCallSuperClone"}) // Selector interface does not declare CloneNotSupported
        public Object clone() {
            return new InvertedSelector((Selector) delegate.clone());
        }

    }

    private void tsaVerify() throws Exception {
        if (inrepstring == null) {
            LOG.error("Needs an inrep!");
        } else if (signerfilestring == null) {
            LOG.error("Needs a signerfile!");
        } else {
            final Collection<X509Certificate> col =
                    getCertsFromPEM(signerfilestring);
            final X509Certificate[] list = (X509Certificate[]) col.toArray(
                    new X509Certificate[0]);
            if (list.length == 0) {
                LOG.error("No certificate found in file: " + signerfilestring);
                return;
            }

            final byte[] b64Bytes = readFiletoBuffer(inrepstring);
            final byte[] replyBytes = Base64.decode(b64Bytes);

            final TimeStampResponse timeStampResponse =
                    new TimeStampResponse(replyBytes);
            final TimeStampToken token = timeStampResponse.getTimeStampToken();
            final SignerInformationVerifier infoVerifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(list[0]);
            token.validate(infoVerifier);
            LOG.info("Token was validated successfully.");

            final TimeStampTokenInfo info = token.getTimeStampInfo();
            LOG.info("Token was generated on: " + info.getGenTime());

            if (LOG.isDebugEnabled()) {
                if (info.getMessageImprintAlgOID().equals(TSPAlgorithms.SHA1)) {
                    LOG.debug("Token hash alg: SHA1");
                } else {
                    LOG.debug("Token hash alg: " + info.getMessageImprintAlgOID());
                }
            }
            final byte[] hexDigest = Hex.encode(info.getMessageImprintDigest());
            LOG.info("MessageDigest=" + new String(hexDigest));
        }
    }

    @SuppressWarnings("SleepWhileInLoop") // We are just using the sleep for rate limiting
    private void tsaRequest() throws Exception {
        final Random rand = new Random();
        final TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        boolean doRun = true;
        ASN1ObjectIdentifier requestDigestAlgorithm = DEFAULT_DIGEST_ALGORITHM;
        int digestLength = DEFAULT_DIGEST_ALGORITHM_OUTPUT_LENGTH;
        do {

            if (digestalgorithm != null) {
                requestDigestAlgorithm = getDigestAlgorithmFromString(digestalgorithm);
                digestLength = getOutputSizeBitsFromDigestAlgorithmString(digestalgorithm) / 8;
            }

            final int nonce = rand.nextInt();

            byte[] digest = new byte[digestLength];
            if (instring != null) {
                final byte[] digestBytes = instring.getBytes(StandardCharsets.UTF_8);
                final MessageDigest dig = MessageDigest.getInstance(
                        requestDigestAlgorithm.getId(),
                        "BC");
                dig.update(digestBytes);
                digest = dig.digest();
                // When we have given input, we don't want to loop
                doRun = false;
            }
            if (infilestring != null) {
            	// TSPAlgorithms constants changed from Strings to ASN1Encoded objects
                digest = digestFile(infilestring, requestDigestAlgorithm.getId());
                doRun = false;
            }
            final byte[] hexDigest = Hex.encode(digest);

            if (LOG.isDebugEnabled()) {
                LOG.debug("MessageDigest=" + new String(hexDigest));
            }

            final TimeStampRequest timeStampRequest;
            if (inreqstring == null) {
                LOG.debug("Generating a new request");
                timeStampRequestGenerator.setCertReq(certReq);
                if (reqPolicy != null) {
                    timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier(reqPolicy));
                }
                timeStampRequest = timeStampRequestGenerator.generate(
                        requestDigestAlgorithm, digest, BigInteger.valueOf(nonce));
            } else {
                LOG.debug("Reading request from file");
                timeStampRequest = new TimeStampRequest(
                        readFiletoBuffer(inreqstring));
            }
            final byte[] requestBytes = timeStampRequest.getEncoded();

            if (outreqstring != null) {
                // Store request
                byte[] outBytes;
                if (base64) {
                    outBytes = Base64.encode(requestBytes);
                } else {
                    outBytes = requestBytes;
                }
                try (FileOutputStream fos = new FileOutputStream(outreqstring)) {
                    fos.write(outBytes);
                }
            }
            
            final SSLSocketFactory sf = keyStoreOptions.setupHTTPS();
            
            if (sf != null) {
                HttpsURLConnection.setDefaultSSLSocketFactory(sf);
            }

            URL url;
            HttpURLConnection urlConn;
            DataOutputStream printout;
            DataInputStream input;

            url = new URL(urlstring);

            // Take start time
            final long startMillis = System.currentTimeMillis();
            final long startTime = System.nanoTime();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Sending request at: " + startMillis);
            }

            urlConn = (HttpURLConnection) url.openConnection();

            urlConn.setDoInput(true);
            urlConn.setDoOutput(true);
            urlConn.setUseCaches(false);
            urlConn.setRequestProperty("Content-Type",
                    "application/timestamp-query");
            
            // Send POST output.
            printout = new DataOutputStream(urlConn.getOutputStream());
            printout.write(requestBytes);
            printout.flush();
            printout.close();

            // Get response data.
            final int responseCode = urlConn.getResponseCode();
            
            if (responseCode >= 400) {
                input = new DataInputStream(urlConn.getErrorStream());
            } else {
                input = new DataInputStream(urlConn.getInputStream());
            }
                
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            int b;
            while ((b = input.read()) != -1) {
                baos.write(b);
            }
            
            if (responseCode >= 400) {
                throw new HTTPException(url, responseCode,
                                        urlConn.getResponseMessage(),
                                        baos.toByteArray());
            }

            // Take stop time
            final long estimatedTime = System.nanoTime() - startTime;

            LOG.info("Got reply after "
                + TimeUnit.NANOSECONDS.toMillis(estimatedTime) + " ms");

            final byte[] replyBytes = baos.toByteArray();
            if (outrepstring != null) {
                // Store request
                byte[] outBytes;
                if (base64) {
                    outBytes = Base64.encode(replyBytes);
                } else {
                    outBytes = replyBytes;
                }
                try (FileOutputStream fos = new FileOutputStream(outrepstring)) {
                    fos.write(outBytes);
                }
            }

            final TimeStampResponse timeStampResponse = new TimeStampResponse(
                    replyBytes);
            timeStampResponse.validate(timeStampRequest);

            final int status = timeStampResponse.getStatus();
            final PKIFailureInfo failInfo = timeStampResponse.getFailInfo();
            final String statusString = timeStampResponse.getStatusString();
            
            final StringBuilder sb = new StringBuilder();
            
            sb.append("TimeStampRequest validated with status code: ");
            sb.append(status);
            
            if (failInfo != null) {
                sb.append(", failure: ");
                sb.append(failInfo);
            }
            
            if (statusString != null && !"".equals(statusString)) {
                sb.append(" (");
                sb.append(statusString);
                sb.append(")");
            }
            LOG.info(sb.toString());

            if (LOG.isDebugEnabled()) {
                final Date genTime;
                if (timeStampResponse.getTimeStampToken() != null && timeStampResponse.getTimeStampToken().getTimeStampInfo() != null) {
                    genTime = timeStampResponse.getTimeStampToken().getTimeStampInfo().getGenTime();
                } else {
                    genTime = null;
                }
                LOG.debug("(Status: " + status
                        + ", " + failInfo + "): "
                        + statusString + (genTime != null ? (", genTime: " + genTime.getTime()) : "") + "\n");
                
            }

            if (doRun) {
                Thread.sleep(sleep);
            }
        } while (doRun);
    }

    /**
     * Helpfunction to read a file to a byte array.
     *
     * @param file filename of file.
     * @return byte[] containing the contents of the file.
     * @throws IOException if the file does not exist or cannot be read.
     */
    private byte[] readFiletoBuffer(final String file) throws IOException {

        ByteArrayOutputStream os = null;
        InputStream in = null;
        try {
            os = new ByteArrayOutputStream();
            in = new FileInputStream(file);
            int len;
            final byte[] buf = new byte[1024];

            while ((len = in.read(buf)) > 0) {
                os.write(buf, 0, len);
            }
            
            return os.toByteArray();
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    ex.printStackTrace(System.err);
                }
            }
            if (os != null) {
                try {
                    os.close();
                } catch (IOException ex) {
                    ex.printStackTrace(System.err);
                }
            }
        }
    }

    /**
     * Helpfunction to calculate the digest of a big file.
     *
     * @param file filename of file.
     * @param digestAlg the digest algorithm.
     * @return byte[] containing the digest of the file.
     * @throws IOException if the file does not exist or cannot be read.
     * @throws NoSuchProviderException if BC provider is not installed
     * @throws NoSuchAlgorithmException if the given hash algorithm does not
     * exist
     */
    private byte[] digestFile(final String file, final String digestAlg) throws
            IOException, NoSuchAlgorithmException, NoSuchProviderException {

        final MessageDigest dig = MessageDigest.getInstance(digestAlg, "BC");

        InputStream in = null;
        try {
            in = new FileInputStream(file);

            final byte[] buf = new byte[2048];
            int len;
            while ((len = in.read(buf)) > 0) {
                dig.update(buf, 0, len);
            }

            return dig.digest();
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    ex.printStackTrace(System.err);
                }
            }
        }
    }

    /**
     * Reads a certificate in PEM-format from a file.
     *
     * The file may contain other things, the first certificate in the file is
     * read.
     *
     * @param certFile the file containing the certificate in PEM-format
     * @return Ordered List of X509Certificate, first certificate first,
     * or empty List
     * @exception IOException if the filen cannot be read.
     * @exception CertificateException if the filen does not contain a correct
     * certificate.
     */
    private List<X509Certificate> getCertsFromPEM(final String certFile)
            throws IOException, CertificateException {
        try (InputStream inStrm = new FileInputStream(certFile)) {
            return getCertsFromPEM(inStrm);
        }
    }

    /**
     * Reads a certificate in PEM-format from an InputStream.
     *
     * The stream may contain other things, the first certificate in the
     * stream is read.
     *
     * @param certstream the input stream containing the certificate in
     * PEM-format
     * @return Ordered List of X509Certificate, first certificate first,
     * or empty List
     * @exception IOException if the stream cannot be read.
     * @exception CertificateException if the stream does not contain a
     * correct certificate.
     */
    private List<X509Certificate> getCertsFromPEM(
            final InputStream certstream) throws IOException,
            CertificateException {
        final ArrayList<X509Certificate> ret = new ArrayList<>();
        
        final BufferedReader bufRdr = new BufferedReader(new InputStreamReader(
                certstream));

        while (bufRdr.ready()) {
            final byte[] certbuf;
            try (ByteArrayOutputStream ostr = new ByteArrayOutputStream();
                 PrintStream opstr = new PrintStream(ostr)) {
                String temp;
                while ((temp = bufRdr.readLine()) != null
                        && !temp.equals(PEM_BEGIN)) {}
                if (temp == null) {
                    throw new IOException("Error in " + certstream.toString()
                            + ", missing " + PEM_BEGIN + " boundary");
                }
                
                while ((temp = bufRdr.readLine()) != null
                        && !temp.equals(PEM_END)) {
                    opstr.print(temp);
                }
                
                if (temp == null) {
                    throw new IOException("Error in " + certstream.toString()
                            + ", missing " + PEM_END + " boundary");
                }
                certbuf = Base64.decode(ostr.toByteArray());
            }
            // Phweeew, were done, now decode the cert from file back to
            // X509Certificate object
            final CertificateFactory cf = getCertificateFactory();
            final X509Certificate x509cert =
                    (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(certbuf));
            ret.add(x509cert);
        }
        return ret;
    }

    private CertificateFactory getCertificateFactory() {
        try {
            return CertificateFactory.getInstance("X.509", "BC");
        } catch (NoSuchProviderException | CertificateException nspe) {
            LOG.error("Error creating certificate factory", nspe);
        }
        return null;
    }
    
    /**
     * Returns the length of output digest in bits for provided digest algorithm.     * 
     * @param digestAlg digest algorithm 
     * @return digest output length in bits
     */
    private static int getOutputSizeBitsFromDigestAlgorithmString(final String digestAlg) {
        switch (digestAlg.toUpperCase()) {
            case "MD5":
            case "MD-5":
                return 128;
            case "GOST3411":
            case "GOST-3411":
                return 256;
            case "RIPEMD128":
            case "RIPEMD-128":
                return 128;
            case "RIPEMD160":
            case "RIPEMD-160":
                return 160;
            case "RIPEMD256":
            case "RIPEMD-256":
                return 256;
            case "SHA1":
            case "SHA-1":
                return 160;
            case "SHA224":
            case "SHA-224":
                return 224;
            case "SHA256":
            case "SHA-256":
                return 256;
            case "SHA384":
            case "SHA-384":
                return 384;
            case "SHA512":
            case "SHA-512":
                return 512;
            default:
                throw new IllegalArgumentException("Invalid digest algorithm: " + digestAlg);
        }
    }
    
    private ASN1ObjectIdentifier getDigestAlgorithmFromString(final String digestAlg) throws CommandFailureException {
        switch (digestAlg) {
            case "MD5":
            case "MD-5":
                return TSPAlgorithms.MD5;
            case "GOST3411":
            case "GOST-3411":
                return TSPAlgorithms.GOST3411;
            case "RIPEMD128":
            case "RIPEMD-128":
                return TSPAlgorithms.RIPEMD128;
            case "RIPEMD160":
            case "RIPEMD-160":
                return TSPAlgorithms.RIPEMD160;
            case "RIPEMD256":
            case "RIPEMD-256":
                return TSPAlgorithms.RIPEMD256;
            case "SHA1":
            case "SHA-1":
                return TSPAlgorithms.SHA1;
            case "SHA224":
            case "SHA-224":
                return TSPAlgorithms.SHA224;
            case "SHA256":
            case "SHA-256":
                return TSPAlgorithms.SHA256;
            case "SHA384":
            case "SHA-384":
                return TSPAlgorithms.SHA384;
            case "SHA512":
            case "SHA-512":
                return TSPAlgorithms.SHA512;
            default:
                throw new IllegalArgumentException("Invalid digest algorithm: " + digestAlg);
        }
    }
}
