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
package org.signserver.client;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

/**
 * Class makeing a simple timestamp request to a timestamp server and tries to
 * validate it.
 *
 * This client only works in unauthenticated mode.
 *
 * @author philip
 * $Id$
 */
public class TimeStampClient {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TimeStampClient.class);

    /** System-specific new line characters. **/
    private static final String NL = System.getProperty("line.separator");

    /** The name of this command. */
    private static final String COMMAND = "timestamp";

    private static final int PARAM_URL = 0;

    /** Begin key for certificates in PEM format. */
    private static final String PEM_BEGIN = "-----BEGIN CERTIFICATE-----";

    /** End key for certificates in PEM format. */
    private static final String PEM_END = "-----END CERTIFICATE-----";

    private String urlstring;

    private String outrepstring;

    private String inrepstring;

    /** Filename to read a pre-formatted request from. */
    private String inreqstring;

    private String outreqstring;

    private String instring;

    private String infilestring;

    private String signerfilestring;

    private boolean base64;

    private boolean verify;

    /** Number of milliseconds to sleep after a request. */
    private int sleep = 1000;


    /**
     * Creates a new instance of TimeStampClient.
     *
     * @param args Command line arguments
     */
    public TimeStampClient(final String[] args) {

        // Create options
        final Option help = new Option("help", false, "Print this message.");
        final Option b64 = new Option("base64", false,
                "Give this option if the stored request/reply should be "
                + "base64 encoded, default is not.");
        final Option verifyopt = new Option("verify", false,
                "Give this option if verification of a stored reply should "
                + "be done, work together with inrep and cafile. If given, no "
                + "request to the TSA will happen.");

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
        OptionBuilder.withArgName("num");
        OptionBuilder.withDescription("Sleep a number of milliseconds after "
                + "each request. Default 1000 ms.");
        final Option optionSleep = OptionBuilder.create("sleep");

        // Add options
        final Options options = new Options();
        options.addOption(help);
        options.addOption(verifyopt);
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

        final CommandLineParser parser = new GnuParser();
        try {
            final CommandLine cmd = parser.parse(options, args);
            if (cmd.hasOption("help")) {
                usage(options);
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

            if (args.length < 1) {
                usage(options);
            } else if (urlstring == null) {
                LOG.error("Missing URL");
                usage(options);
            } else if (Security.addProvider(new BouncyCastleProvider()) < 0) {
                // If already installed, remove so we can handle redeploy
                Security.removeProvider("BC");
                if (Security.addProvider(new BouncyCastleProvider()) < 0) {
                    LOG.error("Cannot even install BC provider again!");
                }
            }
        } catch (ParseException e) {
            // oops, something went wrong
            LOG.error(e.getMessage());
            usage(options);
        }
    }

    private void usage(final Options options) {
        // automatically generate the help statement
        final HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("java -jar timeStampClient.jar <options> <url>",
                options);
        final StringBuilder footer = new StringBuilder();
        footer.append(NL)
            .append("Sample usages:").append(NL)
            .append("a) ").append(COMMAND).append(" -url http://localhost:8080/signserver/tsa?workerName=TimeStampSigner").append(NL);
        System.out.println(footer.toString());
        System.exit(-1);
    }

    /**
     * Use the TimeStamp Client with URL to the TSA server.
     *
     * @param args Command line arguments
     */
    public static void main(final String[] args) {
        try {
            new TimeStampClient(args).run();
        } catch (Exception ex) {
            LOG.error(ex.getMessage(), ex);
        }
    }

    private void run() throws Exception {
        // Take start time
        final long startTime = System.nanoTime();
        
        if (verify) {
            tsaVerify();
        } else {
            tsaRequest();
        }

        // Take stop time
        final long estimatedTime = System.nanoTime() - startTime;

        LOG.info("Processing took "
                + TimeUnit.NANOSECONDS.toMillis(estimatedTime) + " ms");
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
            token.validate(list[0], "BC");
            LOG.info("Token was validated successfully.");

            final TimeStampTokenInfo info = token.getTimeStampInfo();
            LOG.info("Token was generated on: " + info.getGenTime());

            if (LOG.isDebugEnabled()) {
                if (info.getMessageImprintAlgOID().equals(TSPAlgorithms.SHA1)) {
                    LOG.debug("Token hash alg: SHA1");
                } else {
                    LOG.debug("Token hash alg: " + info.getMessageImprintAlgOID());
                }
                final byte[] hexDigest = Hex.encode(info.getMessageImprintDigest());
                LOG.info("MessageDigest=" + new String(hexDigest));
            }
        }
    }

    private void tsaRequest() throws Exception {
        final Random rand = new Random();
        final TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        boolean doRun = true;
        do {

            final int nonce = rand.nextInt();

            byte[] digest = new byte[20];
            if (instring != null) {
                final byte[] digestBytes = instring.getBytes("UTF-8");
                final MessageDigest dig = MessageDigest.getInstance(
                        TSPAlgorithms.SHA1,
                        "BC");
                dig.update(digestBytes);
                digest = dig.digest();
                // When we have given input, we don't want to loop
                doRun = false;
            }
            if (infilestring != null) {
                digest = digestFile(infilestring, TSPAlgorithms.SHA1);
                doRun = false;
            }
            final byte[] hexDigest = Hex.encode(digest);

            if (LOG.isDebugEnabled()) {
                LOG.debug("MessageDigest=" + new String(hexDigest));
            }

            final TimeStampRequest timeStampRequest;
            if (inreqstring == null) {
                LOG.debug("Generating a new request");
                timeStampRequest = timeStampRequestGenerator.generate(
                        TSPAlgorithms.SHA1, digest, BigInteger.valueOf(nonce));
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
                FileOutputStream fos = null;
                try {
                    fos = new FileOutputStream(outreqstring);
                    fos.write(outBytes);
                } finally {
                    if (fos != null) {
                        fos.close();
                    }
                }
            }

            URL url;
            URLConnection urlConn;
            DataOutputStream printout;
            DataInputStream input;

            url = new URL(urlstring);

            // Take start time
            final long startTime = System.nanoTime();

            urlConn = url.openConnection();

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
            input = new DataInputStream(urlConn.getInputStream());
            while (input.available() == 0) {
                Thread.sleep(100);
            }

            byte[] ba = null;
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            do {
                if (ba != null) {
                    baos.write(ba);
                }
                ba = new byte[input.available()];

            } while (input.read(ba) != -1);

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
                FileOutputStream fos = null;
                try {
                    fos = new FileOutputStream(outrepstring);
                    fos.write(outBytes);
                } finally {
                    if (fos != null) {
                        fos.close();
                    }
                }
            }

            final TimeStampResponse timeStampResponse = new TimeStampResponse(
                    replyBytes);
            timeStampResponse.validate(timeStampRequest);

            LOG.info("TimeStampRequest validated");

            if (LOG.isDebugEnabled()) {
                LOG.debug("(Status: " + timeStampResponse.getStatus()
                        + ", " + timeStampResponse.getFailInfo() + "): "
                        + timeStampResponse.getStatusString());
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
            int len = 0;
            final byte[] buf = new byte[1024];

            while ((len = in.read(buf)) > 0) {
                os.write(buf, 0, len);
            }
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

        return os.toByteArray();
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
            int len = 0;
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
        InputStream inStrm = null;
        try {
            inStrm = new FileInputStream(certFile);
            return getCertsFromPEM(inStrm);
        } finally {
            if (inStrm != null) {
                inStrm.close();
            }
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
        final ArrayList<X509Certificate> ret = new ArrayList<X509Certificate>();
        
        final BufferedReader bufRdr = new BufferedReader(new InputStreamReader(
                certstream));

        while (bufRdr.ready()) {
            final ByteArrayOutputStream ostr = new ByteArrayOutputStream();
            final PrintStream opstr = new PrintStream(ostr);
            String temp;
            while ((temp = bufRdr.readLine()) != null
                    && !temp.equals(PEM_BEGIN)) {
                continue;
            }
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
            opstr.close();

            final byte[] certbuf = Base64.decode(ostr.toByteArray());
            ostr.close();
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
        } catch (NoSuchProviderException nspe) {
            LOG.error("Error creating certificate factory", nspe);
        } catch (CertificateException ce) {
            LOG.error("Error creating certificate factory", ce);
        }
        return null;
    }
}
