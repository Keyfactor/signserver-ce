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
import java.util.Random;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
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
 * class makeing a simple timestamp request to a timestamp server a tries to validate it.
 * Only works in unauthenticated mode.
 * 
 * @author philip
 * $Id: TimeStampClient.java 500 2009-04-22 12:10:07Z anatom $
 */

public class TimeStampClient {
 
	private static final int PARAM_URL = 1;
	
	private String urlstring = null;
	private String outrepstring = null;
	private String inrepstring = null;
	private String outreqstring = null;
	private String instring = null;
	private String infilestring = null;
	private String signerfilestring = null;
	private boolean base64 = false;
	private boolean verify = false;

    private int repeat = 0;
    private int sleep = 1000;

	public TimeStampClient(String[] args){
      Option help = new Option( "help", false, "Print this message." );
      Option b64 = new Option( "base64", false, "Give this option if the stored request/reply should be base64 encoded, default is not.");
      Option verifyopt = new Option( "verify", false, "Give this option if verification of a stored reply should be done, work together with inrep and cafile. If given, no request to the TSA will happen.");
      
      OptionBuilder.hasArg();     
      OptionBuilder.withDescription(  "Url of TSA, e.g. http://127.0.0.1:8080/signserver/process?workerId=1." );
      OptionBuilder.withArgName( "url" );
      Option url = OptionBuilder.create( "url" );

      OptionBuilder.hasArg();     
      OptionBuilder.withArgName( "file" );      
      OptionBuilder.withDescription(  "Output file to store the recevied TSA reply, if not given the reply is not stored." );
      Option outrep = OptionBuilder.create( "outrep" );
      
      OptionBuilder.hasArg();     
      OptionBuilder.withArgName( "file" );      
      OptionBuilder.withDescription(  "Input file containing an earlier stored base64 encoded response, to verify. You must specify the verify flag also." );
      Option inrep = OptionBuilder.create( "inrep" );

      OptionBuilder.hasArg();     
      OptionBuilder.withArgName( "file" );      
      OptionBuilder.withDescription(  "Input file containing the PEM encoded certificate of the TSA signer. Used to verify a stored response." );
      Option cafileopt = OptionBuilder.create( "signerfile" );

      OptionBuilder.hasArg();     
      OptionBuilder.withArgName( "file" );      
      OptionBuilder.withDescription(  "Output file to store the sent TSA request, if not given the request is not stored." );
      Option outreq = OptionBuilder.create( "outreq" );

      OptionBuilder.hasArg();     
      OptionBuilder.withArgName( "file" );      
      OptionBuilder.withDescription(  "File containing message to time stamp." );
      Option infile = OptionBuilder.create( "infile" );
      
      OptionBuilder.hasArg();     
      OptionBuilder.withArgName( "file" );      
      OptionBuilder.withDescription(  "String to be time stamped, if neither instr or infile is given, the client works in test-mode generating it's own message." );
      Option instr = OptionBuilder.create( "instr" );

      OptionBuilder.hasArg();
      OptionBuilder.withArgName("num");
      OptionBuilder.withDescription("Repeat a number of times. If not specified or specified as 0 repeat infinitely.");
      final Option repeat = OptionBuilder.create("repeat");

      OptionBuilder.hasArg();
      OptionBuilder.withArgName("num");
      OptionBuilder.withDescription("Sleep a number of milliseconds after each request. Default 1000 ms. ");
      final Option sleep = OptionBuilder.create("sleep");
      
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
      options.addOption(repeat);
      options.addOption(sleep);
      final CommandLineParser parser = new GnuParser();
      try {
    	  CommandLine cmd = parser.parse( options, args);
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
          if (cmd.hasOption("repeat")) {
              try {
                  this.repeat = Integer.parseInt(cmd.getOptionValue("repeat"));
              } catch (NumberFormatException ex) {
                  throw new ParseException("repeat num");
              }
          }
          if (cmd.hasOption("sleep")) {
              try {
                  this.repeat = Integer.parseInt(cmd.getOptionValue("sleep"));
              } catch (NumberFormatException ex) {
                  throw new ParseException("sleep num");
              }
          }
          final String[] strargs = cmd.getArgs();
          if (strargs.length > 1) {
        	  urlstring = strargs[PARAM_URL];
                  System.out.println("urlstring: " + urlstring);
          }

      } catch (ParseException e) {
    	  // oops, something went wrong
    	  System.err.println( "Parsing failed.  Reason: " + e.getMessage() );
          usage(options);
          return;
      }

	  if(args.length < 2){
		  usage(options);
	  }
      if (Security.addProvider(new BouncyCastleProvider()) < 0) {
          // If already installed, remove so we can handle redeploy
          Security.removeProvider("BC");
          if (Security.addProvider(new BouncyCastleProvider()) < 0) {
              System.out.println("Cannot even install BC provider again!");
          }
      }
	}
	 
	private void usage(Options options) {
		// automatically generate the help statement
		HelpFormatter formatter = new HelpFormatter();
		formatter.printHelp( "timestamp <options> <url>", options );
		System.exit(-1);
	}
	
	private static TimeStampClient client = null; 
	
	/**
	 * Use the TimeStamp Client with url to CRL server. 
	 * 
	 * @param args
	 * 
	 */
	public static void main(String[] args) throws Exception{
		client = new TimeStampClient(args);
		
		client.run();
		
	}

	private void run()  throws Exception {
		if (verify) {
			tsaVerify();
		} else {
			tsaRequest();
		}

	}

	private void tsaVerify() throws Exception {
		if (inrepstring == null) {
			System.out.println("Needs an inrep!");
			return;
		}
		Collection<X509Certificate> col = getCertsFromPEM(signerfilestring);
		X509Certificate[] list = (X509Certificate[])col.toArray(new X509Certificate[0]);
		if (list.length == 0) {
			System.out.println("No certificate found in file: "+signerfilestring);
			return;			
		}
		byte[] b64Bytes = readFiletoBuffer(inrepstring);
		byte[] replyBytes = Base64.decode(b64Bytes);
		TimeStampResponse timeStampResponse = new TimeStampResponse(replyBytes);
		TimeStampToken token = timeStampResponse.getTimeStampToken();
		token.validate(list[0], "BC");
		System.out.println("Token was validated successfully.");
		TimeStampTokenInfo info = token.getTimeStampInfo();
		System.out.println("Token was generated on: "+info.getGenTime());
		if (info.getMessageImprintAlgOID().equals(TSPAlgorithms.SHA1)) {
			System.out.println("Token hash alg: SHA1");
		} else {
			System.out.println("Token hash alg: "+info.getMessageImprintAlgOID());
		}
		byte[] hexDigest = Hex.encode(info.getMessageImprintDigest());
		System.out.println("MessageDigest="+new String(hexDigest));
	}
	private void tsaRequest() throws Exception {
		boolean doRun = true;
		do{  
			TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
			
			Random rand = new Random();
			int nonce = rand.nextInt();
            byte[] digest = new byte[20]; 
			if (instring != null) {
				byte[] digestBytes = instring.getBytes("UTF-8");
                MessageDigest dig = MessageDigest.getInstance(TSPAlgorithms.SHA1, "BC");
                dig.update(digestBytes);
                digest = dig.digest();
				// When we have given input, we don't want to loop
				doRun = false;
			}
			if (infilestring != null) {
                digest = digestFile(infilestring, TSPAlgorithms.SHA1);
				doRun = false;
			}
			byte[] hexDigest = Hex.encode(digest);
			System.out.println("MessageDigest="+new String(hexDigest));
			TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, digest, BigInteger.valueOf(nonce));
			byte[] requestBytes = timeStampRequest.getEncoded();
			if (outreqstring != null) {
				// Store request
				byte[] outBytes;
				if (base64) {
					outBytes=Base64.encode(requestBytes);
				} else {
					outBytes = requestBytes;
				}
				FileOutputStream fos = null;
				try {
					fos = new FileOutputStream(outreqstring);
					fos.write(outBytes);					
				} finally {
					if (fos != null) fos.close();
				}
			}
			
			URL                 url;
			URLConnection urlConn;
			DataOutputStream    printout;
			DataInputStream     input;
			
			url = new URL (urlstring);
			
			urlConn = url.openConnection();
			
			urlConn.setDoInput (true);
			urlConn.setDoOutput (true);
			urlConn.setUseCaches (false);
			urlConn.setRequestProperty("Content-Type", "application/timestamp-query");
			// Send POST output.
			printout = new DataOutputStream (urlConn.getOutputStream ());
			
			printout.write(requestBytes);
			printout.flush ();
			printout.close ();
			// Get response data.
			input = new DataInputStream (urlConn.getInputStream ());
			while(input.available() == 0){
				Thread.sleep(100);
			}
			
			byte[] ba = null;
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			do{
				if(ba != null){
					baos.write(ba);
				}
				ba = new byte[input.available()]; 
				
			}while(input.read(ba) != -1);
			
			byte[] replyBytes = baos.toByteArray();
			if (outrepstring != null) {
				// Store request
				byte[] outBytes;
				if (base64) {
					outBytes=Base64.encode(replyBytes);
				} else {
					outBytes = replyBytes;
				}
				FileOutputStream fos = null;
				try {
					fos = new FileOutputStream(outrepstring);
					fos.write(outBytes);					
				} finally {
					if (fos != null) fos.close();
				}
			}

			TimeStampResponse timeStampResponse = new TimeStampResponse(replyBytes);
			timeStampResponse.validate(timeStampRequest);
			System.out.print("TimeStampRequest validated\n");

                        if (doRun) {
                            // Sleep a specified number of milliseconds
                            Thread.sleep(sleep);
                        }
		} while(doRun);
       // timeStampResponse.getTimeStampToken().validate();
	}
	
	/**
     * Helpfunction to read a file to a byte array.
     *
     * @param file filename of file.
     *
     * @return byte[] containing the contents of the file.
     *
     * @throws IOException if the file does not exist or cannot be read.
     */
    private byte[] readFiletoBuffer(String file) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        InputStream in = new FileInputStream(file);
        int len = 0;
        byte[] buf = new byte[1024];

        while ((len = in.read(buf)) > 0) {
            os.write(buf, 0, len);
        }

        in.close();
        os.close();

        return os.toByteArray();
    } // readFiletoBuffer
	
    /**
     * Helpfunction to calculate the digest of a big file.
     *
     * @param file filename of file.
     *
     * @return byte[] containing the digest of the file.
     *
     * @throws IOException if the file does not exist or cannot be read.
     * @throws NoSuchProviderException if BC provider is not installed
     * @throws NoSuchAlgorithmException if the given hash algorithm does not exist
     */
    private byte[] digestFile(String file, String digestAlg) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
        InputStream in = new FileInputStream(file);
        MessageDigest dig = MessageDigest.getInstance(digestAlg, "BC");
        int len = 0;
        byte[] buf = new byte[2048];
        while ((len = in.read(buf)) > 0) {
            dig.update(buf, 0, len);
        }
        byte[] digest = dig.digest();
        in.close();
        return digest;
    } // digestFile
    
    /**
     * Reads a certificate in PEM-format from a file. The file may contain other things,
     * the first certificate in the file is read.
     *
     * @param certFile the file containing the certificate in PEM-format
     * @return Ordered Collection of X509Certificate, first certificate first, or empty Collection
     * @exception IOException if the filen cannot be read.
     * @exception CertificateException if the filen does not contain a correct certificate.
     */
    private Collection<X509Certificate> getCertsFromPEM(String certFile) throws IOException, CertificateException {
        InputStream inStrm = new FileInputStream(certFile);
        Collection<X509Certificate> certs = getCertsFromPEM(inStrm);
        return certs;
    }

    /**
     * Reads a certificate in PEM-format from an InputStream. The stream may contain other things,
     * the first certificate in the stream is read.
     *
     * @param certFile the input stream containing the certificate in PEM-format
     * @return Ordered Collection of X509Certificate, first certificate first, or empty Collection
     * @exception IOException if the stream cannot be read.
     * @exception CertificateException if the stream does not contain a correct certificate.
     */
    private Collection<X509Certificate> getCertsFromPEM(InputStream certstream)
    throws IOException, CertificateException {
        ArrayList<X509Certificate> ret = new ArrayList<X509Certificate>();
        String beginKey = "-----BEGIN CERTIFICATE-----";
        String endKey = "-----END CERTIFICATE-----";
        BufferedReader bufRdr = new BufferedReader(new InputStreamReader(certstream));
        while (bufRdr.ready()) {
            ByteArrayOutputStream ostr = new ByteArrayOutputStream();
            PrintStream opstr = new PrintStream(ostr);
            String temp;
            while ((temp = bufRdr.readLine()) != null &&
            !temp.equals(beginKey))
                continue;
            if (temp == null)
                throw new IOException("Error in " + certstream.toString() + ", missing " + beginKey + " boundary");
            while ((temp = bufRdr.readLine()) != null &&
            !temp.equals(endKey))
                opstr.print(temp);
            if (temp == null)
                throw new IOException("Error in " + certstream.toString() + ", missing " + endKey + " boundary");
            opstr.close();

            byte[] certbuf = Base64.decode(ostr.toByteArray());
            ostr.close();
            // Phweeew, were done, now decode the cert from file back to X509Certificate object
            CertificateFactory cf = getCertificateFactory();
            X509Certificate x509cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certbuf));
            ret.add(x509cert);
        }
        return ret;
    } // getCertsFromPEM

    private CertificateFactory getCertificateFactory() {
        try {
            return CertificateFactory.getInstance("X.509", "BC");
        } catch (NoSuchProviderException nspe) {
            nspe.printStackTrace();
        } catch (CertificateException ce) {
            ce.printStackTrace();
        }
        return null;
    }

}
