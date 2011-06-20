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
package org.signserver.client.validationservice;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.SSLSocketFactory;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.ejbca.util.CertTools;
import org.signserver.common.RequestAndResponseManager;
import org.signserver.common.SignServerUtil;
import org.signserver.protocol.ws.ProcessRequestWS;
import org.signserver.protocol.ws.ProcessResponseWS;
import org.signserver.protocol.ws.client.ICommunicationFault;
import org.signserver.protocol.ws.client.IFaultCallback;
import org.signserver.protocol.ws.client.ISignServerWSClient;
import org.signserver.protocol.ws.client.SignServerWSClientFactory;
import org.signserver.protocol.ws.client.WSClientUtil;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.Validation.Status;

/**
 * CLI Tool used to administrate the data in the
 * WSRA interface.
 * 
 * @author Philip Vendil 13 sep 2008
 *
 * @version $Id$
 */
public class ValidationCLI {

	ValidationCLI(){}
	
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
	
	public static final int RETURN_ERROR = -2;
	public static final int RETURN_BADARGUMENT = -1;
	public static final int RETURN_VALID = 0;
	public static final int RETURN_REVOKED = 1;
	public static final int RETURN_NOTYETVALID = 2;
	public static final int RETURN_EXPIRED = 3;
	public static final int RETURN_DONTVERIFY = 4;
	public static final int RETURN_CAREVOKED = 5;
	public static final int RETURN_CANOTYETVALID = 6;
	public static final int RETURN_CAEXPIRED = 7;
	public static final int RETURN_BADCERTPURPOSE = 8;
	
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
	
	private ValidationCLI(String[] args){
		
		SignServerUtil.installBCProvider();
		
		Option help = new Option( OPTION_HELP, false, "Display this info" );		
		Option silent = new Option( OPTION_SILENT, false, "Don't produce any output, only return value." );
		Option pem = new Option( OPTION_PEM, false, "Certificate is in PEM format (Default)." );
		Option der = new Option( OPTION_DER, false, "Certificate is in DER format." );				
		
		OptionBuilder.withArgName( "service-name" );
		OptionBuilder.hasArg();
        OptionBuilder.withDescription( "The name or id of the validation service to process request. (Required)" );        		 
		Option serviceOption = OptionBuilder.create( OPTION_SERVICE );
		
		OptionBuilder.withArgName( "cert-file" );
		OptionBuilder.hasArg();
        OptionBuilder.withDescription( "Path to certificate file (DER or PEM) (Required)." );        		 
		Option certOption = OptionBuilder.create( OPTION_CERT );
		
		OptionBuilder.withArgName( "hosts" );
		OptionBuilder.hasArg();
        OptionBuilder.withDescription( "A ',' separated string containing the hostnames of the validation service nodes. Ex 'host1.someorg.org,host2.someorg.org' (Required)." );        		 
		Option hostsOption = OptionBuilder.create( OPTION_HOSTS );
		
		OptionBuilder.withArgName( "port" );
		OptionBuilder.hasArg();
        OptionBuilder.withDescription( "Remote port of service (Default is 8080 or 8442 for SSL)." );        		 
		Option portOption = OptionBuilder.create( OPTION_PORT );
		
		OptionBuilder.withArgName( "certpurposes" );
		OptionBuilder.hasArg();
        OptionBuilder.withDescription( "A ',' separated string containing requested certificate purposes." );        		 
		Option usagesOption = OptionBuilder.create( OPTION_CERTPURPOSES );
		
		OptionBuilder.withArgName( "jks-file" );
		OptionBuilder.hasArg();
        OptionBuilder.withDescription( "Path to JKS truststore containing trusted CA for SSL Server certificates." );        		 
		Option truststore = OptionBuilder.create( OPTION_TRUSTSTORE );
		
		OptionBuilder.withArgName( "password" );
		OptionBuilder.hasArg();
        OptionBuilder.withDescription( "Password to unlock the truststore." );        		 
		Option truststorepwd = OptionBuilder.create( OPTION_TRUSTSTOREPWD );
		
	    Options options = new Options();
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

	     CommandLineParser parser = new GnuParser();
	      try {
	    	  CommandLine cmd = parser.parse( options, args);
	          if (cmd.hasOption(OPTION_HELP)) {
	        	  printUsage(options);
	          }
	          
	          silentMode = cmd.hasOption(OPTION_SILENT);
	          derFlag = cmd.hasOption(OPTION_DER);
	          pemFlag = cmd.hasOption(OPTION_PEM);
	          
	          if(derFlag && pemFlag){
	        	  System.err.println("Error, only one of -pem and -der options can be specified.");
	        	  printUsage(options);
	          }
	          
	          if(!derFlag){
	        	  pemFlag = true;
	          }
	          
	          if(cmd.hasOption(OPTION_SERVICE) && cmd.getOptionValue(OPTION_SERVICE) != null){
	        	   service = cmd.getOptionValue(OPTION_SERVICE);
	          }else{
	        	  System.err.println("Error, an name or id of the validation service must be specified with the -" + OPTION_SERVICE + " option.");
	        	  printUsage(options);
	          }
	          
	          if(cmd.hasOption(OPTION_TRUSTSTORE)){
	        	  trustStorePath = cmd.getOptionValue(OPTION_TRUSTSTORE);
	        	  if(trustStorePath != null){
	        		  File f = new File(trustStorePath);
	        		  if(!f.exists() || !f.canRead() || f.isDirectory()){
	        			  System.err.println("Error, a path to the truststore must point to a readable JKS file.");
			        	  printUsage(options);
	        		  }
	        	  }else{
		        	  System.err.println("Error, a path to the truststore must be supplied to the -"+ OPTION_TRUSTSTORE + " option.");
		        	  printUsage(options);
	        	  }
	          }
	          
	          if(cmd.hasOption(OPTION_TRUSTSTOREPWD)){
	        	  trustStorePwd = cmd.getOptionValue(OPTION_TRUSTSTOREPWD);
	        	  if(trustStorePwd == null){	        		  
		        	  System.err.println("Error, a truststore password must be supplied to the -"+ OPTION_TRUSTSTOREPWD + " option.");
		        	  printUsage(options);
                          }
	          }
	          
	          if(trustStorePath == null ^ trustStorePwd == null){
	        	  System.err.println("Error, if HTTPS is going to be used must both the options -"+ OPTION_TRUSTSTORE + " and -"+ OPTION_TRUSTSTOREPWD + " be specified");
	        	  printUsage(options);
	          }
	          
	          useSSL = trustStorePath != null;
	          
	          if(cmd.hasOption(OPTION_HOSTS) && cmd.getOptionValue(OPTION_HOSTS) != null){
	        	  hosts = cmd.getOptionValue(OPTION_HOSTS).split(",");
	          }else{
	        	  System.err.println("Error, at least one validation service host must be specified.");
	        	  printUsage(options);
	          }
	          
	          if(cmd.hasOption(OPTION_PORT)){
	        	  String portString = cmd.getOptionValue(OPTION_PORT);
	        	  if(portString != null){
	        		  try{
	        			  port = Integer.parseInt(portString);
	        		  }catch(NumberFormatException e){
			        	  System.err.println("Error, port value must be an integer for option -"+ OPTION_PORT + ".");
			        	  printUsage(options);
	        		  }
	        	  }else{
		        	  System.err.println("Error, a port value must be supplied to the -"+ OPTION_PORT + " option.");
		        	  printUsage(options);
	        	  }
	          }else{
	        	  if(useSSL){
	        		  port = DEFAULT_SSLPORT;
	        	  }else{
	        		  port = DEFAULT_PORT;
	        	  }
	          }	          	          
	          
	          if(cmd.hasOption(OPTION_CERTPURPOSES)){
	        	  if(cmd.getOptionValue(OPTION_CERTPURPOSES) != null){
	        		  usages = cmd.getOptionValue(OPTION_CERTPURPOSES);
	        	  }else{
	        		  System.err.println("Error, at least one usage must be specified with the -" + OPTION_CERTPURPOSES + " option.");
	        		  printUsage(options);
	        	  }
	          }
	          
	          if(cmd.hasOption(OPTION_CERT) && cmd.getOptionValue(OPTION_CERT) != null){
	        	  certPath = new File(cmd.getOptionValue(OPTION_CERT));
	        	  if(!certPath.exists() || !certPath.canRead() || certPath.isDirectory()){
	        			  System.err.println("Error, the certificate file must exist and be readable by the user.");
			        	  printUsage(options);
	        	  }	        	
	          }else{
	        	  System.err.println("Error, the certificate to validate must be specified with the -"+ OPTION_CERT + " option.");
	        	  printUsage(options);
        	  }
	          

	      } catch (ParseException e) {
	    	  System.err.println( "Error occurred when parsing options.  Reason: " + e.getMessage() );
	    	  printUsage(options);
	      }

		  if(args.length < 1){
			  printUsage(options);
		  }
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {		
		int result = RETURN_BADARGUMENT;
		try {
			ValidationCLI cli = new ValidationCLI(args);
			result = cli.run();
		} catch (Exception e) {
			if(!e.getClass().getSimpleName().equals("ExitException")){
			  
			  System.err.println("Error occured during validation : " + e.getClass().getName());
			  if(e.getMessage() != null){
				  System.err.println("  Message : " + e.getMessage());
			  }
			  result = RETURN_ERROR;
			}
		}
		System.exit(result);
	}
	
	private int run() throws Exception {		
		
		// 1. set up trust
		SSLSocketFactory sslf = null;
		if(trustStorePath != null){
		   sslf = WSClientUtil.genCustomSSLSocketFactory(null, null, trustStorePath, trustStorePwd);
		}
		
		// 2. read certificate
		X509Certificate cert = null;
		FileInputStream fis = new FileInputStream(certPath);
		try{
			if(pemFlag){
                Collection<?> certs = CertTools.getCertsFromPEM(fis);
                if(certs.iterator().hasNext()){
                	cert = (X509Certificate) certs.iterator().next();
                }
			}else{
				byte[] data = new byte[fis.available()];
				fis.read(data,0,fis.available());
				cert = (X509Certificate)CertTools.getCertfromByteArray(data);
			}
		}finally{
			fis.close();
		}
		
		if(cert == null){
			println("Error, Certificate in file "+ certPath + " not read succesfully.");
		}
		
		println("\n\nValidating certificate with: ");
		println("  Subject    : " + cert.getSubjectDN().toString());
		println("  Issuer     : " + cert.getIssuerDN().toString());
		println("  Valid From : " + cert.getNotBefore());
		println("  Valid To   : " + cert.getNotAfter());
	    				
		println("\n");
		// 3. validate
		SignServerWSClientFactory fact = new SignServerWSClientFactory();
		ISignServerWSClient client = fact.generateSignServerWSClient(SignServerWSClientFactory.CLIENTTYPE_CALLFIRSTNODEWITHSTATUSOK, 
				hosts, useSSL, 
				new LogErrorCallback(), 
				port, SignServerWSClientFactory.DEFAULT_TIMEOUT, 
				SignServerWSClientFactory.DEFAULT_WSDL_URL, 
				sslf);
		
		ValidateRequest vr = new ValidateRequest(org.signserver.validationservice.common.X509Certificate.getInstance(cert),usages);
		
		ArrayList<ProcessRequestWS> requests = new ArrayList<ProcessRequestWS>();
		requests.add(new ProcessRequestWS(vr));
		List<ProcessResponseWS> response = client.process(service, requests);
		if(response == null){
			throw new IOException("Error communicating with valdation servers, no server in the cluster seem available.");
		}
		ValidateResponse vresp = (ValidateResponse) RequestAndResponseManager.parseProcessResponse(response.get(0).getResponseData());
		
		// 4. output result
		String certificatePurposes = vresp.getValidCertificatePurposes();
		println("Valid Certificate Purposes:\n  " + (certificatePurposes == null ?  "" : certificatePurposes));
		Validation validation = vresp.getValidation();		
		println("Certificate Status:\n  " + validation.getStatus());
		
		return getReturnValue(validation.getStatus()); 
	}
	
    private void println(String string) {
		if(!silentMode){
			System.out.println(string);
		}
		
	}

	private int getReturnValue(Status status) {
		if(status == Status.VALID){
			return RETURN_VALID;
		}
		if(status == Status.REVOKED){
			return RETURN_REVOKED;
		}
		if(status == Status.NOTYETVALID){
			return RETURN_NOTYETVALID;
		}
		if(status == Status.EXPIRED){
			return RETURN_EXPIRED;
		}
		if(status == Status.DONTVERIFY){
			return RETURN_DONTVERIFY;
		}
		if(status == Status.CAREVOKED){
			return RETURN_CAREVOKED;
		}
		if(status == Status.CANOTYETVALID){
			return RETURN_CANOTYETVALID;
		}
		if(status == Status.CAEXPIRED){
			return RETURN_CAEXPIRED;
		}
		if(status == Status.BADCERTPURPOSE){
			return RETURN_BADCERTPURPOSE;
		}
		return RETURN_ERROR;
	}

	class LogErrorCallback implements IFaultCallback{
        @SuppressWarnings("synthetic-access")
        public void addCommunicationError(ICommunicationFault error) {
            final String s = "Error communication with host : " + error.getHostName() + ", " + error.getDescription();
            if ( error.getThrowed()!=null ){
            	System.out.println(s);
                error.getThrowed().printStackTrace();
            }else{
            	System.out.println(s);
            }
        }

	
    }

    private static void printUsage(Options options) {
        final StringBuilder footer = new StringBuilder();
        footer.append(NL)
            .append("The following values is returned by the program that can be used when scripting.").append(NL)
            .append("  -2   : Error happened during execution").append(NL)
            .append("  -1   : Bad arguments").append(NL)
            .append("   0   : Certificate is valid").append(NL)
            .append("   1   : Certificate is revoked").append(NL)
            .append("   2   : Certificate is not yet valid").append(NL)
            .append("   3   : Certificate have expired").append(NL)
            .append("   4   : Certificate doesn't verify").append(NL)
            .append("   5   : CA Certificate have been revoked").append(NL)
            .append("   6   : CA Certificate is not yet valid").append(NL)
            .append("   7   : CA Certificate have expired.").append(NL)
            .append("   8   : Certificate have no valid certificate purpose.").append(NL)
            .append(NL)
            .append("Sample usages:").append(NL)
            .append("a) ").append(COMMAND).append(" -service CertValidationWorker -hosts localhost -cert").append(NL)
            .append("    certificate.pem").append(NL)
            .append("b) ").append(COMMAND).append(" -service 5806 -hosts localhost -cert certificate.pem").append(NL)
            .append("    -truststore p12/truststore.jks -truststorepwd changeit").append(NL);

        final HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("Usage: java -jar validate.jar <options>\n", options);
        System.out.println(footer.toString());

        System.exit(RETURN_BADARGUMENT);
    }

}
