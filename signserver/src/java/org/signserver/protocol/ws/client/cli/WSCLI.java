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

package org.signserver.protocol.ws.client.cli;

import java.io.PrintStream;
import java.util.List;
import java.util.Random;

import org.signserver.cli.IllegalAdminCommandException;
import org.signserver.protocol.ws.ProcessResponseWS;
import org.signserver.protocol.ws.client.ICommunicationFault;
import org.signserver.protocol.ws.client.IFaultCallback;
import org.signserver.protocol.ws.client.ISignServerWSClient;
import org.signserver.protocol.ws.client.SignServerWSClientFactory;

/**
 * Main class for the CLI WS client for the signserver.
 * 
 * It is used mainly for testing a cluster setup and can be
 * customized for different signers for different usages.
 * 
 * 
 * @author Philip Vendil 15 dec 2007
 *
 * @version $Id$
 */

public class WSCLI {
	
	private static PrintStream out = System.out;

	private static final int ARG_SIGNERIDORNAME      = 0;
	private static final int ARG_NUMOFREQUESTS       = 1;
	private static final int ARG_TIMEBETWEENREQUESTS = 2;
	private static final int ARG_NUMOFTHREADS        = 3;
	private static final int ARG_RANDOMWAIT          = 4;

	private static final int DEFAULT_NUMOFREQUESTS = 1;
	private static final int DEFAULT_TIMEBETWEENREQUESTS = 1000;
	private static final int DEFAULT_NUMOFTHREADS = 1;
	private static final int DEFAULT_RANDOMWAITTIME = 0;
	
	private final String signerIdOrName;
	private final int numOfRequests;
	private final int timeBetweenRequests;
	private final int numOfThreads;
	private final int randomWaitTime;
	
	private PropertyParser props;
	private SignServerWSClientFactory clientFactory = new SignServerWSClientFactory();
	
	private static IWSRequestGenerator regGen = null;
	private static WSCLILogger log = null;
	
	public WSCLI(String[] args) throws IllegalAdminCommandException {
		if(args.length < 1 || args.length > 5){
			displayHelp();
			System.exit(-1);
		}
		
		signerIdOrName = args[ARG_SIGNERIDORNAME];
		
		
		if(args.length > ARG_NUMOFREQUESTS){
		   if(args[ARG_NUMOFREQUESTS].equalsIgnoreCase("c") || 
			  args[ARG_NUMOFREQUESTS].equalsIgnoreCase("continuous")){
			   numOfRequests = 0;
		   }else{
			   numOfRequests = checkArgument(args,ARG_NUMOFREQUESTS, DEFAULT_NUMOFREQUESTS,0,10000, "Bad number of requests argument '@DATA@', should either be 'c', 'continuous' or an integer between 1 and 10000");
		   }
		}else{
			numOfRequests = DEFAULT_NUMOFREQUESTS;
		}
        timeBetweenRequests = checkArgument(args,ARG_TIMEBETWEENREQUESTS, DEFAULT_TIMEBETWEENREQUESTS,0,10000, "Bad wait between requests argument '@DATA@', should be an integer between 0 and 10000.");	 				
        numOfThreads = checkArgument(args,ARG_NUMOFTHREADS, DEFAULT_NUMOFTHREADS,0,100, "Bad number of requests  argument '@DATA@', should be an integer between 0 and 100.");
        randomWaitTime = checkArgument(args,ARG_RANDOMWAIT, DEFAULT_RANDOMWAITTIME,0,10000, "Bad random wait argument '@DATA@', should be an integer between 0 and 10000.");
        
        props = new PropertyParser();
		try {
			regGen = props.getWSRequestGenerator();
			log = new WSCLILogger(props.getLogFilePath());
		} catch (ParseException e) {
			throw new IllegalAdminCommandException(e.getMessage());
		}
		
		
	}
	
	private int checkArgument(String[] args, int argIndex, int defaultValue, int minVal, int maxVal, String errorMessage) throws IllegalAdminCommandException {
		int retval = defaultValue;
		if(args.length > argIndex){
			errorMessage = errorMessage.replaceAll("@DATA@", args[argIndex]);
			try{
				retval = Integer.parseInt(args[argIndex]);
				if(retval < 0 || retval > 10000){
					throw new IllegalAdminCommandException(errorMessage);
				}
			}catch(NumberFormatException e){
				throw new IllegalAdminCommandException(errorMessage);
			}
		}
		return retval;
	}
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		try{
		  WSCLI wSCLI = new WSCLI(args);
		  wSCLI.run();
		}catch(IllegalAdminCommandException e){
			out.println("Error: " + e.getMessage());
			System.exit(-1);
		} catch (InterruptedException e) {
			out.println("Error: " + e.getMessage());
			System.exit(-1);
		}
		if(log != null){
			log.close();
		}
		System.exit(0);
	}

	/**
	 * Main method performing the sign requests.
	 * @throws IllegalAdminCommandException 
	 * @throws InterruptedException 
	 */
	private void run() throws IllegalAdminCommandException, InterruptedException {
		WSClientThread[] clientThreads = new WSClientThread[numOfThreads];
        for(int i=0;i<numOfThreads;i++){        	
        	clientThreads[i] = new WSClientThread(i,signerIdOrName,numOfRequests,timeBetweenRequests,randomWaitTime);
        	new Thread(clientThreads[i]).start();
        }	
        out.println("Client started, tail log files for result.");
        while(Thread.activeCount() >1){
        	Thread.sleep(100);
        }
	}


	private void displayHelp() {
		out.println("SignServer WebService CLI\n");
		out.println("  Usage:");
		out.println("  wsclient <signer Id or Name> <number of requests> <milliseconds between request> <number of threads> <random wait>");
		out.println("  Where:");
		out.println("    Signer id or name to send requests to, (required parameter)");
		out.println("    Number of requests is for each thread (default is '1'), use 'c' or 'continuous' for infinite number of requests.");
		out.println("    Minimum milliseconds between requests is the least time the client waits before issuing the next (default is '1000').");
		out.println("    Number of threads that will send concurrent requests (default is '1').");
		out.println("    Random wait in milliseconds, used for more random test behaviour and is added to the fixed wait time (default is '0').\n");
		out.println("  The client requires a configuration file 'wsclient.properties' to exist in the same directory as the wscli, see the configuration file for more details.");
		
	}
	
	   class WSClientThread implements Runnable{
	        final private int threadIndex;
	    	private final String signerIdOrName;
	    	private final int numOfRequests;
	    	private final int timeBetweenRequests;
	    	private final int randomWaitTime;
			private final String loadBalancePolicy;
			private final String[] hosts;
			private final boolean useHTTPS;
			private final int port;
			private final int timeOut;
			private final String uRIPath;
	    	
	        final private Random random = new Random();



	        WSClientThread(int threadIndex, 
	        		String signerIdOrName, 
	        		int numOfRequests, int timeBetweenRequests,
	        		int randomWaitTime) throws IllegalAdminCommandException{
	            this.threadIndex = threadIndex;
	            this.signerIdOrName = signerIdOrName;
	            this.numOfRequests = numOfRequests;
	            this.timeBetweenRequests = timeBetweenRequests;
	            this.randomWaitTime = randomWaitTime;
	            try{
	            	loadBalancePolicy = props.getLoadBalancePolicy();
	            	hosts = props.getHosts();
	            	useHTTPS = props.useHTTPS();  
	            	port = props.getPort(); 
            		timeOut = props.getTimeout();
            		uRIPath = props.getURIPath();
	            }catch(ParseException e){
	            	throw new IllegalAdminCommandException(e.getMessage());
	            }
	            
	        }

	        public void run() {
	            LogErrorCallback logErrorCallback = new LogErrorCallback();

	            ISignServerWSClient client = null;
	            int i = 0;
	            while(numOfRequests == 0 || i<numOfRequests){
	                try {
	                    Thread.sleep(getWaitTime());
	                } catch (InterruptedException e1) {
	                    log.error("Thread : " + threadIndex + " : " + e1.getMessage(),e1);
	                }
	                try{                       	  
	                	    if(client == null){
	                	    	client = clientFactory.generateSignServerWSClient(loadBalancePolicy, hosts, useHTTPS, logErrorCallback, port, 
	            	            		timeOut, uRIPath);
	                	    }
	                    	List<ProcessResponseWS> responses = client.process(signerIdOrName, regGen.genProcessRequests(props.getProperites()));
	                    	if(responses == null){
	                    		log.error("Thread : " + threadIndex + " : FATAL no response recieved from any of the nodes" );         		
	                    	}else{	                    		                    	
	                    		String errorMessage = regGen.processResponses(responses);
	                    		if ( errorMessage==null){	                            
	                    			log.info("Thread : " + threadIndex + " : Successfully recieved and verified response.");
	                    		}else{
                                    log.error("Thread : " + threadIndex + " : Error verifying response, message : " + errorMessage);
	                    		}
	                    	}	                                 
	                }catch(Exception e){
	                    log.error("Thread : " + threadIndex + " : " +e.getClass().getName() + " : "  + ((e.getMessage() != null) ? e.getMessage() : "No message"), e );
	                }
	                i++;
	            }
	        }

	        private long getWaitTime() {			
	            return this.timeBetweenRequests + (randomWaitTime!=0 ? random.nextInt(randomWaitTime) : 0);
	        }

	        class LogErrorCallback implements IFaultCallback{
	            @SuppressWarnings("synthetic-access")
	            public void addCommunicationError(ICommunicationFault error) {
	                final String s = "Error communication with host : " + error.getHostName() + ", " + error.getDescription();
	                if (error.getThrowed() != null) {
	                	log.error(s, error.getThrowed());
                        } else {
	                    log.error(s);
                        }
	            }

			
	        }
	    }
	
}
