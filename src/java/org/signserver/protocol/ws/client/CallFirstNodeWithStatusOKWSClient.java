package org.signserver.protocol.ws.client;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;

import org.apache.log4j.Logger;
import org.signserver.protocol.ws.ProcessRequestWS;
import org.signserver.protocol.ws.ProcessResponseWS;
import org.signserver.protocol.ws.gen.CryptoTokenOfflineException_Exception;
import org.signserver.protocol.ws.gen.IllegalRequestException_Exception;
import org.signserver.protocol.ws.gen.InvalidWorkerIdException_Exception;
import org.signserver.protocol.ws.gen.SignServerException_Exception;
import org.signserver.protocol.ws.gen.SignServerWS;
import org.signserver.protocol.ws.gen.SignServerWSService;
import org.signserver.protocol.ws.gen.WorkerStatusWS;


/**
 * The main message client class that implements the 
 * high availability functionality and should be used
 * by clients to make reliable calls to a message api
 * server cluster.
 * 
 * 
 * @author Philip Vendil 2007 feb 3
 *
 * @version $Id: CallFirstNodeWithStatusOKWSClient.java,v 1.1 2007-11-27 06:05:11 herrvendil Exp $
 */
public class CallFirstNodeWithStatusOKWSClient implements ISignServerWSClient {
	    private static Logger log = Logger.getLogger(CallFirstNodeWithStatusOKWSClient.class);
		

	    
	    private String[] hosts;
	    private int timeOut;
	    
		private String fastestHost = null;
		private String protocol = SignServerWSClientFactory.PROTOCOL;
		
		private HashMap<String, SignServerWS> serviceMap = new HashMap<String, SignServerWS>();
	    

	    
	    /**
	     * Special constructor used from test scripts
	     * 
	     * @param host to connect to
	     * @param port to connect to
	     * @param securityLayer to use
	     * @param transportLayer to use
	     * @param timeOut in milliseconds
	     * @param wSDLURL the URL to the WSDL of the service appended to the host and port.
	     * @param useHTTPS if HTTPS should be used.  
	     * 
	     */
	    public void init(String[] hosts, int port, int timeOut, 
	    		             String  wSDLURL, boolean useHTTPS){

	        this.hosts = hosts;  
	        this.timeOut = timeOut;
	        if(useHTTPS){
	        	protocol = SignServerWSClientFactory.SECURE_PROTOCOL;
	        }
	        
	        QName qname = new QName("gen.ws.protocol.signserver.org", "SignServerWSService");
	        for (int i = 0; i < hosts.length; i++) {
				try {
					URL u = new URL(protocol + hosts[i] + ":" + port + wSDLURL);
					SignServerWSService signServerWSService = new SignServerWSService(u,qname);
					SignServerWS client = signServerWSService.getSignServerWSPort();
					if( client instanceof BindingProvider ){
						( ( BindingProvider ) client ).getRequestContext().put(
								"com.sun.xml.ws.connect.timeout", timeOut  );
						( ( BindingProvider ) client ).getRequestContext().put(
								"com.sun.xml.ws.request.timeout", timeOut  );
					} 
					serviceMap.put(hosts[i], client);
				} catch (MalformedURLException e) {
					log.error("MalformedURLException :" +protocol + hosts[i] + ":" + port + wSDLURL ,e);
				}

			}
	    }
	    
	    /**
		 * @see org.signserver.protocol.ws.client.ISignServerWSClient#process(String, List, IFaultCallback)
		 */
	    public List<ProcessResponseWS> process(String workerId, List<ProcessRequestWS> requests, IFaultCallback errorCallback){
	    	List<ProcessResponseWS> resp = null;

	    	String fastestHost = getFastestHost(errorCallback);

	    	if(fastestHost != null){
	    		SignServerWS service = serviceMap.get(fastestHost);	

	    		try {
	    			List<org.signserver.protocol.ws.gen.ProcessResponseWS> response = service.process(workerId, WSClientUtil.convertProcessRequestWS(requests));
	    			if(response != null && response.size() != 0){
	    				resp = WSClientUtil.convertProcessResponseWS(response);  
	    			}
	    		} catch (IllegalRequestException_Exception e) {
	    			errorCallback.addCommunicationError(new GenericCommunicationFault(fastestHost,new org.signserver.common.IllegalRequestException(e.getMessage())));
	    		} catch (InvalidWorkerIdException_Exception e) {
	    			errorCallback.addCommunicationError(new GenericCommunicationFault(fastestHost,new org.signserver.common.InvalidWorkerIdException(e.getMessage())));
	    		} catch (SignServerException_Exception e) {
	    			errorCallback.addCommunicationError(new GenericCommunicationFault(fastestHost,new org.signserver.common.SignServerException(e.getMessage())));
	    		} catch (CryptoTokenOfflineException_Exception e) {
	    			errorCallback.addCommunicationError(new GenericCommunicationFault(fastestHost,new org.signserver.common.CryptoTokenOfflineException(e.getMessage())));
	    		}

	    	}

	    	return resp;
	    }
		


		/**
	     * Method that sends a status requests to all hosts
	     * in the cluster and returns the host name of
	     * the first to respond
	     * 
	     * If some error occurred of making a call to some
	     * of the nodes the error callback will be called
	     * 
	     * @param errorCallback
	     * @return the fastest host or null if no host responded within the timeout.
	     */
	    
	    String getFastestHost(IFaultCallback errorCallback) {
	        this.fastestHost = null;
	        
	        for(int i=0; i<hosts.length ; i++)
	            new Thread(new StatusChecker("ID " + i,hosts[i],errorCallback)).start();
	        synchronized( this ) {
	            try {
	                this.wait(timeOut);
	            } catch (InterruptedException e) {
	                throw new Error(e);
	            }
	        }
	        return fastestHost;
	    }

	    
	    /**
	     * Inner class running a thread that sends
	     * a status request to each of the servers
	     * in the cluster.
	     * 
	     */
	    private class StatusChecker implements Runnable{
	    	private Logger logStatusChecker = Logger.getLogger(StatusChecker.class);
	    	
	    	final private String host;
			final private IFaultCallback errorCallback;		
			
			final private String id;

			public StatusChecker(String id, String host, IFaultCallback errorCallback){
	    		super();
	    		this.id = id;
	    		this.host = host;
	    		this.errorCallback = errorCallback;    		
	    	}
	    	
			@SuppressWarnings("synthetic-access")
	        public void run() {
			    boolean statusOK = false;
			    logStatusChecker.debug("Thread with id : " + id + " started.");
			    try{
			    	List<WorkerStatusWS> result = serviceMap.get(host).getStatus(id);
			    	if(result.size() == 1){
			    		WorkerStatusWS status = result.get(0);
			    		if(status.getOverallStatus().equals(org.signserver.protocol.ws.WorkerStatusWS.OVERALLSTATUS_ALLOK))
			    			statusOK = true;
			    		else {
			    			errorCallback.addCommunicationError(new GenericCommunicationFault(host,"Error the node responded status ERROR :" + status.getErrormessage() ));			        			
			    		}
			    	}
			    }catch (InvalidWorkerIdException_Exception e) {
			    	errorCallback.addCommunicationError(new GenericCommunicationFault(host,new org.signserver.common.InvalidWorkerIdException(e.getMessage())));
				}
			    logStatusChecker.debug("Thread with id : " + id + " finished.");
			    synchronized( CallFirstNodeWithStatusOKWSClient.this ) {
			        if ( fastestHost==null && statusOK ) {
			            fastestHost = host;
			            CallFirstNodeWithStatusOKWSClient.this.notifyAll();
	                }
			    }
			}
	    }


	}

