package org.signserver.client.api;

import java.io.IOException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GenericValidationRequest;
import org.signserver.common.GenericValidationResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestAndResponseManager;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.protocol.ws.client.ICommunicationFault;
import org.signserver.protocol.ws.client.IFaultCallback;
import org.signserver.protocol.ws.client.ISignServerWSClient;
import org.signserver.protocol.ws.client.SignServerWSClientFactory;

/**
 * Implements ISigningAndValidation using SignServer WS Client interface that
 * has support for load balancing etc.
 *
 * @author Markus Kilås
 * @version
 * $Id$
 */
public class SigningAndValidationWSBalanced implements ISigningAndValidation {

	private static Logger log = Logger.getLogger(SigningAndValidationWSBalanced.class);

	private ISignServerWSClient signserver;

	private Throwable exception;
	
	private SigningAndValidationWSBalanced() {
		SignServerUtil.installBCProvider();
	}
	
	/**
	 * Creates an instance of SigningAndValidationWSBalanced using an 
	 * ISignServerWSClient.
	 * 
	 * @param client The ISignServerWSClient to use.
	 */
	public SigningAndValidationWSBalanced(ISignServerWSClient client) {
		this();
		this.signserver = client;
	}
	
	/**
	 * Creates an instance of SigningAndValidationWSBalanced.
	 * 
     * @param clientType One of the CLIENTTYPE_ constants indication the High-Availability policy that should be used.
     * @param hosts Host names of the servers to connect to.
     * @param useHTTPS indicates if HTTPS should be used.
     * @param port to connect to.
     * @param timeOut in milliseconds.
     * @param customAppURI the path to the sign server URI where the WS is deployed.
     * @param clientFactory SignServerWSClientFactory to use for generating the client.
     */
	public SigningAndValidationWSBalanced(String clientType, String[] hosts, boolean useHTTPS, IFaultCallback faultCallback, int port, int timeOut, String customAppURI, SignServerWSClientFactory clientFactory) {
		this();
		this.signserver = clientFactory.generateSignServerWSClient(clientType, hosts, useHTTPS, faultCallback, port, timeOut, customAppURI);
	}
	
	/** 
	 * Creates an instance of SigningAndValidationWSBalanced using host and port 
	 * and default parameters.
	 *  
	 * @param host The remote host to connect to.
	 * @param port The remote port to connect to.
	 */
	public SigningAndValidationWSBalanced(String host, int port) {
		this();
		this.signserver = new SignServerWSClientFactory().generateSignServerWSClient(SignServerWSClientFactory.CLIENTTYPE_CALLFIRSTNODEWITHSTATUSOK, new String[]{host}, false, new LogErrorCallback(), port, SignServerWSClientFactory.DEFAULT_TIMEOUT, SignServerWSClientFactory.DEFAULT_WSDL_URL);
	}
	
	/**
	 * Creates an instance of SigningAndValidationWSBalanced using default client factory.
	 * 
     * @param clientType One of the CLIENTTYPE_ constants indication the High-Availability policy that should be used.
     * @param hosts Host names of the servers to connect to.
     * @param useHTTPS indicates if HTTPS should be used.
     * @param port to connect to.
     * @param timeOut in milliseconds.
     * @param customAppURI the path to the sign server URI where the WS is deployed.
     */
	public SigningAndValidationWSBalanced(String clientType, String[] hosts, boolean useHTTPS, IFaultCallback faultCallback, int port, int timeOut, String customAppURI) {
		this(clientType, hosts, useHTTPS, faultCallback, port, timeOut, customAppURI, new SignServerWSClientFactory());
	}

	@Override
	public ProcessResponse process(String workerIdOrName, ProcessRequest request, RequestContext context) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
		List<ProcessResponse> responses = process(workerIdOrName, Collections.singletonList(request), context);
		if(responses.size() != 1) {
			throw new SignServerException("Unexpected number of responses: " + responses.size());
		}
		return responses.get(0);
	}
	
	public List<ProcessResponse> process(String workerIdOrName, List<ProcessRequest> requests, RequestContext context) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
		
		try {
		
			List<org.signserver.protocol.ws.ProcessRequestWS> list = new LinkedList<org.signserver.protocol.ws.ProcessRequestWS>();
			
			for(ProcessRequest req : requests) {
				org.signserver.protocol.ws.ProcessRequestWS reqWS = new org.signserver.protocol.ws.ProcessRequestWS();
				reqWS.setRequestDataBase64(new String(Base64.encode(RequestAndResponseManager.serializeProcessRequest(req))));
				list.add(reqWS);
			}
	
			List<org.signserver.protocol.ws.ProcessResponseWS> resps = signserver.process(workerIdOrName, list);
			
			if(resps == null) {
				exception.printStackTrace();
				throw new SignServerException("Exception", exception);
			}
			
			List<ProcessResponse> responses3 = new LinkedList<ProcessResponse>();
			
			for(org.signserver.protocol.ws.ProcessResponseWS resp : resps) {
				responses3.add(RequestAndResponseManager.parseProcessResponse(resp.getResponseData()));
			}
			
			return responses3;
			
		} catch (IOException ex) {
			throw new SignServerException("Serialization/deserialization failed", ex);
		}
	}
	
	public GenericSignResponse sign(String signerIdOrName, byte[] document) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {

		ProcessResponse resp = process(signerIdOrName, new GenericSignRequest(1, document), new RequestContext());

		if(!(resp instanceof GenericSignResponse)) {
			throw new SignServerException("Unexpected response type: " + resp.getClass().getName());
		}		
		return (GenericSignResponse) resp;
	}

	public GenericValidationResponse validate(String validatorIdOrName, byte[] document) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
		ProcessResponse resp = process(validatorIdOrName, new GenericValidationRequest(1, document), new RequestContext());

		if(!(resp instanceof GenericValidationResponse)) {
			throw new SignServerException("Unexpected response type: " + resp.getClass().getName());
		}
		return (GenericValidationResponse) resp;
	}

	class LogErrorCallback implements IFaultCallback {
        @SuppressWarnings("synthetic-access")
        public void addCommunicationError(ICommunicationFault error) {
            final String s = "Error communication with host : " + error.getHostName() + ", " + error.getDescription();
            if(error.getThrowed() != null) {
                log.error(s, error.getThrowed());
            } else {
            	log.error(s);
            }
            exception = error.getThrowed();
        }
    }
	
}
