package org.signserver.client.api;

import java.io.IOException;
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
import org.signserver.common.RequestAndResponseManager;
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
 * @verion $Id$
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
		this.signserver = clientFactory.generateSignServerWSClient(SignServerWSClientFactory.CLIENTTYPE_CALLFIRSTNODEWITHSTATUSOK, hosts, useHTTPS, new LogErrorCallback(), port, timeOut, customAppURI);
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

	public GenericSignResponse sign(String xmlSignWorker, byte[] xmlDocument) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
		try {
			org.signserver.protocol.ws.ProcessRequestWS reqWS = new org.signserver.protocol.ws.ProcessRequestWS();
			reqWS.setRequestDataBase64(new String(Base64.encode(RequestAndResponseManager.serializeProcessRequest(new GenericSignRequest(1, xmlDocument)))));
			List<org.signserver.protocol.ws.ProcessRequestWS> list = new LinkedList<org.signserver.protocol.ws.ProcessRequestWS>();
			list.add(reqWS);

			List<org.signserver.protocol.ws.ProcessResponseWS> resps;
			
			resps = signserver.process(xmlSignWorker, list);

			org.signserver.protocol.ws.ProcessResponseWS theResponse = resps.get(0);
			byte[] responseData = theResponse.getResponseData();

			GenericSignResponse resp = (GenericSignResponse) RequestAndResponseManager.parseProcessResponse(responseData);

			if(resps == null) {
				throw new SignServerException("Exception", exception);
			}
			
			if (resps.get(0).getRequestID() != resp.getRequestID()) {
				log.error("Error, invalid request id " + resp.getRequestID() + " in responses");
				throw new SignServerException("Unexpected request id " + resp.getRequestID() + " expected " + resps.get(0).getRequestID());
			}

			return resp;

		} catch (IOException ex) {
			throw new SignServerException("Serialization/deserialization failed", ex);
		}
	}

	public GenericValidationResponse validate(String xmlValidateWorker, byte[] xmlDocument) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
		try {
			org.signserver.protocol.ws.ProcessRequestWS reqWS = new org.signserver.protocol.ws.ProcessRequestWS();
			reqWS.setRequestDataBase64(new String(Base64.encode(RequestAndResponseManager.serializeProcessRequest(new GenericValidationRequest(1, xmlDocument)))));
			List<org.signserver.protocol.ws.ProcessRequestWS> list = new LinkedList<org.signserver.protocol.ws.ProcessRequestWS>();
			list.add(reqWS);

			List<org.signserver.protocol.ws.ProcessResponseWS> resps;
			
			resps = signserver.process(xmlValidateWorker, list);
			
			if(resps == null) {
				throw new SignServerException("Exception", exception);
			}

			org.signserver.protocol.ws.ProcessResponseWS theResponse = resps.get(0);
			byte[] responseData = theResponse.getResponseData();

			GenericValidationResponse resp = (GenericValidationResponse) RequestAndResponseManager.parseProcessResponse(responseData);

			log.debug("Valid: " + resp.isValid());
			return resp;

		} catch (IOException ex) {
			throw new SignServerException("Serialization/deserialization failed", ex);
		}

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
