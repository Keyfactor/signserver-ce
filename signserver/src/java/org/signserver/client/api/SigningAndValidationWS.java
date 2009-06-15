package org.signserver.client.api;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.LinkedList;
import java.util.List;

import javax.xml.namespace.QName;

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
import org.signserver.protocol.ws.client.WSClientUtil;
import org.signserver.protocol.ws.gen.CryptoTokenOfflineException_Exception;
import org.signserver.protocol.ws.gen.IllegalRequestException_Exception;
import org.signserver.protocol.ws.gen.InvalidWorkerIdException_Exception;
import org.signserver.protocol.ws.gen.ProcessRequestWS;
import org.signserver.protocol.ws.gen.ProcessResponseWS;
import org.signserver.protocol.ws.gen.SignServerException_Exception;
import org.signserver.protocol.ws.gen.SignServerWS;
import org.signserver.protocol.ws.gen.SignServerWSService;

/**
 * Implements ISigningAndValidation using Web Services interface.
 * 
 * @author Markus Kilås
 * @verion $Id$
 */
public class SigningAndValidationWS implements ISigningAndValidation {

	private static Logger log = Logger.getLogger(SigningAndValidationWS.class);

	private SignServerWS signserver;

	public SigningAndValidationWS(String host, int port) {
		String url = "http://" + host + ":" + port + "/signserver/signserverws/signserverws?wsdl";
		SignServerWSService service;
		try {
			service = new SignServerWSService(new URL(url), new QName("gen.ws.protocol.signserver.org", "SignServerWSService"));
		} catch (MalformedURLException ex) {
			throw new IllegalArgumentException("Malformed URL: " + url, ex);
		}
		signserver = service.getSignServerWSPort();
		SignServerUtil.installBCProvider();
	}

	public GenericSignResponse sign(String signIdOrName, byte[] document) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
		try {
			ProcessRequestWS reqWS = new ProcessRequestWS();
			reqWS.setRequestDataBase64(new String(Base64.encode(RequestAndResponseManager.serializeProcessRequest(new GenericSignRequest(1, document)))));
			List<ProcessRequestWS> list = new LinkedList<ProcessRequestWS>();
			list.add(reqWS);

			List<ProcessResponseWS> resps;
			try {
				resps = signserver.process(signIdOrName, list);
			} catch (CryptoTokenOfflineException_Exception e) {
				log.error(null, e);
				throw new CryptoTokenOfflineException(e.getMessage());
			} catch (IllegalRequestException_Exception e) {
				log.error(null, e);
				throw new IllegalRequestException(e.getMessage());
			} catch (InvalidWorkerIdException_Exception e) {
				log.error(null, e);
				throw new IllegalRequestException(e.getMessage());
			} catch (SignServerException_Exception e) {
				log.error(null, e);
				throw new SignServerException(e.getMessage());
			}

			List<org.signserver.protocol.ws.ProcessResponseWS> responses2 = WSClientUtil.convertProcessResponseWS(resps);

			org.signserver.protocol.ws.ProcessResponseWS theResponse = responses2.get(0);
			byte[] responseData = theResponse.getResponseData();

			GenericSignResponse resp = (GenericSignResponse) RequestAndResponseManager.parseProcessResponse(responseData);

			if (resps.get(0).getRequestID() != resp.getRequestID()) {
				log.error("Error, invalid request id " + resp.getRequestID() + " in responses");
				throw new SignServerException("Unexpected request id " + resp.getRequestID() + " expected " + resps.get(0).getRequestID());
			}

			return resp;

		} catch (IOException ex) {
			throw new SignServerException("Serialization/deserialization failed", ex);
		}
	}

	public GenericValidationResponse validate(String validatorIdOrName, byte[] document) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
		try {
			ProcessRequestWS reqWS = new ProcessRequestWS();
			reqWS.setRequestDataBase64(new String(Base64.encode(RequestAndResponseManager.serializeProcessRequest(new GenericValidationRequest(1, document)))));
			List<ProcessRequestWS> list = new LinkedList<ProcessRequestWS>();
			list.add(reqWS);

			List<ProcessResponseWS> resps;
			try {
				resps = signserver.process(validatorIdOrName, list);
			} catch (CryptoTokenOfflineException_Exception e) {
				log.error(null, e);
				throw new CryptoTokenOfflineException(e.getMessage());
			} catch (IllegalRequestException_Exception e) {
				log.error(null, e);
				throw new IllegalRequestException(e.getMessage());
			} catch (InvalidWorkerIdException_Exception e) {
				log.error(null, e);
				throw new IllegalRequestException(e.getMessage());
			} catch (SignServerException_Exception e) {
				log.error(null, e);
				throw new SignServerException(e.getMessage());
			}
			List<org.signserver.protocol.ws.ProcessResponseWS> responses2 = WSClientUtil.convertProcessResponseWS(resps);

			org.signserver.protocol.ws.ProcessResponseWS theResponse = responses2.get(0);
			byte[] responseData = theResponse.getResponseData();

			GenericValidationResponse resp = (GenericValidationResponse) RequestAndResponseManager.parseProcessResponse(responseData);

			log.debug("Valid: " + resp.isValid());
			return resp;

		} catch (IOException ex) {
			throw new SignServerException("IOException", ex);
		}
	}

}
