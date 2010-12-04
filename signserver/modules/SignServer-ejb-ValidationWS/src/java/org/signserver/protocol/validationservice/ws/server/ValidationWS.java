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

package org.signserver.protocol.validationservice.ws.server;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebService;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.apache.log4j.Logger;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.signserver.common.CompileTimeSettings;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.RequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerException;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.healthcheck.HealthCheckUtils;
import org.signserver.protocol.validationservice.ws.IValidationWS;
import org.signserver.protocol.validationservice.ws.ValidationResponse;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;
import org.signserver.validationservice.common.ValidationStatus;
import org.signserver.validationservice.server.ICertificateManager;
import org.signserver.validationservice.server.ValidationServiceWorker;




/**
 * Implementation of the Validation Service web interface.
 * 
 *
 * @version $Id: ValidationWS.java 1333 2010-12-04 11:49:26Z netmackan $
 */
@Stateless
@WebService(targetNamespace="gen.ws.validationservice.protocol.signserver.org")
public class ValidationWS implements IValidationWS {
	
	@Resource
	private WebServiceContext wsContext;
	
	private static final Logger log = Logger.getLogger(ValidationWS.class);
	
	/**
	 * @see org.signserver.protocol.validationservice.ws.IValidationWS#isValid(String, CertType)
	 */
	@WebMethod
	public ValidationResponse isValid(@WebParam(name="serviceName")String serviceName, @WebParam(name="base64Cert") String base64Cert,@WebParam(name="certPurposes") String certPurposes)  throws IllegalRequestException, SignServerException{
		ICertificate reqCert;
		int workerId = getWorkerId(serviceName);
		
		if(workerId == 0){
			throw new IllegalRequestException("Illegal service name : " + serviceName + " no validation service with such name exists");
		}
		
		if(base64Cert == null){
			throw new IllegalRequestException("Error base64Cert parameter cannot be empty, it must contain a Base64 encoded DER encoded certificate.");
		}else{
			try {
				reqCert = ICertificateManager.genICertificate(CertTools.getCertfromByteArray(Base64.decode(base64Cert.getBytes())));
			} catch (CertificateException e) {
				throw new IllegalRequestException("Error base64Cert parameter data have bad encoding, check that it contains supported certificate data");
			}
		}
		
		if(certPurposes == null){
			certPurposes = "";
		}else{
			certPurposes = certPurposes.trim();
		}
		
		ValidateResponse res = null;
		try {
			ValidateRequest req = new ValidateRequest(reqCert,certPurposes);
			res = (ValidateResponse) getWorkerSession().process(workerId, req, genRequestContext());
		} catch (CertificateEncodingException e) {
			throw new IllegalRequestException("Error in request, the requested certificate seem to have a unsupported encoding : " + e.getMessage());
		} catch (CryptoTokenOfflineException e) {
			throw new SignServerException("Error using cryptotoken when validating certificate, it seems to be offline : " + e.getMessage());
		}
		return new ValidationResponse(res.getValidation(), res.getValidCertificatePurposes());
	}
	
	/**
	 * Returning the worker id of the validation service with corresponding name or Id.
	 * Otherwise is 0 returned.
	 */
	private int getWorkerId(String serviceName) {	   
		int retval = 0;

		if(serviceName.substring(0, 1).matches("\\d")){
			retval = Integer.parseInt(serviceName);    		
		}else{
			retval = getWorkerSession().getWorkerId(serviceName);
		}

		if(retval != 0){
		  String classPath =  getGlobalConfigurationSession().getGlobalConfiguration().getProperty(GlobalConfiguration.SCOPE_GLOBAL, GlobalConfiguration.WORKERPROPERTY_BASE + retval + GlobalConfiguration.WORKERPROPERTY_CLASSPATH);
		  if(classPath == null || !classPath.trim().equals(ValidationServiceWorker.class.getName())){
			  retval = 0;
		  }
		}
		
		return retval;

	}

	private RequestContext genRequestContext() {		
		return new RequestContext(getClientCertificate(),getRequestIP());
	}

	/**
	 * @see org.signserver.protocol.validationservice.ws.IValidationWS#getStatus()
	 */
	@WebMethod
	public String getStatus(@WebParam(name="serviceName") String serviceName) throws IllegalRequestException{
		
		int workerId = getWorkerId(serviceName);
		
		if(workerId == 0){
			throw new IllegalRequestException("Illegal service name : " + serviceName + " no validation service with such name exists");
		}
		
		String errormessage = "";
		
		errormessage += HealthCheckUtils.checkDB(getCheckDBString());
		if(errormessage.equals("")){
		  errormessage += HealthCheckUtils.checkMemory(getMinimumFreeMemory());
		
		}
		
		if(errormessage.equals("")){
			// everything seems OK.
			errormessage = null;
		}
		
		if(errormessage== null){
			  errormessage = checkValidationService(workerId);
		}
		
		if(errormessage == null){					
			errormessage = "ALLOK";
		}
		
		return errormessage;
	}
	
    private String checkValidationService(int workerId) {
    	String retval = null;
    	try {
    		ValidationStatus status = (ValidationStatus) getWorkerSession().getStatus(workerId);
    		retval = status.isOK();
    		
    	} catch (InvalidWorkerIdException e) {
    		log.error("Error invalid worker id " + workerId + "when checking status for validation service");
    	}
		
		return retval;
	}

    private int minimumFreeMemory = 1;
    private int getMinimumFreeMemory(){
        final String minMemory = CompileTimeSettings.getInstance().getProperty(
                CompileTimeSettings.HEALTHECK_MINIMUMFREEMEMORY);
      if (minMemory != null) {
    	  try{
    	    minimumFreeMemory = Integer.parseInt(minMemory.trim());
    	  }catch(NumberFormatException e){
    		  log.error("Error: SignServerWS badly configured, setting healthcheck.minimumfreememory should only contain integers");
    	  }
      }
      return minimumFreeMemory;
    }
    
    private String checkDBString = "Select count(*) from signerconfigdata";
    private String getCheckDBString(){
        final String dbString = CompileTimeSettings.getInstance().getProperty(
                CompileTimeSettings.HEALTHECK_CHECKDBSTRING);
      if (dbString != null) {
    	  checkDBString = dbString;
      }
      return checkDBString;
    }
	
	
	private X509Certificate getClientCertificate(){
		MessageContext msgContext = wsContext.getMessageContext();
		HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
		X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

		if(certificates != null){
			return certificates[0];
		}
		return null;
	}
	
	private String getRequestIP(){
		MessageContext msgContext = wsContext.getMessageContext();
		HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
		
		return request.getRemoteAddr();
	}

        @EJB
	private IWorkerSession.IRemote signserversession;
	
    private IWorkerSession.IRemote getWorkerSession(){
    	if(signserversession == null){
    		try{
    		  signserversession = ServiceLocator.getInstance().lookupRemote(IWorkerSession.IRemote.class);
    		}catch(NamingException e){
    			log.error(e);
    		}
    	}
    	
    	return signserversession;
    }

    @EJB
    private IGlobalConfigurationSession.IRemote globalconfigsession;
	
    private IGlobalConfigurationSession.IRemote getGlobalConfigurationSession(){
    	if(globalconfigsession == null){
    		try{
                  globalconfigsession = ServiceLocator.getInstance().lookupRemote(IGlobalConfigurationSession.IRemote.class);
    		}catch(NamingException e){
    			log.error(e);
    		}
    	}
    	
    	return globalconfigsession;
    }

}
