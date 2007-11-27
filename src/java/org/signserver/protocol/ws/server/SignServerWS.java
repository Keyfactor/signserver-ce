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

package org.signserver.protocol.ws.server;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.annotation.Resource;
import javax.jws.WebService;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.apache.log4j.Logger;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IProcessResponse;
import org.signserver.common.ISignResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.SignServerException;
import org.signserver.common.SignerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.protocol.ws.Certificate;
import org.signserver.protocol.ws.ISignServerWS;
import org.signserver.protocol.ws.ProcessRequestWS;
import org.signserver.protocol.ws.ProcessResponseWS;
import org.signserver.protocol.ws.WorkerStatusWS;
import org.signserver.server.signers.BaseSigner;
import org.signserver.web.SignServerHealthCheck;



/**
 * Implementor of the ISignServerWS interface.
 * 
 * @author Philip Vendil
 * $Id: SignServerWS.java,v 1.1 2007-11-27 06:05:12 herrvendil Exp $
 */

@WebService(targetNamespace="gen.ws.protocol.signserver.org")
public class SignServerWS implements ISignServerWS {
	
	@Resource
	private WebServiceContext wsContext;	

	
	private static final Logger log = Logger.getLogger(SignServerWS.class);

	public Collection<WorkerStatusWS> getStatus(String workerIdOrName)
			throws InvalidWorkerIdException {
		log.info("WS getStatus called");
		ArrayList<WorkerStatusWS> retval = new ArrayList<WorkerStatusWS>();
		
		String errormessage = "";
		
		errormessage += SignServerHealthCheck.checkDB(getCheckDBString());
		if(errormessage.equals("")){
		  errormessage += SignServerHealthCheck.checkMemory(getMinimumFreeMemory());										  	
		
		}
		
		if(errormessage.equals("")){
			// everything seems ok.
			errormessage = null;
		}
		
	     // TODO Check Signers
		int workerId = 0;
		try {
			if(workerIdOrName.equalsIgnoreCase(ISignServerWS.ALLWORKERS))
			workerId = getWorkerId(workerIdOrName);
		} catch (IllegalRequestException e) {
			throw new InvalidWorkerIdException("Worker id or name " + workerIdOrName + " couldn't be found.");
		}
		
		if(workerId != 0){
			// Specified WorkerId
			if(errormessage== null){
				  errormessage = checkSigner(workerId);
			}
			WorkerStatusWS resp = new WorkerStatusWS();
			if(errormessage == null){					
				resp.setOverallStatus(WorkerStatusWS.OVERALLSTATUS_ALLOK);
			}else{
				resp.setOverallStatus(WorkerStatusWS.OVERALLSTATUS_ERROR);
				resp.setErrormessage(errormessage);
			}
			retval.add(resp);
		}else{
			// All Workers
			List<Integer> signers = getGlobalConfigurationSession().getWorkers(GlobalConfiguration.WORKERTYPE_SIGNERS);
			for (Iterator<Integer> iterator = signers.iterator(); iterator.hasNext();) {
				int next =  iterator.next();
				if(errormessage== null){
				  errormessage = checkSigner(next);
				}
				
				WorkerStatusWS resp = new WorkerStatusWS();
				if(errormessage == null){					
					resp.setOverallStatus(WorkerStatusWS.OVERALLSTATUS_ALLOK);
				}else{
					resp.setOverallStatus(WorkerStatusWS.OVERALLSTATUS_ERROR);
					resp.setErrormessage(errormessage);
				}
				retval.add(resp);			    
			}							
		}
		
		
		
		
		retval.add(new WorkerStatusWS(WorkerStatusWS.OVERALLSTATUS_ALLOK,null));
		
		return retval;
	}
	
	private String checkSigner(int workerId) throws InvalidWorkerIdException{
		String retval = null;
		SignerStatus signerStatus = (SignerStatus) getSignServerSession().getStatus(workerId);
		WorkerConfig signerConfig = signerStatus.getActiveSignerConfig();
		if(signerConfig.getProperties().getProperty(BaseSigner.DISABLED) == null  || !signerConfig.getProperties().getProperty(BaseSigner.DISABLED).equalsIgnoreCase("TRUE")){													
		  if(signerStatus.getTokenStatus() == SignerStatus.STATUS_OFFLINE){
			  retval ="Error Signer Token is disconnected, worker Id : " + workerId;
		  }
		}
		
		return retval;
	}


   /**
    * @see  org.signserver.protocol.ws.ISignServerWS#signData(String, Collection)
    */
	public Collection<ProcessResponseWS> process(String workerIdOrName,
			Collection<ProcessRequestWS> requests)
			throws InvalidWorkerIdException, IllegalRequestException,
			CryptoTokenOfflineException, SignServerException {
		ArrayList<ProcessResponseWS> retval = new ArrayList<ProcessResponseWS>();
		
		X509Certificate clientCert = getClientCertificate();
		String requestIP = getRequestIP();
		
		int workerId = getWorkerId(workerIdOrName);
		
		ArrayList<Certificate> signerCertificateChain = getSignerCertificateChain(workerId);
		
		for (Iterator<ProcessRequestWS> iterator = requests.iterator(); iterator.hasNext();) {
			ProcessRequestWS next = iterator.next();
			GenericSignRequest req = new GenericSignRequest(next.getRequestID(),next.getSignRequestData());
			IProcessResponse resp = getSignServerSession().process(workerId, req, clientCert, requestIP);
			ProcessResponseWS wsresp = new ProcessResponseWS();
			wsresp.setProcessedData((byte[]) resp.getProcessedData());
			if(resp instanceof ISignResponse){
				wsresp.setRequestID(((ISignResponse)resp).getRequestID());
				try {
					wsresp.setSignerCertificate(new Certificate(((ISignResponse)resp).getSignerCertificate()));
					wsresp.setSignerCertificateChain(signerCertificateChain);					
				} catch (CertificateEncodingException e) {
					log.error(e);
				}
				
			}
			retval.add(wsresp);
		}
		return retval;
	}				


	private ArrayList<Certificate> getSignerCertificateChain(int workerId) throws InvalidWorkerIdException {
		ArrayList<Certificate> retval = null;
		try{
		  WorkerStatus ws = getSignServerSession().getStatus(workerId);
		  if(ws instanceof SignerStatus){
			ProcessableConfig sc = new ProcessableConfig(((SignerStatus) ws).getActiveSignerConfig());
			Collection<java.security.cert.Certificate> signerCertificateChain = sc.getSignerCertificateChain();
			
			if(signerCertificateChain != null){
				retval = new ArrayList<Certificate>();
				for (Iterator<java.security.cert.Certificate> iterator = signerCertificateChain.iterator(); iterator.hasNext();) {
					retval.add(new Certificate(iterator.next()));			
				}
			}
		  }
		}catch (CertificateEncodingException e) {
			log.error(e);
		}
		
		
		
	return null;
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
	
    private int getWorkerId(String workerIdOrName) throws IllegalRequestException{
    	int retval = 0;
    	
    	if(workerIdOrName.substring(0, 1).matches("\\d")){
    		retval = Integer.parseInt(workerIdOrName);    		
    	}else{
    		retval = getSignServerSession().getWorkerId(workerIdOrName);
    		if(retval == 0){
    			throw new IllegalRequestException("Error: No worker with the given name could be found");
    		}
    	}
    	
    	return retval;
    }
    
    
    private static final String MINIMUMFREEMEMORY = "@healthcheck.minimumfreememory@";
    private int minimumFreeMemory = 1;
    private int getMinimumFreeMemory(){
      if(!MINIMUMFREEMEMORY.equals("@healthcheck.minimumfreememory@")){
    	  try{
    	    minimumFreeMemory = Integer.parseInt(MINIMUMFREEMEMORY.trim());
    	  }catch(NumberFormatException e){
    		  log.error("Error: SignServerWS badly configured, setting healthcheck.minimumfreememory should only contain integers");
    	  }
      }
      return minimumFreeMemory;
    }
    
    private static final String CHECKDBSTRING = "@healthcheck.checkdbstring@";
    private String checkDBString = "Select count(*) from SignerConfigData";
    private String getCheckDBString(){
      if(!CHECKDBSTRING.equals("@healthcheck.checkdbstring@")){
    	  checkDBString = CHECKDBSTRING;
      }
      return checkDBString;
    }
    
	private IWorkerSession.ILocal signserversession;
	
    private IWorkerSession.ILocal getSignServerSession(){
    	if(signserversession == null){
    		try{
    		  Context context = new InitialContext();
    		  signserversession =  (org.signserver.ejb.interfaces.IWorkerSession.ILocal) context.lookup(IWorkerSession.ILocal.JNDI_NAME);
    		}catch(NamingException e){
    			log.error(e);
    		}
    	}
    	
    	return signserversession;
    }
    
	private IGlobalConfigurationSession.ILocal globalconfigsession;
	
    private IGlobalConfigurationSession.ILocal getGlobalConfigurationSession(){
    	if(globalconfigsession == null){
    		try{
    		  Context context = new InitialContext();
    		  globalconfigsession =  (org.signserver.ejb.interfaces.IGlobalConfigurationSession.ILocal) context.lookup(IGlobalConfigurationSession.ILocal.JNDI_NAME);
    		}catch(NamingException e){
    			log.error(e);
    		}
    	}
    	
    	return globalconfigsession;
    }
}
