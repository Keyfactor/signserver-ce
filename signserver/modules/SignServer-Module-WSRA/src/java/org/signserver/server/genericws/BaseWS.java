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

package org.signserver.server.genericws;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;

import javax.annotation.Resource;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.apache.log4j.Logger;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.annotations.WorkerEntityManager;
import org.signserver.server.clusterclassloader.ExtendedClusterClassLoader;
import org.signserver.server.cryptotokens.ICryptoToken;

/**
 * Abstract class containing help methods for retrieving
 * worker data such as, crypto token, worker entity manager,
 * worker config etc.
 * 
 * 
 * @author Philip Vendil 8 okt 2008
 *
 * @version $Id$
 */

public abstract class BaseWS {

	private transient Logger log = Logger.getLogger(this.getClass());
	
	@Resource
	protected WebServiceContext wsContext;	
	
	public static final String WORKERID               = "WORKERID";
	public static final String CRYPTOTOKEN            = "CRYPTOTOKEN";
	public static final String WORKERCONFIG           = "WORKERCONFIG";
	public static final String REQUESTCONTEXT         = "REQUESTCONTEXT";
	public static final String WORKERENTITYMANAGER    = "WORKERENTITYMANAGER";
	public static final String GLOBALENTITYMANAGER    = "GLOBALENTITYMANAGER";
	public static final String WORKERCERTIFICATE      = "WORKERCERTIFICATE";
	public static final String WORKERCERTIFICATECHAIN = "WORKERCERTIFICATECHAIN";
	
	
	public BaseWS() {
		super();
		if(getClass().getClassLoader() instanceof ExtendedClusterClassLoader){
			ExtendedClusterClassLoader ccl = (ExtendedClusterClassLoader) getClass().getClassLoader();
			workerEntityManager = ccl.getWorkerEntityManger(null);	       	
		}
	}
	protected ICryptoToken getCryptoToken(){
		if(cryptoToken == null){			
			HttpServletRequest request = (HttpServletRequest) wsContext.getMessageContext().get(MessageContext.SERVLET_REQUEST);
			cryptoToken = (ICryptoToken) request.getAttribute(CRYPTOTOKEN);
		}
		return cryptoToken;
	}	
	private ICryptoToken cryptoToken = null;
	
	protected WorkerConfig getWorkerConfig(){
		if(workerConfig == null){			
			HttpServletRequest request = (HttpServletRequest) wsContext.getMessageContext().get(MessageContext.SERVLET_REQUEST);
			workerConfig = (WorkerConfig) request.getAttribute(WORKERCONFIG);
		}
		return workerConfig;
	}	
	private WorkerConfig workerConfig = null;
	
	protected RequestContext getRequestContext(){
		if(requestContext == null){
			if(getWorkerConfig().getProperty("TESTCERT")!= null){
				try {
					requestContext = new RequestContext(CertTools.getCertfromByteArray(Base64.decode(getWorkerConfig().getProperty("TESTCERT").getBytes())),"0.0.0.0");
				} catch (CertificateException e) {
					log.error(e);
				}				
			}else{
				HttpServletRequest request = (HttpServletRequest) wsContext.getMessageContext().get(MessageContext.SERVLET_REQUEST);
				requestContext = (RequestContext) request.getAttribute(REQUESTCONTEXT);				
			}
		}
		return requestContext;
	}	
	private RequestContext requestContext = null;
	
	protected EntityManager getWorkerEntityManager(){
		if(workerEntityManager == null){			
			HttpServletRequest request = (HttpServletRequest) wsContext.getMessageContext().get(MessageContext.SERVLET_REQUEST);
			workerEntityManager = (EntityManager) request.getAttribute(WORKERENTITYMANAGER);
		}
		return workerEntityManager;
	}	
	
	@WorkerEntityManager
	protected EntityManager workerEntityManager = null;
	
	protected EntityManager getGlobalEntityManager(){
		if(globalEntityManager == null){			
			HttpServletRequest request = (HttpServletRequest) wsContext.getMessageContext().get(MessageContext.SERVLET_REQUEST);
			globalEntityManager = (EntityManager) request.getAttribute(GLOBALENTITYMANAGER);
		}
		return globalEntityManager;
	}	
	private EntityManager globalEntityManager = null;
	
	protected int getWorkerId(){
		if(workerId == null){			
			HttpServletRequest request = (HttpServletRequest) wsContext.getMessageContext().get(MessageContext.SERVLET_REQUEST);
			workerId = (Integer) request.getAttribute(WORKERID);
		}
		return workerId;
	}	
	private Integer workerId = null;
	
	protected Certificate getWorkerCertificate(){
		if(workerCertificate == null){			
			HttpServletRequest request = (HttpServletRequest) wsContext.getMessageContext().get(MessageContext.SERVLET_REQUEST);
			workerCertificate = (Certificate) request.getAttribute(WORKERCERTIFICATE);
		}
		return workerCertificate;
	}	
	private Certificate workerCertificate = null;
	
	@SuppressWarnings("unchecked")
	protected Collection<Certificate> getWorkerCertificateChain(){
		if(workerCertificateChain == null){			
			HttpServletRequest request = (HttpServletRequest) wsContext.getMessageContext().get(MessageContext.SERVLET_REQUEST);
			workerCertificateChain = (Collection<Certificate>) request.getAttribute(WORKERCERTIFICATECHAIN);
		}
		return workerCertificateChain;
	}	
	private Collection<Certificate> workerCertificateChain = null;
}
