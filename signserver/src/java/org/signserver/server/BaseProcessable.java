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

package org.signserver.server;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.WorkerConfig;
import org.signserver.server.cryptotokens.ICryptoToken;


public abstract class BaseProcessable extends BaseWorker implements IProcessable {
	
    /** Log4j instance for actual implementation class */
	private transient Logger log = Logger.getLogger(this.getClass());

	//Private Property constants

    protected ICryptoToken cryptoToken = null;

    
    protected BaseProcessable(){

    }

	    
	public void activateSigner(String authenticationCode)
			throws CryptoTokenAuthenticationFailureException,
			CryptoTokenOfflineException {		
		if (log.isTraceEnabled()) {
			log.trace(">activateSigner");
		}	    
		getCryptoToken().activate(authenticationCode);
		if (log.isTraceEnabled()) {
			log.trace("<activateSigner");
		}	    
	}

	public boolean deactivateSigner() throws CryptoTokenOfflineException {
		if (log.isTraceEnabled()) {
			log.trace(">deactivateSigner");
		}
		boolean ret = getCryptoToken().deactivate();
		if (log.isTraceEnabled()) {
			log.trace("<deactivateSigner");
		}
		return ret;
	}
	
	/**
	 * Returns the authentication type configured for this signer.
	 * Returns one of the ISigner.AUTHTYPE_ constants or the class path
	 * to a custom authenticator. 
	 * 
	 * default is client certificate authentication.
	 */
	public String getAuthenticationType(){				
		return config.getProperties().getProperty(WorkerConfig.PROPERTY_AUTHTYPE, IProcessable.AUTHTYPE_CLIENTCERT);
	}
	
	
	
	protected ICryptoToken getCryptoToken() {
		if (log.isTraceEnabled()) {
			log.trace(">getCryptoToken");
		}
		if(cryptoToken == null){
			GlobalConfiguration gc = getGlobalConfigurationSession().getGlobalConfiguration();
			try{				
				String classpath = gc.getCryptoTokenProperty(workerId,GlobalConfiguration.CRYPTOTOKENPROPERTY_CLASSPATH);
				if (log.isDebugEnabled()) {
					log.debug("Found cryptotoken classpath: "+classpath);
				}
				if(classpath != null){		
					Class<?> implClass = Class.forName(classpath);
					Object obj = implClass.newInstance();
					cryptoToken = (ICryptoToken) obj;
					cryptoToken.init(workerId, config.getProperties());								 
				} 
			}catch(CryptoTokenInitializationFailureException e){
				throw new EJBException(e);
			}catch(ClassNotFoundException e){
				throw new EJBException(e);
			}
			catch(IllegalAccessException iae){
				throw new EJBException(iae);
			}
			catch(InstantiationException ie){
				throw new EJBException(ie);
			}
		}
		if (log.isTraceEnabled()) {
			log.trace("<getCryptoToken: "+cryptoToken);
		}
		
		return cryptoToken;
	}

	

	
						
    private X509Certificate cert = null;	
 
	/**
	 * Private method that returns the certificate used when signing
	 * @throws CryptoTokenOfflineException 
	 */
	public Certificate getSigningCertificate() throws CryptoTokenOfflineException {
		if(cert==null){
			if(getCryptoToken() != null){
			  cert = (X509Certificate) getCryptoToken().getCertificate(ICryptoToken.PURPOSE_SIGN);
			}
			if(cert==null){
			  cert=( new ProcessableConfig( config)).getSignerCertificate();
			}
		}		
		return cert;
	}
	
	
	private Collection<Certificate> certChain = null;
	/**
	 * Private method that returns the certificate used when signing
	 * @throws CryptoTokenOfflineException 
	 */
	public Collection<Certificate> getSigningCertificateChain() throws CryptoTokenOfflineException {
		if(certChain==null){
			ICryptoToken cToken =  getCryptoToken();
			if(cToken != null){
				certChain =  cToken.getCertificateChain(ICryptoToken.PURPOSE_SIGN);
				if(certChain==null){
					log.debug("Signtoken did not contain a certificate chain, looking in config.");
					certChain=(new ProcessableConfig(config)).getSignerCertificateChain();
					if (certChain == null) {
						log.error("Neither Signtoken or ProcessableConfig contains a certificate chain!");					
					}
				}
			}
		}		
		return certChain;
	}

	/**
	 * Method sending the request info to the signtoken
	 * @return the request or null if method isn't supported by signertoken.
	 */
	public ICertReqData genCertificateRequest(ISignerCertReqInfo info) throws CryptoTokenOfflineException {
		if (log.isTraceEnabled()) {
			log.trace(">genCertificateRequest");
		}
		ICryptoToken token = getCryptoToken();
		if (log.isDebugEnabled()) {
			log.debug("Found a crypto token of type: "+token.getClass().getName());
			log.debug("Token status is: "+token.getCryptoTokenStatus());
		}
		ICertReqData data = token.genCertificateRequest(info);
		if (log.isTraceEnabled()) {
			log.trace("<genCertificateRequest");
		}
		return data;		 
	}
	
	/**
	 * Method sending the removal request to the signtoken
	 */
	public boolean destroyKey(int purpose) {
		return getCryptoToken().destroyKey(purpose);
	}
	
}
