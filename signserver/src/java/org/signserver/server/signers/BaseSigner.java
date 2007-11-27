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

package org.signserver.server.signers;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ISignerCertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.SignerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.server.BaseWorker;
import org.signserver.server.cryptotokens.ICryptoToken;


public abstract class BaseSigner extends BaseWorker implements ISigner {
	
	private transient Logger log = Logger.getLogger(this.getClass());

	//Private Property constants
	/**
	 * Property indicating that the signserver shouldn't be used.
	 * Set propery to TRUE to disable the signer.
	 */
	public static final String DISABLED          = "DISABLED";
	
	/**
	 * Constant indicating that the signserver archive the response data.
	 * Set propery to TRUE to start archiving
	 */
	public static final String ARCHIVE          = "ARCHIVE";

    /** Log4j instance for actual implementation class */
   // private transient Logger log = Logger.getLogger(this.getClass());
    
    protected ICryptoToken cryptoToken = null;

    
    protected BaseSigner(){

    }

	    
	public void activateSigner(String authenticationCode)
			throws CryptoTokenAuthenticationFailureException,
			CryptoTokenOfflineException {		
			    
		getCryptoToken().activate(authenticationCode);
	    
	}

	public boolean deactivateSigner() throws CryptoTokenOfflineException {
		return getCryptoToken().deactivate();
	}
	
	/**
	 * Returns the authentication type configured for this signer.
	 * Returns one of the ISigner.AUTHTYPE_ constants or the class path
	 * to a custom authenticator. 
	 * 
	 * default is client certificate authentication.
	 */
	public String getAuthenticationType(){				
		return config.getProperties().getProperty(WorkerConfig.PROPERTY_AUTHTYPE, ISigner.AUTHTYPE_CLIENTCERT);
	}
	
	/**
	 * @see org.signserver.server.signers.ISigner#getStatus()
	 */
	public WorkerStatus getStatus() {
		SignerStatus retval = null;
		
        try {
			retval = new SignerStatus(getCryptoToken().getCryptoTokenStatus(), new ProcessableConfig( config), getSigningCertificate());
		} catch (CryptoTokenOfflineException e) {
			retval = new SignerStatus(getCryptoToken().getCryptoTokenStatus(), new ProcessableConfig( config), null);
		}
		
		
		return retval;
	}
	
	protected ICryptoToken getCryptoToken() {
		if(cryptoToken == null){
			GlobalConfiguration gc = getGlobalConfigurationSession().getGlobalConfiguration();
			try{				
				String classpath =gc.getSignTokenProperty(
						workerId,GlobalConfiguration.SIGNTOKENPROPERTY_CLASSPATH);
				if(classpath != null){		
					Class<?> implClass = Class.forName(classpath);
					Object obj = implClass.newInstance();
					cryptoToken = (ICryptoToken) obj;
					cryptoToken.init(config.getProperties());								 
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
		
		return cryptoToken;
	}

	

	
						
    private X509Certificate cert = null;	
 
	/**
	 * Private method that returns the certificate used when signing
	 * @throws CryptoTokenOfflineException 
	 */
	protected Certificate getSigningCertificate() throws CryptoTokenOfflineException {
		if(cert==null){
			cert = (X509Certificate) getCryptoToken().getCertificate(ICryptoToken.PURPOSE_SIGN);
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
	protected Collection<Certificate> getSigningCertificateChain() throws CryptoTokenOfflineException {
		if(certChain==null){
			certChain =  getCryptoToken().getCertificateChain(ICryptoToken.PURPOSE_SIGN);
			if(certChain==null){
				log.debug("Signtoken did not contain a certificate chain, looking in config.");
				certChain=(new ProcessableConfig(config)).getSignerCertificateChain();
				if (certChain == null) {
					log.error("Neither Signtoken or ProcessableConfig contains a certificate chain!");					
				}
			}
		}		
		return certChain;
	}

	/**
	 * Method sending the request info to the signtoken
	 * @return the request or null if method isn't supported by signertoken.
	 */
	public ISignerCertReqData genCertificateRequest(ISignerCertReqInfo info) throws CryptoTokenOfflineException {
		return getCryptoToken().genCertificateRequest(info);
		 
	}
	
	/**
	 * Method sending the removal request to the signtoken
	 */
	public boolean destroyKey(int purpose) {
		return getCryptoToken().destroyKey(purpose);
	}
	
	
}
