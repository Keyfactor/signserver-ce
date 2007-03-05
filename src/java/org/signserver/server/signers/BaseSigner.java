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
import org.signserver.common.SignTokenAuthenticationFailureException;
import org.signserver.common.SignTokenOfflineException;
import org.signserver.common.SignerConfig;
import org.signserver.common.SignerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.server.BaseWorker;
import org.signserver.server.signtokens.ISignToken;


public abstract class BaseSigner extends BaseWorker implements ISigner {
	

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
    public transient Logger log = Logger.getLogger(this.getClass());
    
    protected ISignToken signToken = null;

    
    protected BaseSigner(){

    }

	    
	public void activateSigner(String authenticationCode)
			throws SignTokenAuthenticationFailureException,
			SignTokenOfflineException {		
			    
		getSignToken().activate(authenticationCode);
	    
	}

	public boolean deactivateSigner() throws SignTokenOfflineException {
		return getSignToken().deactivate();
	}
	
	/**
	 * Returns the authentication type configured for this signer.
	 * Returns one of the ISinger.AUTHTYPE_ constants.
	 * 
	 * default is clientcertificate authention.
	 */
	public int getAuthenticationType(){
		int retval = ISigner.AUTHTYPE_CLIENTCERT;
		
		String authtype = config.getProperties().getProperty(WorkerConfig.PROPERTY_AUTHTYPE);
		if(authtype != null){
			if(authtype.equalsIgnoreCase(WorkerConfig.AUTHTYPE_NOAUTH)){
				retval = ISigner.AUTHTYPE_NOAUTH;
			}
		}
		
		return retval;
	}
	
	/**
	 * @see org.signserver.server.signers.ISigner#getStatus()
	 */
	public WorkerStatus getStatus() {
		SignerStatus retval = null;
		
        try {
			retval = new SignerStatus(getSignToken().getSignTokenStatus(), new SignerConfig( config), getSigningCertificate());
		} catch (SignTokenOfflineException e) {
			retval = new SignerStatus(getSignToken().getSignTokenStatus(), new SignerConfig( config), null);
		}
		
		
		return retval;
	}
	
	protected ISignToken getSignToken() {
		if(signToken == null){
			GlobalConfiguration gc = getGlobalConfigurationSession().getGlobalConfiguration();
			try{				
				String classpath =gc.getSignTokenProperty(
						workerId,GlobalConfiguration.SIGNTOKENPROPERTY_CLASSPATH);
				if(classpath != null){		
					Class implClass = Class.forName(classpath);
					Object obj = implClass.newInstance();
					signToken = (ISignToken) obj;
					signToken.init(config.getProperties());								 
				} 
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
		
		return signToken;
	}

	

	
						
    private X509Certificate cert = null;	
 
	/**
	 * Private method that returns the certificate used when signing
	 * @throws SignTokenOfflineException 
	 */
	protected Certificate getSigningCertificate() throws SignTokenOfflineException {
		if(cert==null){
			cert = (X509Certificate) getSignToken().getCertificate(ISignToken.PURPOSE_SIGN);
			if(cert==null){
			  cert=( new SignerConfig( config)).getSignerCertificate();
			}
		}		
		return cert;
	}
	
	
	private Collection certChain = null;
	/**
	 * Private method that returns the certificate used when signing
	 * @throws SignTokenOfflineException 
	 */
	protected Collection getSigningCertificateChain() throws SignTokenOfflineException {
		if(certChain==null){
			certChain =  getSignToken().getCertificateChain(ISignToken.PURPOSE_SIGN);
			if(certChain==null){
				certChain=(new SignerConfig(config)).getSignerCertificateChain();
			}
		}		
		return certChain;
	}

	/**
	 * Method sending the request info to the signtoken
	 * @return the request or null if method isn't supported by signertoken.
	 */
	public ISignerCertReqData genCertificateRequest(ISignerCertReqInfo info) throws SignTokenOfflineException {
		return getSignToken().genCertificateRequest(info);
		 
	}
	
	
}
