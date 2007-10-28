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

package org.signserver.mailsigner;

import java.security.cert.Certificate;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ISignerCertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.MailSignerConfig;
import org.signserver.common.MailSignerStatus;
import org.signserver.common.SignServerUtil;
import org.signserver.common.SignTokenAuthenticationFailureException;
import org.signserver.common.SignTokenInitializationFailureException;
import org.signserver.common.SignTokenOfflineException;
import org.signserver.common.SignerConfig;
import org.signserver.common.SignerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.mailsigner.core.NonEJBGlobalConfigurationSession;
import org.signserver.server.signtokens.ISignToken;

/**
 * Base class for IMailSigners containing a lot of useful methods
 * for the IMailSigner plug-in.
 * 
 * If extending this class is the only the  method that requires implementation the 
 * 'service' method. 
 * 
 * 
 * @author Philip Vendil 23 sep 2007
 *
 * @version $Id: BaseMailSigner.java,v 1.1 2007-10-28 12:26:13 herrvendil Exp $
 */
public abstract class BaseMailSigner  implements IMailSigner {
	
	static{
		SignServerUtil.installBCProvider();
	}
	
	/**
	 * Property indicating that the signserver shouldn't be used.
	 * Set propery to TRUE to disable the signer.
	 */
	public static final String DISABLED          = "DISABLED";
	
    /** Log4j instance for actual implementation class */
    public transient Logger log = Logger.getLogger(this.getClass());
    
    protected ISignToken signToken = null;


    protected int workerId =0;
    
    protected WorkerConfig config = null; 
    
    protected BaseMailSigner(){

    }

    /**
     * Initialization method that should be called directly after creation
     */
    public void init(int workerId, WorkerConfig config){
      this.workerId = workerId;
      this.config = config;
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
	 * @see org.signserver.server.signers.ISigner#getStatus()
	 */
	public WorkerStatus getStatus() {
		MailSignerStatus retval = null;

        try {
        	
            int signTokenStatus = SignerStatus.STATUS_ACTIVE;
        	if(getSignToken() != null){
        		signTokenStatus = getSignToken().getSignTokenStatus();
        	}
			  retval = new MailSignerStatus(signTokenStatus, new MailSignerConfig( config), getSigningCertificate());
		} catch (SignTokenOfflineException e) {
			retval = new MailSignerStatus(getSignToken().getSignTokenStatus(), new MailSignerConfig( config), null);
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
					Class<?> implClass = Class.forName(classpath);
					Object obj = implClass.newInstance();
					signToken = (ISignToken) obj;
					signToken.init(config.getProperties());								 
				} 
			}catch(SignTokenInitializationFailureException e){
				log.error("Error instanciating SignerToken",e);
			}catch(ClassNotFoundException e){
				log.error("Error instanciating SignerToken",e);
			}catch(IllegalAccessException iae){
				log.error("Error instanciating SignerToken",iae);
			}catch(InstantiationException ie){
				log.error("Error instanciating SignerToken",ie);
			}
		}
		
		return signToken;
	}

					
    private Certificate cert = null;	
 
	/**
	 * Private method that returns the certificate used when signing
	 * @throws SignTokenOfflineException 
	 */
	protected Certificate getSigningCertificate() throws SignTokenOfflineException {
		if(cert==null){
			if(getSignToken() != null){
			  cert = (Certificate) getSignToken().getCertificate(ISignToken.PURPOSE_SIGN);
			}
			if(cert==null){
			  cert=( new SignerConfig( config)).getSignerCertificate();
			}
		}		
		return cert;
	}
	
	
	private Collection<Certificate> certChain = null;
	/**
	 * Private method that returns the certificate used when signing
	 * @throws SignTokenOfflineException 
	 */

	protected Collection<Certificate> getSigningCertificateChain() throws SignTokenOfflineException {
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
	
	/**
	 * Method sending the removal request to the signtoken
	 */
	public boolean destroyKey(int purpose) {
		return getSignToken().destroyKey(purpose);
	}
	
	/**
	 * Returns the non-EJB variant of the global configuration session.
	 * 
	 * Is very similar capabilities as the EJB bean.
	 * @return the instance of NonEJBGlobalConfigurationSession 
	 */
	protected NonEJBGlobalConfigurationSession getGlobalConfigurationSession(){
		return NonEJBGlobalConfigurationSession.getInstance();
	}
	
	
}
