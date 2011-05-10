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
import java.util.HashSet;
import java.util.Set;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.apache.mailet.Mail;
import org.apache.mailet.MailetContext;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.MailSignerConfig;
import org.signserver.common.MailSignerStatus;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.SignServerUtil;
import org.signserver.common.SignerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.mailsigner.core.NonEJBGlobalConfigurationSession;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.ICryptoToken;

/**
 * Base class for IMailProcessor containing a lot of useful methods
 * for the IMailProcessor plug-in.
 * 
 * If extending this class is the only the  method that requires implementation the 
 * 'service' method. 
 * 
 * 
 * @author Philip Vendil 23 sep 2007
 *
 * @version $Id$
 */
public abstract class BaseMailProcessor  implements IMailProcessor {
	
	static{
		SignServerUtil.installBCProvider();
	}
	
	/**
	 * Property indicating that the mail processor shouldn't be used.
	 * Set property to TRUE to disable the signer.
	 */
	public static final String DISABLED          = "DISABLED";
	
	/**
	 * A ',' separated list indicating that this mailprocessor
	 * should be called only if one of the username was used through
	 * STMP-AUTH
	 */
	public static final String VALIDUSERS          = "VALIDUSERS";
	
    /** Log4j instance for actual implementation class */
    public transient Logger log = Logger.getLogger(this.getClass());
    
    protected ICryptoToken cryptoToken = null;


    protected int workerId =0;
    
    protected WorkerConfig config = null;

    protected MailSignerContext mailSignerContext = null;
    
	protected MailetContext mailetContext; 
	
	protected HashSet<String> validUsers = null;
	
	protected EntityManager workerEntityManager;
    
    protected BaseMailProcessor(){

    }

    /**
     * Initialization method that should be called directly after creation
     */
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEntityManager){
      this.workerId = workerId;
      this.config = config;
      this.mailSignerContext = (MailSignerContext) workerContext;
      this.mailetContext = mailSignerContext.getMailetContext();
      this.workerEntityManager = workerEntityManager;
      
      if(config.getProperty(VALIDUSERS) != null){
    	  String[] validUserStrings = config.getProperty(VALIDUSERS).split(",");
    	  validUsers = new HashSet<String>();
    	  for(String validUser : validUserStrings){
    		  validUsers.add(validUser.trim());
    	  }
      }
    }
    
    /**
     * Simple matcher that returns all incomming recipients by default.
     * 
     * @see org.signserver.mailsigner.IMailProcessor#match(Mail)
     */
    public Collection<?> match(Mail mail) throws javax.mail.MessagingException{
    	return mail.getRecipients();
    }
	    
	public void activateCryptoToken(String authenticationCode)
			throws CryptoTokenAuthenticationFailureException,
			CryptoTokenOfflineException {		
			    
		getCryptoToken().activate(authenticationCode);
	    
	}

	public boolean deactivateCryptoToken() throws CryptoTokenOfflineException {
		return getCryptoToken().deactivate();
	}
	

	
	/**
	 * @see org.signserver.server.signers.IProcessable#getStatus()
	 */
	public WorkerStatus getStatus() {
		MailSignerStatus retval = null;

        try {
        	
            int signTokenStatus = SignerStatus.STATUS_ACTIVE;
        	if(getCryptoToken() != null){
        		signTokenStatus = getCryptoToken().getCryptoTokenStatus();
        	}
			  retval = new MailSignerStatus(workerId,signTokenStatus, new MailSignerConfig( config), getSigningCertificate());
		} catch (CryptoTokenOfflineException e) {
			retval = new MailSignerStatus(workerId,getCryptoToken().getCryptoTokenStatus(), new MailSignerConfig( config), null);
		}
		
		return retval;
	}
	
	protected ICryptoToken getCryptoToken() {
		if(cryptoToken == null){
			GlobalConfiguration gc = getGlobalConfigurationSession().getGlobalConfiguration();
			try{				
				String classpath =gc.getCryptoTokenProperty(
						workerId,GlobalConfiguration.CRYPTOTOKENPROPERTY_CLASSPATH);
				if(classpath != null){		
					Class<?> implClass = Class.forName(classpath);
					Object obj = implClass.newInstance();
					cryptoToken = (ICryptoToken) obj;
					cryptoToken.init(workerId, config.getProperties());								 
				} 
			}catch(CryptoTokenInitializationFailureException e){
				log.error("Error instanciating SignerToken",e);
			}catch(ClassNotFoundException e){
				log.error("Error instanciating SignerToken",e);
			}catch(IllegalAccessException iae){
				log.error("Error instanciating SignerToken",iae);
			}catch(InstantiationException ie){
				log.error("Error instanciating SignerToken",ie);
			}
		}
		
		return cryptoToken;
	}

					
    private Certificate cert = null;	
 
	/**
	 * Private method that returns the certificate used when signing
	 * @throws CryptoTokenOfflineException 
	 */
	protected Certificate getSigningCertificate() throws CryptoTokenOfflineException {
		if(cert==null){
			if(getCryptoToken() != null){
			  cert = (Certificate) getCryptoToken().getCertificate(ICryptoToken.PURPOSE_SIGN);
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

	protected Collection<Certificate> getSigningCertificateChain() throws CryptoTokenOfflineException {
		if(certChain==null){
			certChain =  getCryptoToken().getCertificateChain(ICryptoToken.PURPOSE_SIGN);
			if(certChain==null){
				certChain=(new ProcessableConfig(config)).getSignerCertificateChain();
			}
		}		
		return certChain;
	}

	/**
	 * Method sending the request info to the signtoken
	 * @return the request or null if method isn't supported by signertoken.
	 */
	public ICertReqData genCertificateRequest(ISignerCertReqInfo info) throws CryptoTokenOfflineException {
		return getCryptoToken().genCertificateRequest(info, true);
		 
	}
	
	/**
	 * Method sending the removal request to the signtoken
	 */
	public boolean destroyKey(int purpose) {
		return getCryptoToken().destroyKey(purpose);
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
	
	 /**
	  * Method that should return all STMP-AUTH user names should apply
	  * for this mail processor to be called.
	  * 
	  * @return all valid names or null if this processor always should 
	  * be called.
	  */
	 public Set<String> getValidUsers(){
		 return validUsers;
	 }
}
