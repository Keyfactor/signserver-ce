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

package org.signserver.cli;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.log4j.Logger;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.MailSignerConfig;
import org.signserver.common.MailSignerUser;
import org.signserver.common.ResyncException;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession.IRemote;
import org.signserver.mailsigner.cli.IMailSignerRMI;

/**
 * A class that maintains the type of sign server build (SignServer of MailSigner), 
 * and directs the CLI calls to the appropriate RMI implementation
 * 
 * All calls to the server should go through this class.
 * 
 * @author Philip Vendil 6 okt 2007
 *
 * @version $Id: CommonAdminInterface.java,v 1.5 2007-12-29 10:43:53 herrvendil Exp $
 */

public class CommonAdminInterface  {
	
    /** Log4j instance  */
    private static Logger log = Logger.getLogger(CommonAdminInterface.class);

    private String hostname = null;
    
	// Not final so it can be used in test scripts
	static  String BUILDMODE = "@BUILDMODE@";
	
	public CommonAdminInterface(String hostname){
		this.hostname = hostname;
	}
	
	
	/**
	 * @return true if the build is a SignServer
	 */
	public static boolean isSignServerMode(){
		if(signServerMode == null){
			signServerMode = BUILDMODE.trim().equalsIgnoreCase("SIGNSERVER");
		}
		
		return signServerMode.booleanValue();
	}
	private static Boolean signServerMode = null;

	/**
	 * @return true if the build is a MailSigner
	 */
    public static boolean isMailSignerMode(){
    	if(mailSignerMode == null){
    		mailSignerMode =  BUILDMODE.trim().equalsIgnoreCase("MAILSIGNER");
    	}
    	
    	return mailSignerMode.booleanValue();
	}
    private static Boolean mailSignerMode = null;
    
	/**
	 * @see org.signserver.ejb.WorkerSessionBean#activateSigner(int, String)
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#activateSigner(int, String)
	 */
	public void activateSigner(int signerId, String authenticationCode)
			throws CryptoTokenAuthenticationFailureException,
			CryptoTokenOfflineException, InvalidWorkerIdException,
			RemoteException {
		if(isMailSignerMode()){
			getIMailSignerRMI().activateSigner(signerId, authenticationCode);
		}
		if(isSignServerMode()){
			getSignSession().activateSigner(signerId, authenticationCode);
		}
		
	}

	/**
	 * @see org.signserver.ejb.WorkerSessionBean#deactivateSigner(int)
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#deactivateSigner(int)
	 */
	public boolean deactivateSigner(int signerId)
			throws CryptoTokenOfflineException, InvalidWorkerIdException,
			RemoteException {
		boolean retval = false;
		if(isMailSignerMode()){
			retval = getIMailSignerRMI().deactivateSigner(signerId);
		}
		if(isSignServerMode()){
			retval = getSignSession().deactivateSigner(signerId);			
		}
		
		return retval;
	}

	/**
	 * @see org.signserver.ejb.WorkerSessionBean#destroyKey(int, int)
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#destroyKey(int, int)
	 */
	public boolean destroyKey(int signerId, int purpose)
			throws InvalidWorkerIdException, RemoteException {
		boolean retval = false;
		if(isMailSignerMode()){
			retval = getIMailSignerRMI().destroyKey(signerId, purpose);
		}
		if(isSignServerMode()){
			retval = getSignSession().destroyKey(signerId, purpose);		
		}
		
		return retval;
	}

	/**
	 * @see org.signserver.ejb.WorkerSessionBean#genCertificateRequest(int, ISignerCertReqInfo)
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#genCertificateRequest(int, ISignerCertReqInfo)
	 */
	public ICertReqData genCertificateRequest(int signerId,
			ISignerCertReqInfo certReqInfo) throws CryptoTokenOfflineException,
			InvalidWorkerIdException, RemoteException {
		ICertReqData retval = null;
		if(isMailSignerMode()){
			retval = getIMailSignerRMI().genCertificateRequest(signerId, certReqInfo);
		}
		if(isSignServerMode()){
			retval = getSignSession().getCertificateRequest(signerId, certReqInfo);		
		}
		return retval;
	}

	/**
	 * @see org.signserver.ejb.WorkerSessionBean#getCurrentSignerConfig(int)
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#getCurrentSignerConfig(int)
	 */	
	public WorkerConfig getCurrentSignerConfig(int signerId)
			throws RemoteException {
		WorkerConfig retval = null;
		if(isMailSignerMode()){
			retval = getIMailSignerRMI().getCurrentSignerConfig(signerId);
		}
		if(isSignServerMode()){
			retval = getSignSession().getCurrentSignerConfig(signerId);		
		}
		return retval;
	}

	/**
	 * @see org.signserver.ejb.GlobalConfigurationSessionBean#getGlobalConfiguration()
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#getGlobalConfiguration()
	 */	
	public GlobalConfiguration getGlobalConfiguration() throws RemoteException {
		GlobalConfiguration retval = null;
		if(isMailSignerMode()){
			retval = getIMailSignerRMI().getGlobalConfiguration();
		}
		if(isSignServerMode()){
			retval = getGlobalConfigurationSession().getGlobalConfiguration();			
		}
		return retval;
	}

	/**
	 * @see org.signserver.ejb.WorkerSessionBean#getWorkerId(String)
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#getWorkerId(String)
	 */	
	public int getWorkerId(String signerName) throws RemoteException {
		int retval = 0;
		if(isMailSignerMode()){
			retval = getIMailSignerRMI().getWorkerId(signerName);
		}
		if(isSignServerMode()){
			retval = getSignSession().getWorkerId(signerName);
		}		
		
		return retval;
	}

	/**
	 * @see org.signserver.ejb.WorkerSessionBean#getStatus(int)
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#getStatus(int)
	 */	
	public WorkerStatus getStatus(int workerId)
			throws InvalidWorkerIdException, RemoteException {
		WorkerStatus retval = null;
		if(isMailSignerMode()){
			retval = getIMailSignerRMI().getStatus(workerId);
		}
		if(isSignServerMode()){
			retval = getSignSession().getStatus(workerId);
		}
		return retval;
	}

	/**
	 * @see org.signserver.ejb.WorkerSessionBean#reloadConfiguration(int)
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#reloadConfiguration(int)
	 */	
	public void reloadConfiguration(int workerId) throws RemoteException {
		if(isMailSignerMode()){
			getIMailSignerRMI().reloadConfiguration(workerId);
		}
		if(isSignServerMode()){
			getSignSession().reloadConfiguration(workerId);
		}
	}

	/**
	 * @see org.signserver.ejb.GlobalConfigurationSessionBean#removeProperty(String, String)
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#removeGlobalProperty(String, String)
	 */
	public boolean removeGlobalProperty(String scope, String key)
			throws RemoteException {
		boolean retval = false;
		if(isMailSignerMode()){
			retval = getIMailSignerRMI().removeGlobalProperty(scope, key);
		}
		if(isSignServerMode()){
			retval = getGlobalConfigurationSession().removeProperty(scope, key);
		}
		return retval;
	}

	/**
	 * @see org.signserver.ejb.WorkerSessionBean#removeWorkerProperty(int, String)
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#removeWorkerProperty(int, String)
	 */	
	public boolean removeWorkerProperty(int workerId, String key)
			throws RemoteException {
		boolean retval = false;
		if(isMailSignerMode()){
			retval = getIMailSignerRMI().removeWorkerProperty(workerId, key);
		}
		if(isSignServerMode()){
			retval = getSignSession().removeWorkerProperty(workerId, key);
		}
		return retval;
	}

	/**
	 * @see org.signserver.ejb.GlobalConfigurationSessionBean#setProperty(String, String, String)
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#setGlobalProperty(String, String, String)
	 */
	public void setGlobalProperty(String scope, String key, String value)
			throws RemoteException {
		if(isMailSignerMode()){
			getIMailSignerRMI().setGlobalProperty(scope,key,value);
		}
		if(isSignServerMode()){
			getGlobalConfigurationSession().setProperty(scope, key, value);	
		}		
	}
	
	public List<Integer> getWorkers(int workerType) throws RemoteException {
		if(isMailSignerMode()){
			if(workerType == GlobalConfiguration.WORKERTYPE_PROCESSABLE){
				workerType = GlobalConfiguration.WORKERTYPE_MAILSIGNERS;
			}
			return getIMailSignerRMI().getWorkers(workerType);
		}
		if(isSignServerMode()){
			return getGlobalConfigurationSession().getWorkers(workerType);
		}	
		return null;
	}

	/**
	 * @see org.signserver.ejb.WorkerSessionBean#setWorkerProperty(int, String, String)
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#setWorkerProperty(int, String, String)	 
	 */	
	public void setWorkerProperty(int workerId, String key, String value)
			throws RemoteException {
		if(isMailSignerMode()){
			getIMailSignerRMI().setWorkerProperty(workerId,key,value);
		}
		if(isSignServerMode()){
			getSignSession().setWorkerProperty(workerId, key, value);
		}
	}

	/**
	 * @see org.signserver.ejb.WorkerSessionBean#uploadSignerCertificate(int, X509Certificate)
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#uploadSignerCertificate(int, X509Certificate)	 
	 */		
	public void uploadSignerCertificate(int signerId, X509Certificate signerCert, String scope)
			throws RemoteException {
		if(isMailSignerMode()){
			getIMailSignerRMI().uploadSignerCertificate(signerId,signerCert);
		}
		if(isSignServerMode()){
			getSignSession().uploadSignerCertificate(signerId, signerCert, scope);
		}
		
	}

	/**
	 * @see org.signserver.ejb.WorkerSessionBean#uploadSignerCertificateChain(int, Collection)
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#uploadSignerCertificateChain(int, Collection)	 
	 */	
	public void uploadSignerCertificateChain(int signerId,
			Collection<Certificate> signerCerts, String scope) throws RemoteException 
			{
		if(isMailSignerMode()){
			getIMailSignerRMI().uploadSignerCertificateChain(signerId,signerCerts);
		}
		if(isSignServerMode()){
			getSignSession().uploadSignerCertificateChain(signerId, signerCerts, scope);
		}
	}
	
	/**
	 * @see org.signserver.ejb.WorkerSessionBean#genFreeWorkerId()
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#genFreeWorkerId()
	 */	
	public int genFreeWorkerId() throws RemoteException{
		int retval = 1;
		if(isMailSignerMode()){
			retval = getIMailSignerRMI().genFreeWorkerId();
		}
		if(isSignServerMode()){
			retval = getSignSession().genFreeWorkerId();
		}
		
		return retval;
	}
	
	public void resync() throws RemoteException, ResyncException {
		if(isSignServerMode()){
			getGlobalConfigurationSession().resync();
		}

	}
	
	/**
	 * Method only supported by SignServer Builds
	 * @throws RemoteException 
	 * 
	 * @see org.signserver.ejb.WorkerSessionBean#getAuthorizedClients(int)
	 */
	public Collection<AuthorizedClient> getAuthorizedClients(int signerId) throws RemoteException{
		if(isSignServerMode()){
		   return getSignSession().getAuthorizedClients(signerId);
		}
		
		return null;
	}
	
	/**
	 * Method adding an authorized client to a signer
	 * 
	 * @param signerId
	 * @param authClient
	 * @throws RemoteException 
	 * 
	 */
	public void addAuthorizedClient(int signerId, AuthorizedClient authClient) throws RemoteException{
		if(isSignServerMode()){
		  getSignSession().addAuthorizedClient(signerId, authClient);
		}
	}

	/**
	 * Removes an authorized client from a signer
	 * 
	 * @param signerId
	 * @param authClient
	 * @throws RemoteException 
	 * 
	 */
	public boolean removeAuthorizedClient(int signerId, AuthorizedClient authClient) throws RemoteException{
		if(isSignServerMode()){
		  return getSignSession().removeAuthorizedClient(signerId, authClient);
		}
		return false;
	}
	
	/**
	 * Method only supported by Mail Signer Builds
	 *  
	 * Method adding an authorized user to the mail signer
	 * 
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#addAuthorizedUser(String, String)
	 * 
	 */
	public void addAuthorizedUser(String username, String password) throws RemoteException{
		if(isMailSignerMode()){
		  getIMailSignerRMI().addAuthorizedUser(username, password);
		}
	}

	/**
	 * Method only supported by Mail Signer Builds
	 * Removes an authorized client from a signer
	 * 
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#removeAuthorizedUser(String)
	 * @throws RemoteException 
	 * 
	 */
	public boolean removeAuthorizedUser(String username) throws RemoteException{
		if(isMailSignerMode()){
			  return getIMailSignerRMI().removeAuthorizedUser(username);
		}
		return false;
	}
	
	/**
	 *  Method only supported by Mail Signer Builds
	 * @throws RemoteException 
	 * 
	 * @see {@link org.signserver.mailsigner.cli.IMailSignerRMI#getAuthorizedUsers()}
	 */
	public List<MailSignerUser> getAuthorizedUsers() throws RemoteException{
		if(isMailSignerMode()){
			return getIMailSignerRMI().getAuthorizedUsers();
		}
		
		return null;
	}
	
	public ArchiveDataVO findArchiveDataFromArchiveId(int signerid,
			String archiveid) throws RemoteException {
		if(isSignServerMode()){
			return getSignSession().findArchiveDataFromArchiveId(signerid, archiveid);
		}
		return null;
	}


	public List<ArchiveDataVO> findArchiveDatasFromRequestCertificate(int signerid,
			BigInteger sn, String issuerdn) throws RemoteException {
		if(isSignServerMode()){
			return getSignSession().findArchiveDatasFromRequestCertificate(signerid, sn, issuerdn);
		}
		return null;
	}


	public List<ArchiveDataVO> findArchiveDatasFromRequestIP(int signerid, String requestIP) throws RemoteException {
		if(isSignServerMode()){
			return getSignSession().findArchiveDatasFromRequestIP(signerid, requestIP);
		}
		return null;
	}
	

	
	private IMailSignerRMI getIMailSignerRMI() throws RemoteException{
		if(iMailSignerRMI == null){
			String lookupName = "//"+ hostname +":" + MailSignerConfig.getRMIRegistryPort() + "/" +
			MailSignerConfig.RMI_OBJECT_NAME;

			try {
				iMailSignerRMI = (IMailSignerRMI) Naming.lookup(lookupName);
			} catch (MalformedURLException e) {
				log.error("Error binding Mail Signer RMI Interface.",e);
			} catch (NotBoundException e) {
				log.error("Error binding Mail Signer RMI Interface.",e);
			}
		}
		
		return iMailSignerRMI;
	}
	
	private IMailSignerRMI iMailSignerRMI = null;
	
    /** Gets GlobalConfigurationSession Remote
     *@return SignServerSession
     */
    private IGlobalConfigurationSession.IRemote getGlobalConfigurationSession() throws RemoteException{
    	
        if(globalConfigurationSession == null){	
        	try{
        		Context context = getInitialContext();        		            
        		globalConfigurationSession = (IRemote) context.lookup(IGlobalConfigurationSession.IRemote.JNDI_NAME);
        	}catch (NamingException e) {
        		log.error("Error instanciating the GlobalConfigurationSession.",e);
        		throw new RemoteException(e.getMessage());
        	}
        } 
        
		return globalConfigurationSession;
     } 
    
	private IGlobalConfigurationSession.IRemote globalConfigurationSession;
	
    /** Gets SignServerSession Remote
     * @return SignServerSession
     * @throws RemoteException 
     */
    private IWorkerSession.IRemote getSignSession() throws RemoteException{
    	 
    	if(signsession == null){    		
			try {
				Context context = getInitialContext();
				signsession = (IWorkerSession.IRemote) context.lookup(IWorkerSession.IRemote.JNDI_NAME);
			} catch (NamingException e) {
				log.error("Error looking up signserver interface");
				throw new RemoteException(e.getMessage());
			}		    		
    	}
		return signsession;
     } // getSignSession
    /** The SignSession home bean */
	private IWorkerSession.IRemote signsession;
	
    /**
     * Gets InitialContext
     *
     * @return InitialContext
     */
    protected InitialContext getInitialContext() throws NamingException {
        log.debug(">getInitialContext()");

        try {
        	Hashtable<String, String> props = new Hashtable<String, String>();
        	props.put(
        		Context.INITIAL_CONTEXT_FACTORY,
        		"org.jnp.interfaces.NamingContextFactory");
        	props.put(
        		Context.URL_PKG_PREFIXES,
        		"org.jboss.naming:org.jnp.interfaces");
        	props.put(Context.PROVIDER_URL, "jnp://" + hostname +":1099");
        	InitialContext cacheCtx = new InitialContext(props);
            log.debug("<getInitialContext()");
            return cacheCtx;
        } catch (NamingException e) {
            log.error("Can't get InitialContext", e);
            throw e;
        }
    } // getInitialContext









}
