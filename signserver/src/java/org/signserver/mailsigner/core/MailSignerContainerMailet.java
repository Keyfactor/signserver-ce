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
package org.signserver.mailsigner.core;

import java.rmi.AccessException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import javax.mail.MessagingException;

import org.apache.log4j.Logger;
import org.apache.mailet.GenericMailet;
import org.apache.mailet.Mail;
import org.apache.mailet.MailetConfig;
import org.apache.mailet.Matcher;
import org.apache.mailet.MatcherConfig;
import org.ejbca.util.CertTools;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.MailSignerConfig;
import org.signserver.common.MailSignerUser;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.mailsigner.BaseMailProcessor;
import org.signserver.mailsigner.IMailProcessor;
import org.signserver.mailsigner.MailSignerContext;
import org.signserver.mailsigner.MailSignerUtil;
import org.signserver.mailsigner.cli.IMailSignerRMI;
import org.signserver.server.IWorker;
import org.signserver.server.PropertyFileStore;
import org.signserver.server.WorkerFactory;
import org.signserver.server.clusterclassloader.xmlpersistence.XMLCCLResourceManager;
import org.signserver.server.statistics.Event;
import org.signserver.server.statistics.StatisticsManager;

/**
 * MailSignerContainerMailet is the base James Mailet that reads the 
 * mail signer configuration file and sets up the IMailSigners in the
 * system.
 * 
 * It also handles the calling of the mails to the configured
 * mail signers.
 * 
 * 
 * @author Philip Vendil
 * $Id$
 */
public class MailSignerContainerMailet extends GenericMailet implements IMailSignerRMI, Matcher{

	
	
	private static transient Logger log = Logger.getLogger(MailSignerContainerMailet.class.getName());	    
	
    private MailSignerUserRepository userRepository = new MailSignerUserRepository();


    
	/* Not used for anything. */
	private MatcherConfig matcherConfig;
    
    /**
     * Creates all the configured IMailProcessor plugins, initializes
     * them and send them their configuration.
     * 
     * Also sets up the RMI service for the CLI.
     */
	@Override
	public void init(MailetConfig mailetConfig) throws MessagingException {
		super.init(mailetConfig);
		MailSignerContext.getInstance().init(mailetConfig.getMailetContext());
		try{
			     			
			Registry registry = LocateRegistry.createRegistry(MailSignerConfig.getRMIRegistryPort());
			Remote stup = UnicastRemoteObject.exportObject(this,MailSignerConfig.getRMIServerPort());
			registry.rebind(MailSignerConfig.RMI_OBJECT_NAME, stup);
			log.info("MailSigner RMI interface bound successfully with registry on port: " + MailSignerConfig.getRMIRegistryPort() + " and server on port: " + MailSignerConfig.getRMIServerPort());
						
			QuartzServiceTimer.getInstance().start();
			
			List<Integer> mailIds = NonEJBGlobalConfigurationSession.getInstance().getWorkers(GlobalConfiguration.WORKERTYPE_MAILSIGNERS);
			for (Integer id : mailIds) {
				try {
					getMailSigner(id);
				} catch (InvalidWorkerIdException e) {
					// Should never happen
					log.error(e);
				}
			}
		}catch(AccessException e){
			log.error("Failed binding MailSigner RMI interface.", e);
		}catch (RemoteException e) {
			log.error("Failed binding MailSigner RMI interface.", e);
		}
		
	}
	
	/**
	 * Stop all services when shutting down.
	 */
	@Override
	protected void finalize() throws Throwable {
		QuartzServiceTimer.getInstance().stop();
		super.finalize();
	}

	/**
	 * Method that sends the mail to all the configured mail signers.
	 * In id order (ascending) order.
	 */
	public void service(Mail mail) throws MessagingException{
				
		List<Integer> mailIds = NonEJBGlobalConfigurationSession.getInstance().getWorkers(GlobalConfiguration.WORKERTYPE_MAILSIGNERS);
		for (Integer id : mailIds) {
			try {
				IMailProcessor mailProcessor = getMailSigner(id);
				if(isValidUser(mail, mailProcessor)){
					WorkerConfig awc = mailProcessor.getStatus().getActiveSignerConfig();
					Event event = StatisticsManager.startEvent(id, awc, null);
					RequestContext requestContext =  new RequestContext(); 
					requestContext.put(RequestContext.STATISTICS_EVENT, event);

					if(!awc.getProperty(BaseMailProcessor.DISABLED,"FALSE").equalsIgnoreCase("TRUE")){
						getMailSigner(id).service(mail, requestContext);
					}

					StatisticsManager.endEvent(id, awc, null, event);
				}
				
			} catch (InvalidWorkerIdException e) {
				// Should never happen
				log.error(e);
			} catch (CryptoTokenOfflineException e){
				log.error("CryptoTokenOfflineException : " + e.getMessage(),e);
				throw new MessagingException(e.getMessage(),e);
			} catch (SignServerException e) {
				log.error(e);
			}
		}
		MailSignerUtil.mailTest(mail);
	}

	/**
	 * Help method that checks if a smtp auth user is valid for
	 * this mail processor.
	 * 
	 * @param mail the mail to check if the mail processor is valid.
	 * @param mailProcessor 
	 * @return true if the user is valid for this mailProcessor
	 */
	private boolean isValidUser(Mail mail, IMailProcessor mailProcessor) {
		String authUser = (String) mail.getAttribute("org.apache.james.SMTPAuthUser");
		
		Set<String> validUsers = mailProcessor.getValidUsers();
		if(validUsers == null){
			return true;
		}
		
		if(authUser == null){
			return false;
		}
						
		return validUsers.contains(authUser);
	}

		


	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#activateSigner(int, String)
	 */
	public void activateCryptoToken(int signerId, String authenticationCode)
			throws CryptoTokenAuthenticationFailureException,
			CryptoTokenOfflineException, InvalidWorkerIdException,
			RemoteException {
		getMailSigner(signerId).activateCryptoToken(authenticationCode);		
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#deactivateSigner(int)
	 */
	public boolean deactivateCryptoToken(int signerId)
			throws CryptoTokenOfflineException, InvalidWorkerIdException,
			RemoteException {
		return getMailSigner(signerId).deactivateCryptoToken();
		
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#destroyKey(int, int)
	 */
	public boolean destroyKey(int signerId, int purpose)
			throws InvalidWorkerIdException, RemoteException {		
		return getMailSigner(signerId).destroyKey(purpose);
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#getCertificateRequest(int, ISignerCertReqInfo)
	 */
	public ICertReqData genCertificateRequest(int signerId,
			ISignerCertReqInfo certReqInfo) throws CryptoTokenOfflineException,
			InvalidWorkerIdException, RemoteException {
		
		return getMailSigner(signerId).genCertificateRequest(certReqInfo);
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#getWorkerId(String)
	 */
	public int getWorkerId(String signerName) throws RemoteException {
		int retval = 0;
		
		List<Integer> signerIds = NonEJBGlobalConfigurationSession.getInstance().getWorkers(GlobalConfiguration.WORKERTYPE_MAILSIGNERS);
		for (Integer id : signerIds) {			
			try {
				String name = getMailSigner(id).getStatus().getActiveSignerConfig().getProperties().getProperty(MailSignerConfig.NAME);
				if(name != null && name.equalsIgnoreCase(signerName)){
					retval = id;
				}
			} catch (InvalidWorkerIdException e) {
				// Should never happen
				log.error(e);
			}

		}
		
		return retval;
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#getStatus(int)
	 */
	public WorkerStatus getStatus(int workerId)
			throws InvalidWorkerIdException, RemoteException {
		
		return WorkerFactory.getInstance().getWorker(workerId, MailSignerWorkerConfigService.getInstance(), NonEJBGlobalConfigurationSession.getInstance(), MailSignerContext.getInstance()).getStatus();
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#reloadConfiguration(int, Properties)
	 */
	public void reloadConfiguration(int workerId)
			throws RemoteException {
		if(workerId == 0){
		  NonEJBGlobalConfigurationSession.getInstance().reload();
		  List<Integer> mailIds = NonEJBGlobalConfigurationSession.getInstance().getWorkers(GlobalConfiguration.WORKERTYPE_MAILSIGNERS);
			for (Integer id : mailIds) {
				try {
					getMailSigner(id);
				} catch (InvalidWorkerIdException e) {
					// Should never happen
					log.error(e);
				}
			}
		}else{
		  WorkerFactory.getInstance().reloadWorker(workerId, MailSignerWorkerConfigService.getInstance(), NonEJBGlobalConfigurationSession.getInstance(), MailSignerContext.getInstance());
			try {
				List<Integer> mailIds = NonEJBGlobalConfigurationSession.getInstance().getWorkers(GlobalConfiguration.WORKERTYPE_MAILSIGNERS);
				if(mailIds.contains(workerId)){
				  getMailSigner(workerId);
				}
			} catch (InvalidWorkerIdException e) {
				// Should never happen
				log.error(e);
			}
		}
		
		QuartzServiceTimer.getInstance().reload(workerId);
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#uploadSignerCertificate(int, X509Certificate)
	 */
	public void uploadSignerCertificate(int signerId, X509Certificate signerCert)
			throws RemoteException {
		
		PropertyFileStore pfs = PropertyFileStore.getInstance();
		
		ArrayList<X509Certificate> list = new ArrayList<X509Certificate>();
		list.add(signerCert);
		try {
			String stringcert = new String(CertTools.getPEMFromCerts(list));
			pfs.setWorkerProperty(signerId, MailSignerConfig.SIGNERCERT, stringcert);				
		} catch (CertificateException e) {
			log.error(e);
		}
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#uploadSignerCertificateChain(int, Collection)
	 */
	public void uploadSignerCertificateChain(int signerId,
			Collection<Certificate> signerCerts) throws RemoteException {
		PropertyFileStore pfs = PropertyFileStore.getInstance();

		try {
			String stringcert = new String(CertTools.getPEMFromCerts(signerCerts));
			pfs.setWorkerProperty(signerId, MailSignerConfig.SIGNERCERTCHAIN, stringcert);				
		} catch (CertificateException e) {
			log.error(e);
		}
		
	}
	
	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#getCurrentWorkerConfig(int)
	 */
	public WorkerConfig getCurrentWorkerConfig(int signerId) {		
		return PropertyFileStore.getInstance().getWorkerProperties(signerId);
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#removeWorkerProperty(int, String)
	 */
	public boolean removeWorkerProperty(int workerId, String key) {
		boolean exists = true;
		PropertyFileStore pfs = PropertyFileStore.getInstance();
		
		exists = pfs.getWorkerProperties(workerId).getProperties().containsKey(key);
		if(exists){
		  pfs.removeWorkerProperty(workerId, key);
		}
		return exists;
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#setWorkerProperty(int, String, String)
	 */
	public void setWorkerProperty(int workerId, String key, String value) {
		 PropertyFileStore.getInstance().setWorkerProperty(workerId, key, value);		
	}
	
	  /**
	   * @see org.signserver.mailsigner.cli.IMailSignerRMI#getGlobalConfiguration()
	   */
		public GlobalConfiguration getGlobalConfiguration() {
			return NonEJBGlobalConfigurationSession.getInstance().getGlobalConfiguration();
		}

		  /**
		   * @see org.signserver.mailsigner.cli.IMailSignerRMI#removeGlobalProperty(String, String)
		   */
		public boolean removeGlobalProperty(String scope, String key) {
			return NonEJBGlobalConfigurationSession.getInstance().removeProperty(scope, key);			 
		}

		  /**
		   * @see org.signserver.mailsigner.cli.IMailSignerRMI#setGlobalProperty(String, String, String)
		   */
		public void setGlobalProperty(String scope, String key, String value) {
			NonEJBGlobalConfigurationSession.getInstance().setProperty(scope, key, value);			
		}
		
		public List<Integer> getWorkers(int workerType){
			return NonEJBGlobalConfigurationSession.getInstance().getWorkers(workerType);
		}
	
		/**
		 * Methods that generates a free workerid that can be used for new signers
		 */
		public int genFreeWorkerId(){
			Collection<?> ids =  NonEJBGlobalConfigurationSession.getInstance().getWorkers(GlobalConfiguration.WORKERTYPE_ALL);
			int max = 0;
			Iterator<?> iter = ids.iterator();
			while(iter.hasNext()){
				Integer id = (Integer) iter.next();
				if(id.intValue() > max){
					max = id.intValue();
				}
			}
			
			return max+1;
		}
		
		
	/**
	 * Method that finds and initializes a MailSigner
	 */
	private IMailProcessor getMailSigner(int workerId) throws InvalidWorkerIdException{
		
		IWorker worker = WorkerFactory.getInstance().getWorker(workerId, MailSignerWorkerConfigService.getInstance(), NonEJBGlobalConfigurationSession.getInstance(),MailSignerContext.getInstance());
		if(!(worker instanceof IMailProcessor)){
			log.error("Error: mail signer with id '" + workerId + " doesn't implement the required IMailProcessor interface");
		}
		
		if(worker == null){
			throw new InvalidWorkerIdException("Error, couldn't find worker id in global configuration.");
		}
		return (IMailProcessor) worker;
	}



	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#addAuthorizedUser(String, String)
	 */
	public void addAuthorizedUser(String username, String password) {
		userRepository.addUser(username, password);		
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#getAuthorizedUsers()
	 */
	public List<MailSignerUser> getAuthorizedUsers() {		
		return userRepository.getUsersSorted();
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#removeAuthorizedUser(String)
	 */
	public boolean removeAuthorizedUser(String username) {
		if(userRepository.containsCaseInsensitive(username)){
			userRepository.removeUser(username);
			return true;
		}
		return false;
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#addResource(String, String, int, String, String, String, String, String, byte[])
	 */
	public void addResource(String moduleName, String part, int version,
			String jarName, String resourceName, String implInterfaces,
			String description, String comment, byte[] resourceData) {
		XMLCCLResourceManager.addResource(moduleName, part, version, jarName, resourceName, implInterfaces, description, comment, resourceData);
		
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#getJarNames(String, String, int)
	 */
	public String[] getJarNames(String moduleName, String part, int version) {
		return XMLCCLResourceManager.getJarNames(moduleName, part, version);
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#listAllModuleParts(String, int)
	 */
	public String[] listAllModuleParts(String moduleName, int version) {
		return XMLCCLResourceManager.listAllModuleParts(moduleName, version);
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#listAllModuleVersions(String)
	 */
	public Integer[] listAllModuleVersions(String moduleName) {		
		return XMLCCLResourceManager.listAllModuleVersions(moduleName);
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#listAllModules()
	 */
	public String[] listAllModules() {
		return XMLCCLResourceManager.listAllModules();
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#removeModulePart(String, String, int)
	 */
	public void removeModulePart(String moduleName, String part, int version) {
        XMLCCLResourceManager.removeModulePart(moduleName, part, version);		
	}


	public MatcherConfig getMatcherConfig() {
		return matcherConfig;
	}


	public String getMatcherInfo() {
		return "MailSigner generinc Matcher";
	}


	public void init(MatcherConfig matcherConfig) throws MessagingException {
		this.matcherConfig = matcherConfig;
		
	}
	
	@SuppressWarnings("unchecked")
	public Collection<?> match(Mail mail) throws MessagingException {
		HashSet retval = new HashSet();			
		List<Integer> mailIds = NonEJBGlobalConfigurationSession.getInstance().getWorkers(GlobalConfiguration.WORKERTYPE_MAILSIGNERS);
		for (Integer id : mailIds) {
			try {
				IMailProcessor mailProcessor = getMailSigner(id);
				if(isValidUser(mail, mailProcessor)){
					WorkerConfig awc = mailProcessor.getStatus().getActiveSignerConfig();

					if(!awc.getProperty(BaseMailProcessor.DISABLED,"FALSE").equalsIgnoreCase("TRUE")){
						retval.addAll(getMailSigner(id).match(mail));
					}

				}

			} catch (InvalidWorkerIdException e) {
				// Should never happen
				log.error(e);
			} 
		}
		return retval;

	}

}
