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
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import javax.mail.MessagingException;

import org.apache.log4j.Logger;
import org.apache.mailet.GenericMailet;
import org.apache.mailet.Mail;
import org.apache.mailet.MailetConfig;
import org.ejbca.util.CertTools;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ISignerCertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.MailSignerConfig;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.mailsigner.BaseMailSigner;
import org.signserver.mailsigner.IMailSigner;
import org.signserver.mailsigner.cli.IMailSignerRMI;

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
 * $Id: MailSignerContainerMailet.java,v 1.3 2007-11-27 06:05:12 herrvendil Exp $
 */
public class MailSignerContainerMailet extends GenericMailet implements IMailSignerRMI{

	private static transient Logger log = Logger.getLogger(MailSignerContainerMailet.class.getName());
	
    private ConcurrentHashMap<Integer, IMailSigner> mailSigners = new ConcurrentHashMap<Integer, IMailSigner>();
	

    
    
    /**
     * Creates all the configured IMailSigner plugins, initializes
     * them and send them their configuration.
     * 
     * Also sets up the RMI service for the CLI.
     */
	@Override
	public void init(MailetConfig mailetConfig) throws MessagingException {
		super.init(mailetConfig);
		
		try{
			     
			Registry registry = LocateRegistry.createRegistry(MailSignerConfig.getRMIRegistryPort());
			Remote stup = UnicastRemoteObject.exportObject(this,MailSignerConfig.getRMIServerPort());
			registry.rebind(MailSignerConfig.RMI_OBJECT_NAME, stup);
			log.info("MailSigner RMI interface bound successfully with registry on port: " + MailSignerConfig.getRMIRegistryPort() + " and server on port: " + MailSignerConfig.getRMIServerPort());			
		}catch(AccessException e){
			log.error("Failed binding MailSigner RMI interface.", e);
		}catch (RemoteException e) {
			log.error("Failed binding MailSigner RMI interface.", e);
		}
		
	}

	/**
	 * Method that sends the mail to all the configured mail signers.
	 * In id order (ascending) order.
	 */
	public void service(Mail mail) {
		List<Integer> mailIds = NonEJBGlobalConfigurationSession.getInstance().getWorkers(GlobalConfiguration.WORKERTYPE_MAILSIGNERS);
		for (Integer id : mailIds) {
			try {
				IMailSigner mailSigner = getMailSigner(id);
				
				Properties activeProps = mailSigner.getStatus().getActiveSignerConfig().getProperties();
				if(activeProps.getProperty(BaseMailSigner.DISABLED,"FALSE").equalsIgnoreCase("TRUE")){
				  getMailSigner(id).service(mail);
				}
			} catch (InvalidWorkerIdException e) {
				// Should never happen
				log.error(e);
			}
		}
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#activateSigner(int, String)
	 */
	public void activateSigner(int signerId, String authenticationCode)
			throws CryptoTokenAuthenticationFailureException,
			CryptoTokenOfflineException, InvalidWorkerIdException,
			RemoteException {
		getMailSigner(signerId).activateSigner(authenticationCode);		
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#deactivateSigner(int)
	 */
	public boolean deactivateSigner(int signerId)
			throws CryptoTokenOfflineException, InvalidWorkerIdException,
			RemoteException {
		return getMailSigner(signerId).deactivateSigner();
		
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
	public ISignerCertReqData genCertificateRequest(int signerId,
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
		
		return getMailSigner(workerId).getStatus();
	}

	/**
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#reloadConfiguration(int, Properties)
	 */
	public void reloadConfiguration(int workerId)
			throws RemoteException {
		if(workerId == 0){
		  NonEJBGlobalConfigurationSession.getInstance().reload();
		  mailSigners.clear();
		}else{
		  mailSigners.remove(workerId);
		}		
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
	 * @see org.signserver.mailsigner.cli.IMailSignerRMI#getCurrentSignerConfig(int)
	 */
	public WorkerConfig getCurrentSignerConfig(int signerId) {		
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
	private IMailSigner getMailSigner(int signerId) throws InvalidWorkerIdException{
		IMailSigner retval = mailSigners.get(signerId);
				
		if(retval == null){
			List<Integer> mailIds = NonEJBGlobalConfigurationSession.getInstance().getWorkers(GlobalConfiguration.WORKERTYPE_MAILSIGNERS);
			for (Integer id : mailIds) {
				if(id.equals(signerId)){
					GlobalConfiguration gc = NonEJBGlobalConfigurationSession.getInstance().getGlobalConfiguration();
					String classPath = gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, GlobalConfiguration.WORKERPROPERTY_BASE + id + GlobalConfiguration.WORKERPROPERTY_CLASSPATH);
					
					try {
						IMailSigner mailSigner = (IMailSigner) this.getClass().getClassLoader().loadClass(classPath).newInstance();
						mailSigner.init(id, cloneWorkerProperties(PropertyFileStore.getInstance().getWorkerProperties(id)));
						mailSigners.put(id, mailSigner);
						retval = mailSigner;
					} catch (Exception e) {
						log.error("Error creating an instance of mail signer with Id " + id,e);
					} 				
					break;
				}
			}			
		}
		
		if(retval == null){
			throw new InvalidWorkerIdException("Error, couldn't find signer id in global configuration.");
		}
		
		return retval;
	}

	private WorkerConfig cloneWorkerProperties(WorkerConfig workerProperties) {
		WorkerConfig retval = new WorkerConfig();
		
		Enumeration<Object> en = workerProperties.getProperties().keys();
		while(en.hasMoreElements()){
			String key = (String) en.nextElement();
			retval.getProperties().setProperty(key, workerProperties.getProperties().getProperty(key));
		}
		
		return retval;
	}







}
