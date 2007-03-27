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


package org.signserver.ejb;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.RemoveException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.util.CertTools;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ISignRequest;
import org.signserver.common.ISignResponse;
import org.signserver.common.ISignerCertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalSignRequestException;
import org.signserver.common.InvalidSignerIdException;
import org.signserver.common.SignTokenAuthenticationFailureException;
import org.signserver.common.SignTokenOfflineException;
import org.signserver.common.SignerConfig;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.server.IWorker;
import org.signserver.server.WorkerFactory;
import org.signserver.server.signers.BaseSigner;
import org.signserver.server.signers.ISigner;

/**
 * The main session bean
 * 
 * @ejb.bean name="SignServerSession"
 *           display-name="Name for SignSession"
 *           description="Description for SignSession"
 *           jndi-name="SignServerSession"
 *           local-jndi-name="SignServerSessionLocal"
 *           type="Stateless"
 *           view-type="both"
 *           transaction-type="Container"
 *
 * @ejb.transaction type="Supports"           
 *       
 * @ejb.ejb-external-ref description="The Global Configuration Session Bean"
 *   view-type="local"
 *   ref-name="ejb/GlobalConfigurationSessionLocal"
 *   type="Session"
 *   home="org.signserver.ejb.IGlobalConfigurationSessionLocalHome"
 *   business="org.signserver.ejb.IGlobalConfigurationSessionLocal"
 *   link="GlobalConfigurationSession"
 *   
 * @ejb.ejb-external-ref description="The Timer Service Session Bean"
 *   view-type="local"
 *   ref-name="ejb/ServiceTimerSessionLocal"
 *   type="Session"
 *   home="org.signserver.ejb.IServiceTimerSessionLocalHome"
 *   business="org.signserver.ejb.IServiceTimerSessionLocal"
 *   link="ServiceTimerSession"
 *           
 *           
 * @ejb.ejb-external-ref
 *   description="The Worker Config Bean"
 *   view-type="local"
 *   ejb-name="WorkerConfigDataLocal"
 *   type="Entity"
 *   home="org.signserver.ejb.WorkerConfigDataLocalHome"
 *   business="org.signserver.ejb.WorkerConfigDataLocal"
 *   link="WorkerConfigData"
 *   
 * @ejb.ejb-external-ref
 *   description="The Archive Bean"
 *   view-type="local"
 *   ejb-name="ArchiveDataLocal"
 *   type="Entity"
 *   home="org.signserver.ejb.ArchiveDataLocalHome"
 *   business="org.signserver.ejb.ArchiveDataLocal"
 *   link="ArchiveData" 
 * 
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.signserver.ejb.SignServerSessionLocalHome"
 *   remote-class="org.signserver.ejb.SignServerSessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.signserver.ejb.SignServerSessionLocal"
 *   remote-class="org.signserver.ejb.SignServerSession"
 * 
 * 
 * 
 * @ejb.security-identity
 *           run-as="InternalUser"
 * 
 */
public class SignServerSessionBean extends BaseSessionBean {


	private static final long serialVersionUID = 1L;


	/** Log4j instance for actual implementation class */
	public transient Logger log = Logger.getLogger(this.getClass());

    /** The local home interface of Worker Config entity bean. */
    private WorkerConfigDataLocalHome workerConfigHome = null;
    
    /** The local home interface of archive entity bean. */
    private ArchiveDataLocalHome archiveDataHome = null;

	/**
	 * 
	 */
	public SignServerSessionBean() {
		super();
		// Do Nothing     
	}

	/**
	 * The SignSession Beans main method. Takes signature requests processes them
	 * and returns a response.
	 *
	 *     
	 * @throws SignTokenOfflineException if the signers token isn't activated. 
	 * @throws IllegalSignRequestException if illegal request is sent to the method
	 *
	 *  
	 * @ejb.interface-method
	 */
	public ISignResponse signData(int signerId, ISignRequest request,
	                              X509Certificate clientCert, String requestIP) throws IllegalSignRequestException,
		SignTokenOfflineException {
		log.debug(">signData " + request.getRequestID());
		IWorker worker = WorkerFactory.getInstance().getWorker(signerId, workerConfigHome, getGlobalConfigurationSession());
		
        if(worker == null){
        	throw new IllegalSignRequestException("Non-existing signerId");
        }
        
        if(!(worker instanceof ISigner)){
        	throw new IllegalSignRequestException("Worker exists but isn't a signer.");
        }
		ISigner signer = (ISigner) worker;
        
        if(signer.getAuthenticationType() == ISigner.AUTHTYPE_CLIENTCERT){
        	if(clientCert == null){
        		throw new IllegalSignRequestException("Error, client authentication is required.");   
        	}else{
        		if(!authorizedToRequestSignature(clientCert, new SignerConfig (signer.getStatus().getActiveSignerConfig()).getAuthorizedClients())){        	                
        			
        			throw new IllegalSignRequestException("Error, client '" + clientCert.getSubjectDN().toString() + "' requesting signature from signer with id : " + 
        					signerId + " isn't an authorized client. ");   
        		}
        	}
        }
        
        if(signer.getStatus().getActiveSignerConfig().getProperties().getProperty(BaseSigner.DISABLED,"FALSE").equalsIgnoreCase("TRUE")){
        	throw new SignTokenOfflineException("Error Signer : " + signerId + " is disabled and cannot perform any signature operations");
        }
        
        ISignResponse res = signer.signData(request,  clientCert);

        if(signer.getStatus().getActiveSignerConfig().getProperties().getProperty(BaseSigner.ARCHIVE,"FALSE").equalsIgnoreCase("TRUE")){
        	if(res.getArchiveData() != null){
    			try {				
    			  archiveDataHome.create(ArchiveDataVO.TYPE_RESPONSE,signerId, res.getArchiveId(), clientCert, requestIP, res.getArchiveData());
    			} catch (CreateException e1) {
                   throw new EJBException(e1);
    			}
        		        	
        	}else{
        		log.error("Error archiving response generated of signer " + signerId + ", archiving is not supported by signer.");
        	}
        }
        
        log.info("Signer " + signerId + " Processed request " + res.getRequestID() + " Successfully");
        
		log.debug("<signData " + request.getRequestID());
		return res;
	}



	private boolean authorizedToRequestSignature(X509Certificate clientCert, Collection authorizedClients) {

        boolean isAuthorized = false;
        final Iterator iter = authorizedClients.iterator();
        String clientDN = CertTools.stringToBCDNString(clientCert.getIssuerDN().toString()); 
        
        while( iter.hasNext() && !isAuthorized ){
            AuthorizedClient next = (AuthorizedClient) iter.next();
            try {
                // If both authorized clients Issuer DN And Cert Serial match, 
                // the client is authorized.
                isAuthorized = clientDN.equals(next.getIssuerDN()) &&
                               clientCert.getSerialNumber().equals(new BigInteger(next.getCertSN(),16));
            }catch( IllegalArgumentException e) {
                log.warn(e.getMessage() + " for athorized client");
            }
        }
		return isAuthorized;
	}

	/**
	 * Returns the current status of a signers. 
	 *
	 * Should be used with the cmd-line status command.
	 * @param signerId of the signer
	 * @return a SignerStatus class 
	 *  
	 * @ejb.interface-method
	 */
	public WorkerStatus getStatus(int workerId) throws InvalidSignerIdException{
		IWorker worker = WorkerFactory.getInstance().getWorker(workerId, workerConfigHome, getGlobalConfigurationSession());
		if(worker == null){
			throw new InvalidSignerIdException("Given SignerId " + workerId + " doesn't exist");
		}
		
		
		return worker.getStatus();
	}

	/**
	 * Returns the Id of a signer given a name 
	 *
	 * @param signerName of the signer cannot be null
	 * @return The Id of a named signer or null if no such name exists
	 *  
	 * @ejb.interface-method
	 */
	public int getSignerId(String signerName) {
		return WorkerFactory.getInstance().getSignerIdFromName(signerName.toUpperCase(), workerConfigHome, getGlobalConfigurationSession());		
	}
	 
	
	/**
	 * Method used when a configuration have been updated. And should be
	 * called from the commandline.
	 *	  
	 *
	 * @param workerId of the worker that should be reloaded, or 0 to reload
	 * reload of all available workers 
	 * @ejb.interface-method
	 */
	public void reloadConfiguration(int workerId) {
		if(workerId == 0){
		  getGlobalConfigurationSession().reload();
		}else{
			WorkerFactory.getInstance().reloadWorker(workerId, workerConfigHome, getGlobalConfigurationSession());
		}
		
		if(workerId == 0 || getGlobalConfigurationSession().getWorkers(GlobalConfiguration.WORKERTYPE_SERVICES).contains(new Integer(workerId))){
		  getServiceTimerSession().unload(workerId);
		  getServiceTimerSession().load(workerId);
		}
	}

	/**
	 * Method used to activate the signtoken of a signer.
	 * Should be called from the command line.
	 *    
	 * 
	 * @param signerId of the signer
	 * @param authenticationCode (PIN) used to activate the token.
	 * 
	 * @throws SignTokenOfflineException 
	 * @throws SignTokenAuthenticationFailureException 
	 *
	 *  
	 * @ejb.interface-method
	 */
	public void activateSigner(int signerId, String authenticationCode)
		throws SignTokenAuthenticationFailureException,
		SignTokenOfflineException, InvalidSignerIdException {
		IWorker worker = WorkerFactory.getInstance().getWorker(signerId, workerConfigHome,getGlobalConfigurationSession());
		if(worker == null){
			throw new InvalidSignerIdException("Given SignerId " + signerId + " doesn't exist");
		}
		
        if(!(worker instanceof ISigner)){
        	throw new InvalidSignerIdException("Worker exists but isn't a signer.");
        }
		ISigner signer = (ISigner) worker;
		
		signer.activateSigner(authenticationCode);
	}

	/**
	 * Method used to deactivate the signtoken of a signer.
	 * Should be called from the command line.
	 *    
	 * 
	 * @param signerId of the signer
	 * @param authenticationCode (PIN) used to activate the token.
	 * 
	 * @throws SignTokenOfflineException 
	 * @throws SignTokenAuthenticationFailureException 
	 *
	 *  
	 * @ejb.interface-method
	 */
	public void deactivateSigner(int signerId)
		throws SignTokenOfflineException, InvalidSignerIdException {
		IWorker worker = WorkerFactory.getInstance().getWorker(signerId, workerConfigHome,getGlobalConfigurationSession());
		if(worker == null){
			throw new InvalidSignerIdException("Given SignerId " + signerId + " doesn't exist");
		}
		
        if(!(worker instanceof ISigner)){
        	throw new InvalidSignerIdException("Worker exists but isn't a signer.");
        }
		ISigner signer = (ISigner) worker;
		
		signer.deactivateSigner();
	}

	/**
	 * Returns the current configuration of a signer.
	 * 
	 * Observe that this config might not be active until a reload command have been excecuted.
	 * 
	 * 
	 * @param signerId
	 * @return the current (not always active) configuration
	 * 
	 *  
	 * @ejb.interface-method
	 */
	public WorkerConfig getCurrentSignerConfig(int signerId){
        return getSignerConfigBean(signerId).getWorkerConfig(); 				
	}
	
	/**
	 * Sets a parameter in a workers configuration
	 * 
	 * Observe that the worker isn't activated with this config until reload is performed.
	 * 
	 * @param workerId
	 * @param key
	 * @param value
	 * 
     * @ejb.transaction type="Required"  
	 * @ejb.interface-method
	 */
	public void setWorkerProperty(int workerId, String key, String value){
		WorkerConfigDataLocal signerconfigdata = getSignerConfigBean(workerId);
		
		WorkerConfig config = signerconfigdata.getWorkerConfig();
		config.setProperty(key.toUpperCase(),value);
		signerconfigdata.setWorkerConfig(config);
	}
	
	/**
	 * Removes a given workers property
	 * 
	 * 
	 * @param workerId
	 * @param key
	 * @return true if the property did exist and was removed othervise false
	 * 
     * @ejb.transaction type="Required"
	 * @ejb.interface-method
	 */
	
	public boolean removeWorkerProperty(int workerId, String key){
		boolean result = false;
		WorkerConfigDataLocal workerconfigdata = getSignerConfigBean(workerId);
		
		WorkerConfig config = workerconfigdata.getWorkerConfig();
		result = config.removeProperty(key.toUpperCase());
		if(config.getProperties().size() == 0){
		  try {
			workerconfigdata.remove();
			log.debug("WorkerConfig is empty and therefore removed.");
		} catch (EJBException e) {
			log.error(e);
		} catch (RemoveException e) {
			log.error(e);
		}
		}else{
		  workerconfigdata.setWorkerConfig(config);
		}
		return result;
	}	
	
	/**
	 * Method that returns a collection of AuthorizedClient of
	 * client certificate sn and issuerid accepted for a given signer-
	 * 
	 * @param signerId
	 * @return Sorted collection opf authorized clients
	 * 
	 *  
	 * @ejb.interface-method
	 */
	public Collection getAuthorizedClients(int signerId){
		return new SignerConfig( getSignerConfigBean(signerId).getWorkerConfig()).getAuthorizedClients();
	}
	
	/**
	 * Method adding an authorized client to a signer
	 * 
	 * @param signerId
	 * @param authClient
	 * 
     * @ejb.transaction type="Required"
	 * @ejb.interface-method
	 */
	public void addAuthorizedClient(int signerId, AuthorizedClient authClient){
		WorkerConfigDataLocal signerconfigdata = getSignerConfigBean(signerId);
		
		WorkerConfig config = signerconfigdata.getWorkerConfig();
		(new SignerConfig(config)).addAuthorizedClient(authClient);
		signerconfigdata.setWorkerConfig(config);		
	}

	/**
	 * Removes an authorized client from a signer
	 * 
	 * @param signerId
	 * @param authClient
	 * 
     * @ejb.transaction type="Required"
	 * @ejb.interface-method
	 */
	public boolean removeAuthorizedClient(int signerId, AuthorizedClient authClient){
		boolean result = false;
		WorkerConfigDataLocal signerconfigdata = getSignerConfigBean(signerId);
		
		WorkerConfig config = signerconfigdata.getWorkerConfig();
		result = (new SignerConfig(config)).removeAuthorizedClient(authClient);
		signerconfigdata.setWorkerConfig(config);
		return result;
	}
	
	/**
	 * Method used to let a signer generate a certificate request
	 * using the signers own genCertificateRequest metod
	 * 
	 * @param signerId id of the signer
	 * @param certReqInfo information used by the signer to create the request
	 * 
     * @ejb.transaction type="Required"
	 * @ejb.interface-method
	 */
	public ISignerCertReqData getCertificateRequest(int signerId, ISignerCertReqInfo certReqInfo) throws		
		SignTokenOfflineException, InvalidSignerIdException {
			IWorker worker = WorkerFactory.getInstance().getWorker(signerId, workerConfigHome,getGlobalConfigurationSession());
			if(worker == null){
				throw new InvalidSignerIdException("Given SignerId " + signerId + " doesn't exist");
			}
			
	        if(!(worker instanceof ISigner)){
	        	throw new InvalidSignerIdException("Worker exists but isn't a signer.");
	        }
			ISigner signer = (ISigner) worker;
			
			return signer.genCertificateRequest(certReqInfo);
	}
	
	/**
	 * Method used to remove a key from a signer.
	 * 
	 * @param signerId id of the signer
	 * @param purpose on of ISignToken.PURPOSE_ constants
	 * @return true if removal was successful.
	 * 
     * @ejb.transaction type="Required"
	 * @ejb.interface-method
	 */
	public boolean destroyKey(int signerId, int purpose) throws	InvalidSignerIdException {
			IWorker worker = WorkerFactory.getInstance().getWorker(signerId, workerConfigHome,getGlobalConfigurationSession());
			if(worker == null){
				throw new InvalidSignerIdException("Given SignerId " + signerId + " doesn't exist");
			}
			
	        if(!(worker instanceof ISigner)){
	        	throw new InvalidSignerIdException("Worker exists but isn't a signer.");
	        }
			ISigner signer = (ISigner) worker;
			
			return signer.destroyKey(purpose);
	}
	
	/**
	 * Method used to upload a certificate to a signers active configuration
	 * 
	 * @param signerId id of the signer
	 * @param signerCert the certificate used to sign signature requests
	 * @param scope one of GlobalConfiguration.SCOPE_ constants
	 *  
     * @ejb.transaction type="Required"
	 * @ejb.interface-method
	 */
	public void uploadSignerCertificate(int signerId, X509Certificate signerCert, String scope){		
		WorkerConfigDataLocal signerconfigdata = getSignerConfigBean(signerId);
		
		WorkerConfig config = signerconfigdata.getWorkerConfig();
		( new SignerConfig(config)).setSignerCertificate(signerCert,scope);
		signerconfigdata.setWorkerConfig(config);
	}
	
	/**
	 * Method used to upload a complete certificate chain to a configuration
	 * 
	 * @param signerId id of the signer
	 * @param signerCerts the certificatechain used to sign signature requests
	 * @param scope one of GlobalConfiguration.SCOPE_ constants
     * @ejb.transaction type="Required"
	 * @ejb.interface-method
	 */
	public void uploadSignerCertificateChain(int signerId, Collection signerCerts, String scope){		
		WorkerConfigDataLocal signerconfigdata = getSignerConfigBean(signerId);
		
		WorkerConfig config = signerconfigdata.getWorkerConfig();
		(new SignerConfig( config)).setSignerCertificateChain(signerCerts, scope);
		signerconfigdata.setWorkerConfig(config);
	}
	
	/**
	 * Methods that generates a free workerid that can be used for new signers
	 * @ejb.interface-method
	 */
	public int genFreeWorkerId(){
		Collection ids =  getGlobalConfigurationSession().getWorkers(GlobalConfiguration.WORKERTYPE_ALL);
		int max = 0;
		Iterator iter = ids.iterator();
		while(iter.hasNext()){
			Integer id = (Integer) iter.next();
			if(id.intValue() > max){
				max = id.intValue();
			}
		}
		
		return max+1;
	}
	
	/**
	 * Method that finds an archive given it's archive Id
	 * 
	 * @param signerId id of the signer
	 * @param archiveId the Id of the archive data (could be request serialnumber).
	 * 
	 * @ejb.interface-method
	 */
	public ArchiveDataVO findArchiveDataFromArchiveId(int signerId, String archiveId){
		ArchiveDataVO retval = null;
		try {
			retval = archiveDataHome.findByArchiveId(ArchiveDataVO.TYPE_RESPONSE,signerId,archiveId).getArchiveDataVO();
		} catch (FinderException e) {}
		
		return retval;
	}
	
	/**
	 * Method that finds an archive given it's requestors IP
	 * 
	 * @param signerId id of the signer
	 * @param requestIP the IP address of the client creating the request
	 * 
	 * @ejb.interface-method
	 */
	public List findArchiveDatasFromRequestIP(int signerId, String requestIP){
		ArrayList retval = new ArrayList();
		try {
			Collection result = archiveDataHome.findByRequestIP(ArchiveDataVO.TYPE_RESPONSE,signerId,requestIP);
			Iterator iter = result.iterator();
			while(iter.hasNext()){
			  ArchiveDataLocal next = (ArchiveDataLocal) iter.next();
			  retval.add(next.getArchiveDataVO());
			}
			
		} catch (FinderException e) {}
		
		return retval;
	}
	
	/**
	 * Method that finds an archive given it's requesters client certificate
	 * 
	 * @param signerId id of the signer
	 * @param requestCertSerialnumber the serialnumber of the certificate making the request
	 * @param requestIssuerDN the issuer of the client certificate
	 * 
	 * @ejb.interface-method
	 */
	public List findArchiveDatasFromRequestCertificate(int signerId, BigInteger requestCertSerialnumber, String requestCertIssuerDN){
		ArrayList retval = new ArrayList();
		try {
			Collection result = archiveDataHome.findByRequestCertificate(ArchiveDataVO.TYPE_RESPONSE,signerId,CertTools.stringToBCDNString(requestCertIssuerDN),requestCertSerialnumber.toString(16));
			Iterator iter = result.iterator();
			while(iter.hasNext()){
			  ArchiveDataLocal next = (ArchiveDataLocal) iter.next();
			  retval.add(next.getArchiveDataVO());
			}
			
		} catch (FinderException e) {}
		
		return retval;
	}	
	
	

	/**
	 * Create method
	 * @ejb.create-method  view-type = "remote"
	 */
	public void ejbCreate() throws javax.ejb.CreateException {
		workerConfigHome = (WorkerConfigDataLocalHome) getLocator().getLocalHome(WorkerConfigDataLocalHome.COMP_NAME);
		archiveDataHome = (ArchiveDataLocalHome) getLocator().getLocalHome(ArchiveDataLocalHome.COMP_NAME);
	}
	
	private WorkerConfigDataLocal getSignerConfigBean(int signerId){
		WorkerConfigDataLocal signerConfig = null;
	    try {
			signerConfig = workerConfigHome.findByPrimaryKey(new WorkerConfigDataPK(signerId));
		} catch (FinderException e) {
			try {				
				signerConfig = workerConfigHome.create(signerId,WorkerConfig.class.getName());
			} catch (CreateException e1) {
               throw new EJBException(e1);
			}
		}
		return signerConfig;	
	}
	
    /**
     * Gets connection to global configuration session bean
     *
     * @return Connection
     */
    private IGlobalConfigurationSessionLocal getGlobalConfigurationSession() {
        if (globalConfigurationSession == null) {
            try {
                IGlobalConfigurationSessionLocalHome globalconfigurationsessionhome = (IGlobalConfigurationSessionLocalHome) getLocator().getLocalHome(IGlobalConfigurationSessionLocalHome.COMP_NAME);
                globalConfigurationSession = globalconfigurationsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return globalConfigurationSession;
    } //getGlobalConfigurationSession
    
    private IGlobalConfigurationSessionLocal globalConfigurationSession = null;
	
    /**
     * Gets connection to the service timer session
     *
     * @return Connection
     */
    private IServiceTimerSessionLocal getServiceTimerSession() {
        if (serviceTimerSession == null) {
            try {
                IServiceTimerSessionLocalHome servicetimersessionhome = (IServiceTimerSessionLocalHome) getLocator().getLocalHome(IServiceTimerSessionLocalHome.COMP_NAME);
                serviceTimerSession = servicetimersessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return serviceTimerSession;
    } //getServiceTimerSession
    
    private IServiceTimerSessionLocal serviceTimerSession = null;
    
}
