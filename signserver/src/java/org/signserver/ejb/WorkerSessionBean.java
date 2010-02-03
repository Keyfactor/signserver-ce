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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.ejbca.util.CertTools;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IArchivableProcessResponse;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignResponse;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerConstants;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IServiceTimerSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.IAuthorizer;
import org.signserver.server.IProcessable;
import org.signserver.server.IWorker;
import org.signserver.server.SignServerContext;
import org.signserver.server.WorkerFactory;
import org.signserver.server.statistics.Event;
import org.signserver.server.statistics.StatisticsManager;

/**
 * The main worker session bean
 * 
 */
@Stateless
public class WorkerSessionBean implements IWorkerSession.ILocal, IWorkerSession.IRemote  {
    @PersistenceContext(unitName="SignServerJPA")
    EntityManager em;

	private static final long serialVersionUID = 1L;

	@EJB
	private IGlobalConfigurationSession.ILocal globalConfigurationSession;

	@EJB
	private IServiceTimerSession.ILocal serviceTimerSession; 
		
	
	/** Log4j instance for actual implementation class */
	private static final Logger log = Logger.getLogger(WorkerSessionBean.class);

    /** The local home interface of Worker Config entity bean. */
    private WorkerConfigDataService workerConfigService = null;
    
    /** The local home interface of archive entity bean. */
    private ArchiveDataService archiveDataService = null;

    @PostConstruct
	public void create() {
    	workerConfigService = new WorkerConfigDataService(em);
    	archiveDataService = new ArchiveDataService(em);
    	
    
	}
	
	

	/**
	 * @see org.signserver.ejb.interfaces.IWorkerSession#process(int, org.signserver.common.ISignRequest, java.security.cert.X509Certificate, java.lang.String)
	 */
	public ProcessResponse process(int workerId, ProcessRequest request, RequestContext requestContext) throws IllegalRequestException,
		CryptoTokenOfflineException, SignServerException {
		log.debug(">process: "+workerId);
		IWorker worker = WorkerFactory.getInstance().getWorker(workerId, workerConfigService, globalConfigurationSession,new SignServerContext(em));
		
        if(worker == null){
        	throw new IllegalRequestException("Non-existing workerId: "+workerId);
        }
        
        if(!(worker instanceof IProcessable)){
        	throw new IllegalRequestException("Worker exists but isn't a processable: "+workerId);
        }
		IProcessable processable = (IProcessable) worker;
        		
        IAuthorizer auth = WorkerFactory.getInstance().getAuthenticator(workerId, processable.getAuthenticationType(), worker.getStatus().getActiveSignerConfig(), em);
        auth.isAuthorized(request, requestContext);
        
        WorkerConfig awc = processable.getStatus().getActiveSignerConfig();
        if(awc.getProperties().getProperty(SignServerConstants.DISABLED,"FALSE").equalsIgnoreCase("TRUE")){
        	throw new CryptoTokenOfflineException("Error Signer : " + workerId + " is disabled and cannot perform any signature operations");
        }
        // Check if the signer has a signer certificate and if that certificate have ok validity and private key usage periods. 
        checkCertificateValidity(workerId, awc);
    	
        Event event = StatisticsManager.startEvent(workerId, awc, em);
        requestContext.put(RequestContext.STATISTICS_EVENT, event);
        
        ProcessResponse res = null;
		try {
			res = processable.processData(request,  requestContext);
	        if(res instanceof IArchivableProcessResponse){
	        	IArchivableProcessResponse arres = (IArchivableProcessResponse) res;
	        	if(awc.getProperties().getProperty(SignServerConstants.ARCHIVE,"FALSE").equalsIgnoreCase("TRUE")){
	        		if(arres.getArchiveData() != null){ 
	        			String requestIP = (String) requestContext.get(RequestContext.REMOTE_IP);
	        			X509Certificate clientCert = (X509Certificate) requestContext.get(RequestContext.CLIENT_CERTIFICATE);
	        			archiveDataService.create(ArchiveDataVO.TYPE_RESPONSE,workerId, arres.getArchiveId(), clientCert, requestIP, arres.getArchiveData());        		        	
	        		}else{
	        			log.error("Error archiving response generated of signer " + workerId + ", archiving is not supported by signer.");
	        		}
	        	}
	        }
	        
	        StatisticsManager.endEvent(workerId, awc, em, event);
	        if(res instanceof ISignResponse){
	          log.info("Worker " + workerId + " Processed request " + ((ISignResponse) res).getRequestID() + " successfully");
	        }else{
	          log.info("Worker " + workerId + " Processed request successfully");
	        }
		} catch (SignServerException e) {
			log.error("SignServerException calling signer with id " + workerId + " : " +e.getMessage(),e);
			throw e;
		}
                
		log.debug("<process " );
		return res;
	}


	/** Verify the certificate validity times and also that the PrivateKeyUsagePeriod is ok
	 * 
	 * @param workerId
	 * @param awc
	 * @throws CryptoTokenOfflineException
	 */
	private void checkCertificateValidity(int workerId, WorkerConfig awc)
			throws CryptoTokenOfflineException {
    	boolean checkcertvalidity = awc.getProperties().getProperty(SignServerConstants.CHECKCERTVALIDITY,"TRUE").equalsIgnoreCase("TRUE");
    	boolean checkprivatekeyvalidity = awc.getProperties().getProperty(SignServerConstants.CHECKCERTPRIVATEKEYVALIDITY,"TRUE").equalsIgnoreCase("TRUE");
    	int minremainingcertvalidity = Integer.valueOf(awc.getProperties().getProperty(SignServerConstants.MINREMAININGCERTVALIDITY,"0"));
    	if (log.isDebugEnabled()) {
        	log.debug("checkcertvalidity: "+checkcertvalidity);
        	log.debug("checkprivatekeyvalidity: "+checkprivatekeyvalidity);    		
        	log.debug("minremainingcertvalidity: "+minremainingcertvalidity);    		
    	}

    	if (checkcertvalidity || checkprivatekeyvalidity || (minremainingcertvalidity > 0)) {
    		// If the signer have a certificate, check that it is usable
        	X509Certificate cert =(new ProcessableConfig(awc)).getSignerCertificate();
        	if (cert != null) {
        		// Check regular certificate validity
            	Date notBefore = cert.getNotBefore();
            	Date notAfter = cert.getNotAfter();
            	if (log.isDebugEnabled()) {
            		log.debug("The signer certificate is valid from '"+notBefore+"' until '"+notAfter+"'");
            	}
            	Date now = new Date();
            	
            	// Certificate validity period. Cert must not be expired.
            	if (checkcertvalidity) {
                	if (now.before(notBefore)) {
                		String msg = "Error Signer " + workerId + " have a signing certificate that is not valid until "+notBefore;
                		if (log.isDebugEnabled()) {
                    		log.debug(msg);                			
                		}
                    	throw new CryptoTokenOfflineException(msg);    		
                	}
                	if (now.after(notAfter)) {
                		String msg = "Error Signer " + workerId + " have a signing certificate that expired at "+notAfter;
                		if (log.isDebugEnabled()) {
                    		log.debug(msg);                			
                		}
                    	throw new CryptoTokenOfflineException(msg);    		
                	}            		
            	}
            	
            	// Private key usage period. Private key must not be expired
            	if (checkprivatekeyvalidity) {
                	// Check privateKeyUsagePeriod of it exists
                	byte[] extvalue = cert.getExtensionValue(X509Extensions.PrivateKeyUsagePeriod.getId());
                	if ( (extvalue != null) && (extvalue.length > 0) ) {
                    	if (log.isDebugEnabled()) {
                    		log.debug("Found a PrivateKeyUsagePeriod in the signer certificate.");
                    	}
            	        try {
            	        	DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(extvalue)).readObject());
            	        	PrivateKeyUsagePeriod p = PrivateKeyUsagePeriod.getInstance((ASN1Sequence) new ASN1InputStream(
            	        			new ByteArrayInputStream(oct.getOctets())).readObject());
            	        	if (p != null) {
            	        		notBefore = p.getNotBefore().getDate();
            	        		notAfter = p.getNotAfter().getDate();
            	            	if (log.isDebugEnabled()) {
            	            		log.debug("The signer certificate has a private key usage period from '"+notBefore+"' until '"+notAfter+"'");
            	            	}
            	            	now = new Date();
            	            	if (now.before(notBefore)) {
                            		String msg = "Error Signer " + workerId + " have a private key that is not valid until "+notBefore;
                            		if (log.isDebugEnabled()) {
                                		log.debug(msg);                			
                            		}
            	                	throw new CryptoTokenOfflineException(msg);    		
            	            	}
            	            	if (now.after(notAfter)) {
                            		String msg = "Error Signer " + workerId + " have a private key that expired at "+notAfter;
                            		if (log.isDebugEnabled()) {
                                		log.debug(msg);                			
                            		}
            	                	throw new CryptoTokenOfflineException(msg);    		
            	            	}
            	        	}
            	        } catch (IOException e) {
            	        	log.error(e);
            	        	CryptoTokenOfflineException newe = new CryptoTokenOfflineException("Error Signer " + workerId + " have a problem with PrivateKeyUsagePeriod, check server log.");
                        	newe.initCause(e);
                        	throw newe;
            	        } catch (ParseException e) {
            	        	log.error(e);
            	        	CryptoTokenOfflineException newe = new CryptoTokenOfflineException("Error Signer " + workerId + " have a problem with PrivateKeyUsagePeriod, check server log.");    		
                        	newe.initCause(e);
                        	throw newe;
        				}
                	}
            	} // if (checkprivatekeyvalidity)
            	
            	// Check remaining validity of certificate. Must not be too short.
            	if (minremainingcertvalidity > 0) {
            		Calendar cal = Calendar.getInstance();
            		cal.add(Calendar.DAY_OF_MONTH, minremainingcertvalidity);
            		Date check = cal.getTime();
            		if (log.isDebugEnabled()) {
            			log.debug("Checking if signer certificate expires before: "+check);
            		}
                	if (check.after(notAfter)) {
                		String msg = "Error Signer " + workerId + " have a signing certificate that expires within "+minremainingcertvalidity+" days.";
                		if (log.isDebugEnabled()) {
                    		log.debug(msg);                			
                		}
                    	throw new CryptoTokenOfflineException(msg);    		
                	}            		
            	}

        	} else { // if (cert != null)
        		if (log.isDebugEnabled()) {
        			log.debug("Worker does not have a signing certificate. Worker: "+workerId);
        		}
        	}
    	} // if (checkcertvalidity || checkprivatekeyvalidity) {
	} // checkCertificateValidity


	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#getStatus(int)
	 */
	public WorkerStatus getStatus(int workerId) throws InvalidWorkerIdException{
		IWorker worker = WorkerFactory.getInstance().getWorker(workerId, workerConfigService, globalConfigurationSession,new SignServerContext(em));
		if(worker == null){
			throw new InvalidWorkerIdException("Given SignerId " + workerId + " doesn't exist");
		}
		
		
		return worker.getStatus();
	}

	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#getWorkerId(java.lang.String)
	 */
	public int getWorkerId(String signerName) {
		return WorkerFactory.getInstance().getWorkerIdFromName(signerName.toUpperCase(), workerConfigService, globalConfigurationSession,new SignServerContext(em));		
	}
	 
	
	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#reloadConfiguration(int)
	 */
	public void reloadConfiguration(int workerId) {
		if(workerId == 0){
		  globalConfigurationSession.reload();		  
		}else{
			WorkerFactory.getInstance().reloadWorker(workerId, workerConfigService, globalConfigurationSession,new SignServerContext(em));
		}
		
		if(workerId == 0 || globalConfigurationSession.getWorkers(GlobalConfiguration.WORKERTYPE_SERVICES).contains(new Integer(workerId))){
		  serviceTimerSession.unload(workerId);
		  serviceTimerSession.load(workerId);
		}
		
		StatisticsManager.flush(workerId);
	}

	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#activateSigner(int, java.lang.String)
	 */
	public void activateSigner(int signerId, String authenticationCode)
		throws CryptoTokenAuthenticationFailureException,
		CryptoTokenOfflineException, InvalidWorkerIdException {
		IWorker worker = WorkerFactory.getInstance().getWorker(signerId, workerConfigService,globalConfigurationSession,new SignServerContext(em));
		if(worker == null){
			throw new InvalidWorkerIdException("Given SignerId " + signerId + " doesn't exist");
		}
		
        if(!(worker instanceof IProcessable)){
        	throw new InvalidWorkerIdException("Worker exists but isn't a signer.");
        }
		IProcessable signer = (IProcessable) worker;
		
		signer.activateSigner(authenticationCode);
	}

	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#deactivateSigner(int)
	 */
	public boolean deactivateSigner(int signerId)
		throws CryptoTokenOfflineException, InvalidWorkerIdException {
		IWorker worker = WorkerFactory.getInstance().getWorker(signerId, workerConfigService,globalConfigurationSession,new SignServerContext(em));
		if(worker == null){
			throw new InvalidWorkerIdException("Given SignerId " + signerId + " doesn't exist");
		}
		
        if(!(worker instanceof IProcessable)){
        	throw new InvalidWorkerIdException("Worker exists but isn't a signer.");
        }
		IProcessable signer = (IProcessable) worker;
		
		return signer.deactivateSigner();
	}

	/* (non-Javadoc)
	 * @see org.signserver.ejb.IWorkerSession#getCurrentSignerConfig(int)
	 */
	public WorkerConfig getCurrentWorkerConfig(int signerId){
        return getWorkerConfig(signerId); 				
	}
	
	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#setWorkerProperty(int, java.lang.String, java.lang.String)
	 */
	public void setWorkerProperty(int workerId, String key, String value){
		WorkerConfig config = getWorkerConfig(workerId);
		config.setProperty(key.toUpperCase(),value);
		workerConfigService.setWorkerConfig(workerId, config);		
	}
	
	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#removeWorkerProperty(int, java.lang.String)
	 */	
	public boolean removeWorkerProperty(int workerId, String key){
		boolean result = false;
		WorkerConfig config = getWorkerConfig(workerId);
				
		result = config.removeProperty(key.toUpperCase());
		if(config.getProperties().size() == 0){
			workerConfigService.removeWorkerConfig(workerId);
			log.debug("WorkerConfig is empty and therefore removed.");
		}else{
			workerConfigService.setWorkerConfig(workerId,config);
		}
		return result;
	}	
	
	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#getAuthorizedClients(int)
	 */
	public Collection<AuthorizedClient> getAuthorizedClients(int signerId){
		return new ProcessableConfig( getWorkerConfig(signerId)).getAuthorizedClients();
	}
	
	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#addAuthorizedClient(int, org.signserver.common.AuthorizedClient)
	 */
	public void addAuthorizedClient(int signerId, AuthorizedClient authClient){
		WorkerConfig config = getWorkerConfig(signerId);
		(new ProcessableConfig(config)).addAuthorizedClient(authClient);
		workerConfigService.setWorkerConfig(signerId, config);		
	}

	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#removeAuthorizedClient(int, org.signserver.common.AuthorizedClient)
	 */
	public boolean removeAuthorizedClient(int signerId, AuthorizedClient authClient){
		boolean result = false;
		WorkerConfig config = getWorkerConfig(signerId);
		
		
		result = (new ProcessableConfig(config)).removeAuthorizedClient(authClient);
		workerConfigService.setWorkerConfig(signerId, config);
		return result;
	}
	
	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#getCertificateRequest(int, org.signserver.common.ISignerCertReqInfo)
	 */
	public ICertReqData getCertificateRequest(int signerId, ISignerCertReqInfo certReqInfo) throws		
		CryptoTokenOfflineException, InvalidWorkerIdException {
		if (log.isTraceEnabled()) {
			log.trace(">getCertificateRequest: signerId="+signerId);
		}
			IWorker worker = WorkerFactory.getInstance().getWorker(signerId, workerConfigService,globalConfigurationSession,new SignServerContext(em));
			if(worker == null){
				throw new InvalidWorkerIdException("Given SignerId " + signerId + " doesn't exist");
			}
			
	        if(!(worker instanceof IProcessable)){
	        	throw new InvalidWorkerIdException("Worker exists but isn't a signer.");
	        }
			IProcessable processable = (IProcessable) worker;
			if (log.isDebugEnabled()) {
				log.debug("Found processable worker of type: "+processable.getClass().getName());
			}
			
			ICertReqData ret = processable.genCertificateRequest(certReqInfo);
			if (log.isTraceEnabled()) {
				log.trace("<getCertificateRequest: signerId="+signerId);
			}
			return ret;
	}
	
	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#destroyKey(int, int)
	 */
	public boolean destroyKey(int signerId, int purpose) throws	InvalidWorkerIdException {
			IWorker worker = WorkerFactory.getInstance().getWorker(signerId, workerConfigService,globalConfigurationSession,new SignServerContext(em));
			if(worker == null){
				throw new InvalidWorkerIdException("Given SignerId " + signerId + " doesn't exist");
			}
			
	        if(!(worker instanceof IProcessable)){
	        	throw new InvalidWorkerIdException("Worker exists but isn't a signer.");
	        }
			IProcessable signer = (IProcessable) worker;
			
			return signer.destroyKey(purpose);
	}
	
	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#uploadSignerCertificate(int, java.security.cert.X509Certificate, java.lang.String)
	 */
	public void uploadSignerCertificate(int signerId, X509Certificate signerCert, String scope){		
		WorkerConfig config = getWorkerConfig(signerId);

		( new ProcessableConfig(config)).setSignerCertificate(signerCert,scope);
		workerConfigService.setWorkerConfig(signerId, config);
	}
	
	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#uploadSignerCertificateChain(int, java.util.Collection, java.lang.String)
	 */
	public void uploadSignerCertificateChain(int signerId, Collection<Certificate> signerCerts, String scope){		
		
		WorkerConfig config = getWorkerConfig(signerId);
		(new ProcessableConfig( config)).setSignerCertificateChain(signerCerts, scope);
		workerConfigService.setWorkerConfig(signerId, config);
	}
	
	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#genFreeWorkerId()
	 */
	public int genFreeWorkerId(){
		Collection<Integer> ids =  globalConfigurationSession.getWorkers(GlobalConfiguration.WORKERTYPE_ALL);
		int max = 0;
		Iterator<Integer> iter = ids.iterator();
		while(iter.hasNext()){
			Integer id =  iter.next();
			if(id.intValue() > max){
				max = id.intValue();
			}
		}
		
		return max+1;
	}
	
	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#findArchiveDataFromArchiveId(int, java.lang.String)
	 */
	public ArchiveDataVO findArchiveDataFromArchiveId(int signerId, String archiveId){
		ArchiveDataVO retval = null;
		
		ArchiveDataBean adb = archiveDataService.findByArchiveId(ArchiveDataVO.TYPE_RESPONSE,signerId,archiveId);
		if(adb != null){
			retval = adb.getArchiveDataVO();
		}
		
		return retval;
	}
	
	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#findArchiveDatasFromRequestIP(int, java.lang.String)
	 */
	public List<ArchiveDataVO> findArchiveDatasFromRequestIP(int signerId, String requestIP){
		ArrayList<ArchiveDataVO> retval = new ArrayList<ArchiveDataVO>();

		Collection<ArchiveDataBean> result = archiveDataService.findByRequestIP(ArchiveDataVO.TYPE_RESPONSE,signerId,requestIP);
		Iterator<ArchiveDataBean> iter = result.iterator();
		while(iter.hasNext()){
			ArchiveDataBean next =  iter.next();
			retval.add(next.getArchiveDataVO());
		}

		return retval;
	}
	
	/* (non-Javadoc)
	 * @see org.signserver.ejb.interfaces.IWorkerSession#findArchiveDatasFromRequestCertificate(int, java.math.BigInteger, java.lang.String)
	 */
	public List<ArchiveDataVO> findArchiveDatasFromRequestCertificate(int signerId, BigInteger requestCertSerialnumber, String requestCertIssuerDN){
		ArrayList<ArchiveDataVO> retval = new ArrayList<ArchiveDataVO>();

		Collection<ArchiveDataBean> result = archiveDataService.findByRequestCertificate(ArchiveDataVO.TYPE_RESPONSE,signerId,CertTools.stringToBCDNString(requestCertIssuerDN),requestCertSerialnumber.toString(16));
		Iterator<ArchiveDataBean> iter = result.iterator();
		while(iter.hasNext()){
			ArchiveDataBean next = iter.next();
			retval.add(next.getArchiveDataVO());
		}
		
		return retval;
	}	
	
	
	private WorkerConfig getWorkerConfig(int workerId){
		WorkerConfig workerConfig = workerConfigService.getWorkerConfig(workerId);
	    if(workerConfig == null){
	    	workerConfigService.create(workerId, WorkerConfig.class.getName());
	    	workerConfig = workerConfigService.getWorkerConfig(workerId);
		}
		return workerConfig;	
	}
	


    
}
