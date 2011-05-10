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
 
package org.signserver.module.wsra.ws;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.module.wsra.beans.BackupRestoreBean;
import org.signserver.module.wsra.beans.CertificateDataBean;
import org.signserver.module.wsra.beans.OrganizationDataBean;
import org.signserver.module.wsra.beans.ProductDataBean;
import org.signserver.module.wsra.beans.TokenDataBean;
import org.signserver.module.wsra.beans.TransactionDataBean;
import org.signserver.module.wsra.beans.UserDataBean;
import org.signserver.module.wsra.ca.ICertRequestData;
import org.signserver.module.wsra.ca.IRequestDataChecker;
import org.signserver.module.wsra.common.AuthorizationDeniedException;
import org.signserver.module.wsra.common.Roles;
import org.signserver.module.wsra.common.WSRAConstants;
import org.signserver.module.wsra.common.WSRAConstants.OrganizationStatus;
import org.signserver.module.wsra.common.WSRAConstants.ProductStatus;
import org.signserver.module.wsra.common.WSRAConstants.UserStatus;
import org.signserver.module.wsra.common.tokenprofiles.JKSTokenProfile;
import org.signserver.module.wsra.common.tokenprofiles.SMTPTokenProfile;
import org.signserver.module.wsra.core.DBManagers;
import org.signserver.module.wsra.core.DataConfigurationManager;
import org.signserver.module.wsra.core.DataFileParser;
import org.signserver.module.wsra.core.ProductMapper;
import org.signserver.module.wsra.core.DataConfigurationManager.Type;
import org.signserver.protocol.ws.Certificate;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.validationservice.common.ICertificate;

/**
 * Class containing helper methods for the WSRA class
 * to keep the code more clean.
 * 
 * 
 * @author Philip Vendil 25 okt 2008
 *
 * @version $Id$
 */

public class WSRAHelper {
	
	private static final Logger log = Logger.getLogger(WSRAHelper.class);
	
	
	static final HashSet<UserStatus> ALLOW_ALL_USER_STATUSES = null;
	static final HashSet<OrganizationStatus> ALLOW_ALL_ORGANIZATION_STATUSES = null;
	
	static final HashSet<UserStatus> ALLOWED_CALLER_STATUSES = new HashSet<UserStatus>();
	static{
		ALLOWED_CALLER_STATUSES.add(UserStatus.READYFORGENERATION);
		ALLOWED_CALLER_STATUSES.add(UserStatus.GENERATED);
	}
	
	static final HashSet<OrganizationStatus> DEFAULT_ALLOWED_ORGANIZATION_STATUSES = new HashSet<OrganizationStatus>();
	static{
		DEFAULT_ALLOWED_ORGANIZATION_STATUSES.add(OrganizationStatus.ACTIVE);		
	}
	
	static final HashSet<UserStatus> READYFORGENERATION_USER_STATUSES = new HashSet<UserStatus>();
	static{
		ALLOWED_CALLER_STATUSES.add(UserStatus.READYFORGENERATION);		
	}
	
	static final HashSet<UserStatus> ALLOW_ACTIVE_USER_STATUSES = ALLOWED_CALLER_STATUSES;
	
	private WorkerConfig wc;
	private DBManagers db;
	private ProductMapper pMapper;
	
	private BackupRestoreBean testData;
	
	WSRAHelper(WorkerConfig wc, DBManagers db) throws SignServerException{
		this.wc = wc;
		this.db = db;
		this.pMapper = new ProductMapper(db.dbm);
	}
	
	/**
	 * Method that checks that worker setting SELFADMINISTRATION is set
	 * to TRUE and if so that the caller is the owner of the given
	 * certificate
	 * @param caller the caller of WS
	 * @param certificate the certificate to check that the caller owns
	 * @throws AuthorizationDeniedException if the user isn't allowed
	 * to manage the certificate.
	 * @throws IllegalRequestException if the unsupported type of certificate was used.
	 * @throws SignServerException  if internal error happened.
	 */
	void checkRegularUser(UserDataBean caller, ICertificate certificate) throws AuthorizationDeniedException, IllegalRequestException, SignServerException{
		Set<String> callerRoles = caller.getRoles();
		if(callerRoles.contains(Roles.SUPERADMIN)||
		   callerRoles.contains(Roles.MAINADMIN)||
		   callerRoles.contains(Roles.RAADMIN)){
		   return;	
		}
		
		if(callerRoles.contains(Roles.USER)){
			if(wc.getProperty(WSRAConstants.SETTING_SELFADMINISTRATION,WSRAConstants.SETTING_DEFAULT_SELFADMINISTRATION).equalsIgnoreCase("TRUE")){
				if(certificate instanceof org.signserver.validationservice.common.X509Certificate){
					org.signserver.validationservice.common.X509Certificate x509Cert = (org.signserver.validationservice.common.X509Certificate) certificate;
			        CertificateDataBean cdb = db.tm.findCertificate(x509Cert.getSerialNumber().toString(), x509Cert.getIssuer());
			        if(cdb != null){
							TokenDataBean tdb = db.tm.findToken(cdb.getTokenId(), false);
							if(tdb != null){
								 if(tdb.getUserId() != caller.getId()){
									 throw new AuthorizationDeniedException("Error you can only manage your own certificates.");
								 }
							}else{
								throw new IllegalRequestException("Error token containing the certificate couldn't be found in database.");								
							}
			        }else{
			        	throw new IllegalRequestException("Error certificate couldn't be found in database");
			        }
				}else{
					throw new IllegalRequestException("Unsupported certificate type.");
				}
			}else{
				throw new AuthorizationDeniedException("Error insufficient priviledges to revoke certificate.");
			}			
		}else{
			throw new AuthorizationDeniedException("Error insufficient priviledges to revoke certificate.");
		}		
	}
	
	/**
	 * Method that checks that worker setting SELFADMINISTRATION is set
	 * to TRUE and if so that the caller is the owner of the given
	 * token
	 * @param caller the caller of WS
	 * @param tdb the TokenDataBean that should be managed.
	 * @throws AuthorizationDeniedException if the user isn't allowed
	 * to manage the certificate.
	 * @throws IllegalRequestException if the unsupported type of certificate was used.
	 * @throws SignServerException  if internal error happened.
	 */
	void checkRegularUser(UserDataBean caller, TokenDataBean tdb) throws AuthorizationDeniedException, IllegalRequestException, SignServerException{
		Set<String> callerRoles = caller.getRoles();
		if(callerRoles.contains(Roles.SUPERADMIN)||
		   callerRoles.contains(Roles.MAINADMIN)||
		   callerRoles.contains(Roles.SMTPADMIN)||
		   callerRoles.contains(Roles.RAADMIN)){
		   return;	
		}
		
		if(callerRoles.contains(Roles.USER)){
			if(wc.getProperty(WSRAConstants.SETTING_SELFADMINISTRATION,WSRAConstants.SETTING_DEFAULT_SELFADMINISTRATION).equalsIgnoreCase("TRUE")){
				if(tdb != null){
					if(tdb.getUserId() != caller.getId()){
						throw new AuthorizationDeniedException("Error you can only manage your own certificates.");
					}
				}else{
					throw new IllegalRequestException("Error token containing the certificate couldn't be found in database.");								
				}				
			}else{
				throw new IllegalRequestException("Unsupported certificate type.");
			}
		}else{
			throw new AuthorizationDeniedException("Error insufficient priviledges to revoke certificate.");
		}			
	}

	/**
	 * Method that checks that the requested issuer and certificate profile
	 * is among the callers organizations allowed issuers and profiles
	 * @param caller WS caller
	 * @param user the user the request is about
	 * @param tProfile token profile used in the request.
	 * @param issuerDN that should issue a certificate 
	 * @param certReqData the request data.
	 * @throws IllegalRequestException if the request didn't contain valid data.
	 * @throws SignServerException if internal server error
	 */
	ICertRequestData checkValidRequest(UserDataBean caller, UserDataBean user, String tProfile,
			ICertRequestData requestData, ICertRequestData importData) throws IllegalRequestException, SignServerException {
		OrganizationDataBean o = db.om.findOrganization(caller.getOrganizationId());
		
		
		
		if(!o.getAllowedIssuers().contains(requestData.getIssuerDN())){
			throw new IllegalRequestException("Error requested IssuerDN '" + requestData.getIssuerDN() + "' isn't among the callers organizations allowed issuers.");
		}
		
		if(!o.getAllowedCProfiles().contains(requestData.getCertificateProfile().trim())){
			throw new IllegalRequestException("Error requested certificate profile '" + requestData.getCertificateProfile() + "' isn't among the callers organizations allowed certificate profiles.");
		}
		
		if(!o.getAllowedTProfiles().contains(tProfile.trim())){
			throw new IllegalRequestException("Error requested token profile '" + tProfile + "' isn't among the callers organizations allowed token profiles.");
		}
		
		IRequestDataChecker rdc = getRequestDataChecker();
		return rdc.checkRequestData(caller, requestData, importData);
	}

	/**
	 * Method that creates a IRequestDataChecker from setting
	 * REQUESTDATACHECKER in worker configuration.
	 * @return a initialized request data checker.
	 * @throws SignServerException if no REQUESTDATACHECKER is configured.
	 */
	private IRequestDataChecker getRequestDataChecker() throws SignServerException{
		if(requestDataChecker == null){
			String classPath = wc.getProperty(WSRAConstants.SETTING_REQUESTDATACHECKER_CLASSPATH);
			if(classPath == null){
				throw new SignServerException("Error, request data checker not propertly configured, check worker configuration setting "+ WSRAConstants.SETTING_REQUESTDATACHECKER_CLASSPATH);
			}
						
			try {
				Class<?> c = this.getClass().getClassLoader().loadClass(classPath);			
			    IRequestDataChecker o = (IRequestDataChecker) c.newInstance();
			    o.init(wc, db);
			    requestDataChecker = o;
			} catch (ClassNotFoundException e) {
				throw new SignServerException("Error creating request data checker : " + e.getMessage());
			} catch (InstantiationException e) {
				throw new SignServerException("Error creating request data checker : " + e.getMessage());
			} catch (IllegalAccessException e) {
				throw new SignServerException("Error creating request data checker : " + e.getMessage());
			}
		}
		return requestDataChecker;
	}
	
	private IRequestDataChecker requestDataChecker;

	void checkRolesForEdit(Set<String> roles, Set<String> callersRoles) throws AuthorizationDeniedException {
		if(callersRoles.contains(Roles.SUPERADMIN)){
			return;
		}
		if(callersRoles.contains(Roles.MAINADMIN)){
			if(roles.contains(Roles.SUPERADMIN)){
				throw new AuthorizationDeniedException("Error the caller doesn't have enought priviledges to add SUPERADMIN roles");
			}
			return;
		}
		if(callersRoles.contains(Roles.RAADMIN)){
			for(String role : roles){
				if(!role.equals(Roles.USER) && !role.equals(Roles.RAADMIN)){
					throw new AuthorizationDeniedException("Error a RAADMIN can only edit users with role USER and RAADMIN");
				}
			}
		}	
		if(callersRoles.contains(Roles.SMTPADMIN)){
			for(String role : roles){
				if(!role.equals(Roles.SMTPSERVER)){
					throw new AuthorizationDeniedException("Error a SMTPADMIN can only edit users with role SMTPSERVER");
				}
			}
		}
	}
	
	void checkRolesForView(Set<String> roles, Set<String> callersRoles) throws AuthorizationDeniedException {
		if(callersRoles.contains(Roles.SUPERADMIN)){
			return;
		}
		if(callersRoles.contains(Roles.MAINADMIN)){
			if(roles.contains(Roles.SUPERADMIN)){
				throw new AuthorizationDeniedException("Error the caller doesn't have enought priviledges to view SUPERADMIN roles");
			}
			return;
		}
		if(callersRoles.contains(Roles.RAADMIN)){
			for(String role : roles){
				if(!role.equals(Roles.USER) && !role.equals(Roles.RAADMIN) && !role.equals(Roles.SMTPADMIN)){
					throw new AuthorizationDeniedException("Error a RAADMIN can only view users with role USER, RAADMIN, SMTPADMIN");
				}
			}
		}	
		if(callersRoles.contains(Roles.SMTPADMIN)){
			for(String role : roles){
				if(!role.equals(Roles.SMTPSERVER)){
					throw new AuthorizationDeniedException("Error a SMTPADMIN can only view users with role SMTPSERVER");
				}
			}
		}
	}

	/**
	 * Traverses through all a users tokens and sets sensitive data to null
	 * @param udb user data to remove sensitive data from.
	 */
	void removeSensitiveData(UserDataBean udb) {
		if(udb != null && udb.getTokens() != null){
			for(TokenDataBean tdb : udb.getTokens()){
				tdb.setSensitiveData(null);
			}		
		}
	}

	/**
	 * Method that finds the product number that relates
	 * to the input data and adds a transaction for that
	 * product and organization
	 * @throws SignServerException if worker is badly configured
	 * @throws IllegalRequestException if product isn't sold anymore
	 * 
	 */
	void debitEvent(int organizationId, String eventType, String tokenProfile,
			String certificateProfile) throws SignServerException, IllegalRequestException {
		this.debitEvent(organizationId, eventType, tokenProfile, certificateProfile, 1, new Date());
		
	}
	/**
	 * Method that finds the product number that relates
	 * to the input data and adds a transaction for that
	 * product and organization
	 * @throws SignServerException if worker is badly configured
	 * @throws IllegalRequestException if product isn't sold anymore
	 * 
	 */
	void debitEvent(int organizationId, String eventType, String tokenProfile,
			String certificateProfile, int units) throws SignServerException, IllegalRequestException {
		this.debitEvent(organizationId, eventType, tokenProfile, certificateProfile, units, new Date());
		
	}
	
	/**
	 * Method that finds the product number that relates
	 * to the input data and adds a transaction for that
	 * product and organization
	 * @throws SignServerException if worker is badly configured
	 * @throws IllegalRequestException if product isn't sold anymore
	 * 
	 */
	void debitEvent(int organizationId, String eventType, String tokenProfile,
			String certificateProfile, int units, Date expectedLifeTime) throws SignServerException, IllegalRequestException {
		if(useDebiting()){
		  String productNumber =pMapper.getProductNumber(eventType, tokenProfile, certificateProfile);
		  if(productNumber == null){
			  throw new SignServerException("Error product number mapping couldn't be found in worker configuration.");
		  }
		  ProductDataBean product = db.pm.findProduct(productNumber);
		  if(product == null){
			  throw new SignServerException("Error product with product number " + productNumber + " not found in database");
		  }
		  if(!product.getStatus().equals(ProductStatus.SOLD)){
			  throw new IllegalRequestException(" Error product with number : " + productNumber + " is currently not sold");
		  }
		  int productId = product.getId();
		  TransactionDataBean tdb = new TransactionDataBean(organizationId,productId,units,new Date(),expectedLifeTime);
		  db.trm.addTransaction(tdb);
		}
		
	}
	
	
	private boolean useDebiting() throws SignServerException{
		if(useDebiting == null){
			String value = wc.getProperty(WSRAConstants.SETTING_DEBITWSCALLS, WSRAConstants.SETTING_DEFAULT_DEBITWSCALLS); 
			if(value.equalsIgnoreCase("TRUE")){
               useDebiting = true;
			}else if(value.equalsIgnoreCase("FALSE")){
				useDebiting = false;
			}else{
                throw new SignServerException("Error worker configuration setting " + WSRAConstants.SETTING_DEBITWSCALLS +" should be either 'TRUE' of 'FALSE'.");
			}			
		}
		return useDebiting;
	}
	private Boolean useDebiting = null;
	

	public static String formatLog(RequestContext rc , String event, UserDataBean caller, Exception e,
			String formatedMessage, Object... args) {
		
		String time = DateFormat.getDateTimeInstance(DateFormat.LONG, DateFormat.LONG).format(new Date(System.currentTimeMillis()));
		
		String user = caller.getUserName();
		if(rc.get(RequestContext.CLIENT_CERTIFICATE) != null){
			X509Certificate cert = (X509Certificate) rc.get(RequestContext.CLIENT_CERTIFICATE);
			user += " (Certificate " + cert.getSerialNumber().toString(16) + " " + CertTools.getIssuerDN(cert) + ") ";
		}else{
			user += " (No Certificate) ";
		}
		
		if(e != null){	
			if(e.getMessage() != null){
				formatedMessage = formatedMessage.replaceAll("\\%eMsg", e.getClass().getName() + ": " + e.getMessage());
			}else{
				formatedMessage = formatedMessage.replaceAll("\\%eMsg", e.getClass().getName());
			}
		}else{
			formatedMessage = formatedMessage.replaceAll("\\%eMsg", "No Message");
		}
		
		String message = String.format(formatedMessage, args);
		
		String logline = time + ", EVENT : " + event +  ", REQUESTBY : " + user +
		 ", ORGANIZATION ID " + caller.getOrganizationId() + 
         ", MESSAGE : " + message;
		
		return logline;
		
	}
	
	public String formatCertificateForLog(Certificate cert) throws SignServerException{
		String retval = "Unknown certificate serial number";
		java.security.cert.Certificate c;
		try {
			c = cert.getCertificate();
		} catch (CertificateException e) {
			throw new SignServerException(e.getMessage(),e);
		} catch (NoSuchProviderException e) {
			throw new SignServerException(e.getMessage(),e);
		}
		if(c instanceof X509Certificate){
			X509Certificate xc = (X509Certificate) c;			
			retval = xc.getSerialNumber().toString(16) + " " + CertTools.getIssuerDN(xc);								
		}
		
		return retval;
	}
	
	public String formatCertificateForLog(ICertificate cert) throws SignServerException{
		String retval = "Unknown certificate serial number";
		if(cert instanceof X509Certificate){
			X509Certificate xc = (X509Certificate) cert;			
			retval = xc.getSerialNumber().toString(16) + " " + CertTools.getIssuerDN(xc);								
		}
		
		return retval;
	}

	/**
	 * Returns a new generated JKSTokenProfile (or subclass)
	 * 
	 * @param tokenProfile the token profile id
	 * @return a new instance of a JKSTokenProfile
	 * @throws IllegalRequestException if token profile is unsupported.
	 */
	public JKSTokenProfile getSoftTokenProfile(String tokenProfile) throws IllegalRequestException {
		if(tokenProfile.equals(JKSTokenProfile.PROFILEID)){
			return new JKSTokenProfile();
		}
		if(tokenProfile.equals(SMTPTokenProfile.PROFILEID)){
			return new SMTPTokenProfile();
		}
		throw new IllegalRequestException("Unsupported token profile " + tokenProfile);
	}

	public String genUniqueTokenSN(int orgId) throws SignServerException {
		byte[] serno = new byte[7];
		SecureRandom random;
		try {
			random = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			throw new SignServerException("NoSuchAlgorithmException when generating randon number : " + e.getMessage(), e);
		}
		random.setSeed((new Date().getTime()));
		random.nextBytes(serno);
		String tokenSN = new java.math.BigInteger(serno).abs().toString();
		boolean freeSN = false;
		while(!freeSN){			
				if(db.tm.findToken(orgId, tokenSN, false) == null){
                   freeSN=true;
				}else{
					random.nextBytes(serno);
					tokenSN = new java.math.BigInteger(serno).abs().toString();
				}				
		}
		
		return tokenSN;
	}

	/**
	 * Help Method that creates a java.security.cert.Certificate
	 * chain from the CAConnectors certificates.
	 * @param cert
	 * @param cacerts
	 * @return
	 */
	public java.security.cert.Certificate[] genCertificateChain(
			ICertificate cert, List<ICertificate> cacerts) {
		java.security.cert.Certificate[] chain = new java.security.cert.Certificate[cacerts.size() +1];
		if(cert instanceof org.signserver.validationservice.common.X509Certificate){
			chain[0] = (org.signserver.validationservice.common.X509Certificate) cert;	
		}
		int i=1;
		for(ICertificate c : cacerts){
			if(c instanceof org.signserver.validationservice.common.X509Certificate){
				chain[i++] = (org.signserver.validationservice.common.X509Certificate) c;	
			}
		}
		
		return chain;
	}

	/**
	 * Method that checks that the caller
	 * haven't got any of the roles MAINADMIN,RAADMIN or SUPERADMIN
	 * but got SMTPSERVER
	 * @return true if only role is SMTP server
	 */
	public boolean isCallerSMTPServer(UserDataBean caller) {
		Set<String> roles = caller.getRoles();
		if(roles.contains(Roles.SUPERADMIN)){
			return false;
		}
		if(roles.contains(Roles.RAADMIN)){
			return false;
		}
		if(roles.contains(Roles.MAINADMIN)){
			return false;
		}
		return roles.contains(Roles.SMTPSERVER);
	}

	/**
	 * 
	 * @return @return true if only role is regular user
	 */
	public boolean isCallerRegularUser(UserDataBean caller) {
		Set<String> roles = caller.getRoles();
		if(roles.contains(Roles.SUPERADMIN)){
			return false;
		}
		if(roles.contains(Roles.RAADMIN)){
			return false;
		}
		if(roles.contains(Roles.MAINADMIN)){
			return false;
		}
		if(roles.contains(Roles.SMTPSERVER)){
			return false;
		}
		return roles.contains(Roles.USER);
	}
	
    /**
     * Method that checks that the callers status is one of
     * allowedCallerStatus, that organizations status is among
     * allowedOrganizationStatus and that user status is among
     * allowedUserStatus.
     * 
     * @param caller the request caller
     * @param org the users organization
     * @param user the user.
     * @param allowedCallerStatus an set of UserStatus
     * @param allowedOrganizationStatus an set of OrganizationStatus, use null to allow all statuses
     * @param allowedUserStatus an set of UserStatus, use null to allow all statuses
     * @throws IllegalRequestException if org or user status is not among allowed ones..
     * @throws AuthorizationDeniedException if caller status is not among allowed ones.
     */
	void checkStatus(UserDataBean caller, OrganizationDataBean org, UserDataBean user,
			                Set<UserStatus> allowedCallerStatus,
			                Set<OrganizationStatus> allowedOrganizationStatus,
			                Set<UserStatus> allowedUserStatus) throws IllegalRequestException, AuthorizationDeniedException{
		if(!allowedCallerStatus.contains(caller.getStatus())){
			throw new AuthorizationDeniedException("Error caller have an invalid status to perform request, current status is : " + caller.getStatus());
		}
		if(allowedOrganizationStatus != null && !allowedOrganizationStatus.contains(org.getStatus())){
			throw new IllegalRequestException("Error callers organization have an invalid status to perform request, current status of organization is : " + org.getStatus());
		}
		if(allowedUserStatus != null && !allowedUserStatus.contains(user.getStatus())){
			throw new IllegalRequestException("Error user related to request have an invalid status to perform request, current status of user is : " + user.getStatus());
		}		
	}
	
	void insertTestData(WorkerConfig wc, 
	          EntityManager workerEntityManager,
	          Set<Class<?>> availableTokenProfileClasses,
	          Set<Class<?>> availableAuthTypeClasses,
	          ICryptoToken ct,
	          java.security.cert.Certificate workerCertificate,
	          String nodeId){
		
	   if(wc.getProperty(WSRAConstants.SETTING_TESTDATA) != null){		
		   try {			
			DataFileParser dfp = new DataFileParser(wc.getProperty(WSRAConstants.SETTING_TESTDATA));
			testData = dfp.getData();
			DataConfigurationManager dcm = new DataConfigurationManager(wc, 
			          workerEntityManager,
			          availableTokenProfileClasses,
			          availableAuthTypeClasses,
			          ct,
			          workerCertificate,
			          nodeId);
			dcm.storeConfiguration(Type.ALL, testData, true, false);
			log.info("WSRA Test data configured");
		} catch (Exception e) {
			log.error(e);
		}
		   
	   }
	}


    /**
     * Method called from listUsers and that filter
     * out all roles in a search query so only the 
     * callers authorized roles will remain. For
     * instance can a SMTPADMIN only see SMTPSERVERS
     * @param roles requested roles
     * @param caller user calling the method
     * @return filtered set of roles
     */
	public List<String> filterRoles(List<String> roles, UserDataBean caller) {
		Set<String> callerRoles = caller.getRoles();
		if(callerRoles.contains(Roles.SUPERADMIN) ||
		   callerRoles.contains(Roles.MAINADMIN)){
			return roles;
		}
		
		if(roles == null){
			roles = new ArrayList<String>();
			roles.add(Roles.MAINADMIN);
			roles.add(Roles.RAADMIN);
			roles.add(Roles.USER);
			roles.add(Roles.SMTPSERVER);
			roles.add(Roles.SMTPADMIN);
		}
		
		while(roles.contains(Roles.SUPERADMIN)){
			roles.remove(Roles.SUPERADMIN);
		}
		
		if(!callerRoles.contains(Roles.SMTPADMIN)){
			while(roles.contains(Roles.SMTPSERVER)){
				roles.remove(Roles.SMTPSERVER);
			}
		}
				
		if(!callerRoles.contains(Roles.RAADMIN)){
			while(roles.contains(Roles.USER)){
				roles.remove(Roles.USER);
			}
			while(roles.contains(Roles.RAADMIN)){
				roles.remove(Roles.RAADMIN);
			}
			while(roles.contains(Roles.MAINADMIN)){
				roles.remove(Roles.MAINADMIN);
			}

			while(roles.contains(Roles.SMTPADMIN)){
				roles.remove(Roles.SMTPADMIN);
			}
		}
		
		return roles;
	}


}
