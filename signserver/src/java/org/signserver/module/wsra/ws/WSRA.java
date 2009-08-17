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

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebService;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.module.wsra.beans.CertificateDataBean;
import org.signserver.module.wsra.beans.DataBankDataBean;
import org.signserver.module.wsra.beans.OrganizationDataBean;
import org.signserver.module.wsra.beans.TokenDataBean;
import org.signserver.module.wsra.beans.UserDataBean;
import org.signserver.module.wsra.ca.PKCS10CertRequestData;
import org.signserver.module.wsra.ca.UserCertRequestData;
import org.signserver.module.wsra.ca.connectors.AlreadyRevokedException;
import org.signserver.module.wsra.ca.connectors.CAConnectionManager;
import org.signserver.module.wsra.ca.connectors.ICAConnector;
import org.signserver.module.wsra.common.AuthorizationDeniedException;
import org.signserver.module.wsra.common.Roles;
import org.signserver.module.wsra.common.WSRAConstants;
import org.signserver.module.wsra.common.WSRAConstants.UserStatus;
import org.signserver.module.wsra.common.authtypes.IAuthType;
import org.signserver.module.wsra.common.tokenprofiles.ITokenProfile;
import org.signserver.module.wsra.common.tokenprofiles.JKSTokenProfile;
import org.signserver.module.wsra.common.tokenprofiles.SMTPTokenProfile;
import org.signserver.module.wsra.common.tokenprofiles.UserGeneratedTokenProfile;
import org.signserver.module.wsra.core.DBManagers;
import org.signserver.module.wsra.core.UserManager;
import org.signserver.protocol.validationservice.ws.ValidationResponse;
import org.signserver.protocol.ws.Certificate;
import org.signserver.server.annotations.Transaction;
import org.signserver.server.annotations.wsra.AuthorizedRoles;
import org.signserver.server.clusterclassloader.ClusterClassLoader;
import org.signserver.server.genericws.BaseWS;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.Validation;

/**
 * 
 * The WSRA WebService interface implementation.
 * See separate WebMethods for details.
 * 
 * @author Philip Vendil 8 okt 2008
 *
 * @version $Id$
 */

@WebService(targetNamespace="gen.ws.wsra.module.signserver.org")
public class WSRA extends BaseWS   {
	
	
	private static final Logger log = Logger.getLogger(WSRA.class);
	
	private DBManagers db = null;
	private WSRAHelper helper = null;
	
	private Set<Class<?>> availableTokenProfileClasses;
	private Set<Class<?>> availableAuthTypeClasses;

	private String nodeId;
	
	// Contants used for simplified code reading
	protected static final Level DEBUG = Level.DEBUG;
	protected static final Level INFO = Level.INFO;
	protected static final Level WARN = Level.WARN;
	protected static final Level ERROR = Level.ERROR;
	protected static final Level FATAL = Level.FATAL;
	
	protected static final String EVENT_REVOKEUSER = "REVOKE_USER";
	protected static final String EVENT_REVOKECERT = "REVOKE_CERT";
	protected static final String EVENT_REVOKETOKEN = "REVOKE_TOKEN";
	protected static final String EVENT_CERTIFICATEISSUED = "CERTIFICATE_ISSUED";
	protected static final String EVENT_SOFTTOKENISSUED = "SOFTTOKEN_ISSUED";
	protected static final String EVENT_AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED";
	protected static final String EVENT_EDITUSER = "EDIT_USER";
	protected static final String EVENT_CERTSTATUS = "CERT_STATUS";
	protected static final String EVENT_TOKENVIEWED = "TOKEN_VIEWED";
			
	/**
	 * Default constructor
	 */
	public WSRA(){
		super();
		if(getClass().getClassLoader() instanceof ClusterClassLoader){
			ClusterClassLoader ccl = (ClusterClassLoader) getClass().getClassLoader();
	       	availableAuthTypeClasses = ccl.getAllImplementations(IAuthType.class);
	       	availableTokenProfileClasses = ccl.getAllImplementations(ITokenProfile.class);
	       	nodeId = WorkerConfig.getNodeId();
	       	
		}
				
	}
	
	/**
	 * Constructor that only should be used from test scripts.	 
	 */
    WSRA(Set<Class<?>> availableTokenProfileClasses,
    	 Set<Class<?>> availableAuthTypeClasses,
    	 String nodeId){
    	this.availableAuthTypeClasses = availableAuthTypeClasses;
    	this.availableTokenProfileClasses = availableTokenProfileClasses;
    	this.nodeId = nodeId;
    }
   
	
    // 3. CryptoToken refactoren
    
    /**
     * Method used to list a set of users that exists in the callers
     * organization.
     * 
     * @param a list of roles that the user must be a member in at least
     * one of them. null value returns all users i organization (use with care).
     * @return a list of users with the specified roles that is in the
     * callers organization
     */
	@WebMethod
	@Transaction
	@AuthorizedRoles({Roles.RAADMIN, Roles.MAINADMIN, Roles.SMTPADMIN})	
	public List<UserDataBean> listUsers(@WebParam(name="roles")List<String> roles) throws IllegalRequestException, SignServerException, AuthorizationDeniedException{
		log.debug(">listUsers called ");
		UserDataBean caller = initMethod();
	   
		OrganizationDataBean org = db.om.findOrganization(caller.getOrganizationId());
		helper.checkStatus(caller, org, null, WSRAHelper.ALLOWED_CALLER_STATUSES, WSRAHelper.DEFAULT_ALLOWED_ORGANIZATION_STATUSES, null);
		
		List<UserDataBean> result = new ArrayList<UserDataBean>();
		
		roles = helper.filterRoles(roles,caller);
		
		if(roles != null){	
			Set<UserDataBean> set = new HashSet<UserDataBean>();
			for(String role : roles){
				set.addAll(db.um.listUsers(caller.getOrganizationId(), role));
			}
			result.addAll(set);
		}else{
			result = db.um.listUsers(caller.getOrganizationId(), null);
		}
		
		for(UserDataBean udb : result){
			helper.removeSensitiveData(udb);
		}
		
	   
		log.debug("<listUsers found " + result.size() + " users");
	   return result;
	}
	


	/**
	 * Method used to add/edit a user to the system.
	 * The user added will belong to the same organization as the
	 * caller.
	 * @param userData the user data to add or edit. Username field should be unique.
	 * @throws IllegalRequestException if the request contained illegal data.
	 * @throws SignServerException if internal server exception occurred.
	 * @throws AuthorizationDeniedException if the user doesn't have
	 * sufficient privileges to add the user data.
	 */
	@WebMethod
	@AuthorizedRoles({Roles.RAADMIN, Roles.MAINADMIN, Roles.SMTPADMIN})
	@Transaction
	public void editUsers(@WebParam(name="userData")UserDataBean userData) throws IllegalRequestException, SignServerException, AuthorizationDeniedException{
		log.debug(">editUser called, username : " + userData.getUserName());
		UserDataBean caller = initMethod();
	   
		try{
			OrganizationDataBean org = db.om.findOrganization(caller.getOrganizationId());
			helper.checkStatus(caller, org, null, WSRAHelper.ALLOWED_CALLER_STATUSES, WSRAHelper.DEFAULT_ALLOWED_ORGANIZATION_STATUSES, null);			
			helper.checkRolesForEdit(userData.getRoles(),caller.getRoles());

			userData.setOrganizationId(caller.getOrganizationId());
			db.um.editUser(userData);

			log(INFO,EVENT_EDITUSER,caller,"Successfully edited user : %s ", userData.getUserName());
			log.debug("<editUser " + userData.getUserName() + " finished");
		}catch(Exception e){
			log(ERROR,EVENT_EDITUSER,caller,e,"Error occured when editing user : %s , message : %eMsg",userData.getUserName());
		}
				
	}
	
	/**
	 * Method used to find users by it's alias.
	 * 
	 * @param matchType either "EQUALS" or "CONTAINS", see WSRAConstants.MATCHTYPE_ constants
	 * @param aliasType custom defined alias type
	 * @param alias value to search for
	 * @return a list of users that matches the criteria, never null.
	 * @throws IllegalRequestException if the request contained illegal data.
	 * @throws SignServerException if internal server exception occurred.
	 * @throws AuthorizationDeniedException if the user doesn't have
	 * sufficient privileges to add the user data.
	 */
	@WebMethod
	@Transaction
	@AuthorizedRoles({Roles.RAADMIN, Roles.MAINADMIN, Roles.SMTPSERVER})	
	public List<UserDataBean> findUsersByAlias(@WebParam(name="matchType")String matchType, @WebParam(name="aliasType")String aliasType, @WebParam(name="alias")String alias) throws IllegalRequestException, SignServerException, AuthorizationDeniedException{
		log.debug(">findUsersByAlias called");
		UserDataBean caller = initMethod();
		
		OrganizationDataBean org = db.om.findOrganization(caller.getOrganizationId());
		helper.checkStatus(caller, org, null, WSRAHelper.ALLOWED_CALLER_STATUSES, WSRAHelper.DEFAULT_ALLOWED_ORGANIZATION_STATUSES, null);
		
		List<UserDataBean> retval;
		if(matchType.equalsIgnoreCase(WSRAConstants.MATCHTYPE_EQUALS)){
			retval = db.um.findUserByAlias(caller.getOrganizationId(), aliasType, alias);
		}else{
			retval = db.um.findUserLikeAlias(caller.getOrganizationId(), aliasType, alias);
		}

		for(UserDataBean udb : retval){
			helper.checkRolesForView(udb.getRoles(),caller.getRoles());
			helper.removeSensitiveData(udb);
		}
		log.debug("<findUsersByAlias");
		return retval;
	}
	
	/**
	 * Method used to find a user in the callers organization.
	 *  
	 * @param username of the user to search for
	 * @return the related user data or null if no user with given user name found
	 * in organization.
	 * @throws IllegalRequestException if the request contained illegal data.
	 * @throws SignServerException if internal server exception occurred.
	 * @throws AuthorizationDeniedException if the user doesn't have
	 * sufficient privileges to view the user data.
	 */
	@WebMethod
	@Transaction
	@AuthorizedRoles({Roles.RAADMIN, Roles.MAINADMIN, Roles.SMTPADMIN, Roles.SMTPSERVER})	
	public UserDataBean findUserByUsername(@WebParam(name="username")String username) throws IllegalRequestException, SignServerException, AuthorizationDeniedException{
		log.debug(">findUserByUsername called, username : " + username);
		UserDataBean caller = initMethod();
		OrganizationDataBean org = db.om.findOrganization(caller.getOrganizationId());
		helper.checkStatus(caller, org, null, WSRAHelper.ALLOWED_CALLER_STATUSES, WSRAHelper.DEFAULT_ALLOWED_ORGANIZATION_STATUSES, null);
		
		UserDataBean retval = db.um.findUser(username, caller.getOrganizationId());
		if(retval != null){
		  helper.checkRolesForView(retval.getRoles(),caller.getRoles());
		}
		helper.removeSensitiveData(retval);
		log.debug("<findUserByUsername, username : " + username);
		return retval;
	}
	
	/**
	 * Method used to issue a custom user generated certificate
	 * for a token not known by the system. All certificates will be stored
	 * on with UserGeneratedTokenProfile and token serial number "USERGENERATED"
	 *  
	 * @param username of the user to search for
	 * @return a Base64 encoded certificate of the type specified in the request.
	 * @throws IllegalRequestException if the request contained illegal data.
	 * @throws SignServerException if internal server exception occurred.
	 * @throws AuthorizationDeniedException if the user doesn't have
	 * sufficient privileges to add the user data.
	 */
	@WebMethod
	@AuthorizedRoles({Roles.RAADMIN, Roles.MAINADMIN, Roles.SMTPADMIN})
	@Transaction
	public Certificate generateCertificateFromPKCS10(@WebParam(name="username")String username,
			                          @WebParam(name="pkcs10ReqData")PKCS10CertRequestData pkcs10ReqData,
			                          @WebParam(name="tokenSN")String tokenSN) throws IllegalRequestException, SignServerException, AuthorizationDeniedException{
		log.debug(">generateCertificate called, username : " + username);
		UserDataBean caller = initMethod();
		try{
		
			UserDataBean user = db.um.findUser(username, caller.getOrganizationId());
			if(user == null){
				throw new IllegalRequestException("Error username : " + username + " doesn't exists in organization");
			}		
			
			OrganizationDataBean org = db.om.findOrganization(caller.getOrganizationId());
			helper.checkStatus(caller, org, user, WSRAHelper.ALLOWED_CALLER_STATUSES, WSRAHelper.DEFAULT_ALLOWED_ORGANIZATION_STATUSES, WSRAHelper.ALLOW_ACTIVE_USER_STATUSES);
            helper.checkRolesForEdit(user.getRoles(), caller.getRoles());
			helper.checkValidRequest(caller,user, UserGeneratedTokenProfile.PROFILEID, pkcs10ReqData,null);

			try{
				String tsn = tokenSN;
				if(tsn== null){
					tsn = WSRAConstants.USERGENERATED_TOKENSERIALNUMBER + username;
				}

				TokenDataBean tdb = db.tm.findToken(caller.getOrganizationId(), tsn, false);

				if(tdb != null && tdb.getUserId() != user.getId()){
					throw new IllegalRequestException("Error, the specified token already exists and doesn't belong to the specified user.");
				}

				ICertificate cert = getCAConnector(pkcs10ReqData.getIssuerDN()).requestCertificate(pkcs10ReqData);		

				user.setPassword(null);
				user.setStatus(WSRAConstants.UserStatus.GENERATED);
				db.um.editUser(user);

				if(tdb == null){
					tdb = new TokenDataBean(caller.getOrganizationId(),user.getId(),UserGeneratedTokenProfile.PROFILEID,tsn);
					CertificateDataBean cdb = new CertificateDataBean(cert, 0,pkcs10ReqData.getCertificateProfile());
					ArrayList<CertificateDataBean> certs = new ArrayList<CertificateDataBean>();
					certs.add(cdb);
					tdb.setCertificates(certs);
					db.tm.editToken(tdb);
				}else{
					CertificateDataBean cdb = new CertificateDataBean(cert, tdb.getId(),pkcs10ReqData.getCertificateProfile());
					db.tm.editCertificate(cdb);
				}


				Certificate retval = new Certificate();
				retval.setCertificateBase64(new String(Base64.encode(cert.getEncoded())));

				helper.debitEvent(caller.getOrganizationId(), WSRAConstants.DEBITEVENT_GENCERT,tdb.getProfile(),pkcs10ReqData.getCertificateProfile());
				log(INFO,EVENT_CERTIFICATEISSUED,caller,"Successfully generated certificate : %s from pkcs10 for user : %s.", helper.formatCertificateForLog(retval),username);
				log.debug("<generateCertificate, username : " + username);
				return retval;
			}catch(CertificateEncodingException e){
				throw new SignServerException("Error encoding generated certificate : " + e.getMessage(),e);
			} 
		}catch(Exception e){
			log(ERROR,EVENT_CERTIFICATEISSUED,caller,e,"Error occured when generating certificate from pkcs10 for user : %s , message : %eMsg",username);
			return null;// should never happen.
		}
	}
	
	/**
	 * Method to server generate a soft token.
	 * 
	 * @param username of the user to generate token for
	 * @param password to lock the generated key store with.
	 * @param request a list of UserCertRequestData requests with name (alias) and key specification set.
	 * @param tokenProfile requested token profile
	 * @param tokenSN requested token SN, use null to let the server generate a unique tokenSN
	 * @param overwriteExisting set to true if existing token with the same SN should be over written.
	 * @throws IllegalRequestException if the request contained illegal data.
	 * @throws SignServerException if internal server exception occurred.
	 * @throws AuthorizationDeniedException if the user doesn't have
	 * sufficient privileges to add the user data.
	 */
	@WebMethod
	@AuthorizedRoles({Roles.RAADMIN, Roles.MAINADMIN, Roles.SMTPADMIN, Roles.SMTPSERVER})	
	@Transaction
	public TokenDataBean generateSoftToken(@WebParam(name="username")String username,
			                        @WebParam(name="password")String password,
			                        @WebParam(name="requests")List<UserCertRequestData> requests,
			                        @WebParam(name="tokenProfile")String tokenProfile,
			                        @WebParam(name="tokenSN")String tokenSN, 
			                        @WebParam(name="overwriteExisting")boolean overwriteExisting) throws IllegalRequestException, SignServerException, AuthorizationDeniedException{
		log.debug(">generateSoftToken called, username : " + username);
		UserDataBean caller = initMethod();
		try{
			UserDataBean user = db.um.findUser(username, caller.getOrganizationId());
			if(user == null){
				throw new IllegalRequestException("Error username : " + username + " doesn't exists in organization");
			}
			
			OrganizationDataBean org = db.om.findOrganization(caller.getOrganizationId());
			helper.checkStatus(caller, org, user, WSRAHelper.ALLOWED_CALLER_STATUSES, WSRAHelper.DEFAULT_ALLOWED_ORGANIZATION_STATUSES, WSRAHelper.ALLOW_ACTIVE_USER_STATUSES);
			helper.checkRolesForEdit(user.getRoles(), caller.getRoles());
			
			if(helper.isCallerSMTPServer(caller)){
				if(!tokenProfile.equals(SMTPTokenProfile.PROFILEID)){
					throw new IllegalRequestException("Error SMTP Servers are only allowed to generate tokens with " + SMTPTokenProfile.PROFILEID);
				}
			}

			TokenDataBean existingTokenData = null;		
			if(tokenSN == null){
				tokenSN = helper.genUniqueTokenSN(caller.getOrganizationId());
			}else{
				existingTokenData = db.tm.findToken(caller.getOrganizationId(), tokenSN, false);
				if(existingTokenData != null && !overwriteExisting){
					throw new IllegalRequestException("Token " + tokenSN + " already exists in organization");
				}

				if(existingTokenData != null && existingTokenData.getUserId() != user.getId()){
					throw new IllegalRequestException("Error, the specified token already exists and doesn't belong to the specified user.");
				}
			}

			JKSTokenProfile tProfile = helper.getSoftTokenProfile(tokenProfile);

			tProfile.init(password);
			KeyStore ks = tProfile.getKeyStore();

			List<CertificateDataBean> tokenCerts = new ArrayList<CertificateDataBean>();

			for(UserCertRequestData ucrd : requests){
				ucrd = (UserCertRequestData) helper.checkValidRequest(caller,user, tokenProfile, ucrd,null);

				if(ucrd.getKeySpec() == null || ucrd.getKeyAlg() == null){
					throw new IllegalRequestException("Error key specification and key algorithm must be specified in request data.");
				}
				if(ucrd.getName() == null){
					throw new IllegalRequestException("Request (alias) name must be specified.");
				}

				try{
					KeyPair keys = KeyTools.genKeys(ucrd.getKeySpec(), ucrd.getKeyAlg());
					List<ICertificate> cacerts = getCAConnector(ucrd.getIssuerDN()).getCACertificateChain(ucrd.getIssuerDN());
					ucrd.setPublicKey(keys.getPublic());
					ICertificate cert = getCAConnector(ucrd.getIssuerDN()).requestCertificate(ucrd);
					tokenCerts.add(new CertificateDataBean(cert, 0,ucrd.getCertificateProfile()));
					ks.setKeyEntry(ucrd.getName(), keys.getPrivate(), password.toCharArray(), helper.genCertificateChain(cert,cacerts));
					log(INFO,EVENT_CERTIFICATEISSUED,caller,"Successfully generated certificate : %s for token with serial %s and user : %s.", helper.formatCertificateForLog(cert),tokenSN,username);
				}catch (NoSuchAlgorithmException e) {
					throw new IllegalRequestException("Unsupported key algorithm in request " + ucrd.getKeyAlg());
				} catch (NoSuchProviderException e) {
					throw new SignServerException("Key store provider not found",e);
				} catch (InvalidAlgorithmParameterException e) {
					throw new IllegalRequestException("Unsupported key specification in request " + ucrd.getKeySpec());
				} catch (CertificateEncodingException e) {
					throw new SignServerException("Certificate encoding error."+ e.getMessage(),e);
				} catch (KeyStoreException e) {
					throw new SignServerException("Error in keystore "+ e.getMessage(),e);
				}
			}
			user.setPassword(null);
			user.setStatus(WSRAConstants.UserStatus.GENERATED);
			db.um.editUser(user);

			if(existingTokenData != null){
				db.tm.removeToken(existingTokenData.getId());
			}

			existingTokenData = new TokenDataBean(caller.getOrganizationId(),user.getId(),tProfile.getProfileIdentifier(),tokenSN);					
			existingTokenData.setCertificates(tokenCerts);
			if(tProfile.storeSensitiveData()){
				existingTokenData.setSensitiveData(JKSTokenProfile.serializeKeyStore(ks, password));
			}
			db.tm.editToken(existingTokenData);

			TokenDataBean retval;
			if(tProfile.storeSensitiveData()){
				retval = existingTokenData;	
			}else{
				retval = new TokenDataBean(caller.getOrganizationId(),user.getId(),tProfile.getProfileIdentifier(),tokenSN);
				retval.setCertificates(tokenCerts);
				retval.setSensitiveData(JKSTokenProfile.serializeKeyStore(ks, password));				
			}
			helper.debitEvent(caller.getOrganizationId(), WSRAConstants.DEBITEVENT_GENCERT,existingTokenData.getProfile(),null);
			if(overwriteExisting){
			  log(INFO,EVENT_SOFTTOKENISSUED,caller,"Successfully generated soft token with : %s for user : %s.", tokenSN,username);
			}else{
			  log(INFO,EVENT_SOFTTOKENISSUED,caller,"Successfully generated soft token with : %s, existing token was over written for user : %s.", tokenSN,username);
			}
			log.debug("<generateCertificate, username : " + username);
			return retval;

		}catch(Exception e){
			log(ERROR,EVENT_SOFTTOKENISSUED,caller,e,"Error occured when generating soft token for user : %s , message : %eMsg",username);
			return null;// should never happen.
		}
	}
	
	/**
	 * Method used check the current status of a certificate.
	 *  
	 * @param certificate the certificate to check
	 * @return A ValidationResponse object containing the current status of the certificate.
	 * @throws IllegalRequestException if the request contained illegal data.
	 * @throws SignServerException if internal server exception occurred.
	 * @throws AuthorizationDeniedException if the user doesn't have
	 * sufficient privileges to add the user data.
	 */
	@WebMethod
	@Transaction
	public ValidationResponse checkCertStatus(@WebParam(name="certificate")Certificate certificate) throws IllegalRequestException, SignServerException, AuthorizationDeniedException{
		log.debug(">checkCertStatus called ");
		UserDataBean caller = initMethod();
		OrganizationDataBean o = db.om.findOrganization(caller.getOrganizationId());
		helper.checkStatus(caller, o, null, WSRAHelper.ALLOWED_CALLER_STATUSES, WSRAHelper.DEFAULT_ALLOWED_ORGANIZATION_STATUSES, null);

		try{
			ICertificate certToCheck = null;
			try{
				java.security.cert.Certificate c = certificate.getCertificate();
				if(c instanceof java.security.cert.X509Certificate){
					certToCheck = org.signserver.validationservice.common.X509Certificate.getInstance((X509Certificate) c);
				}
			}catch(NoSuchProviderException e){
				throw new IllegalRequestException("Error when decoding certificate, provider couldn't be found.");
			} catch (CertificateException e) {
				throw new SignServerException("Error when decoding certificate : " + e.getMessage(),e);
			} catch (IOException e) {
				throw new SignServerException("Error when decoding certificate : " + e.getMessage(),e);
			}

			if(certToCheck == null){
				throw new IllegalRequestException("Error, unsupported certificate type");
			}

			Validation v = getCAConnector(certToCheck.getIssuer()).getCertificateStatus(certToCheck);
			if(v == null){
				throw new IllegalRequestException("Error, given certificate not found for issuer " + certToCheck.getIssuer());
			}

			log(INFO,EVENT_CERTSTATUS,caller,"Certificate status of certificate checked : %s , status : %s",helper.formatCertificateForLog(certificate),v.getStatus().toString());
			log.debug("<checkCertStatus called ");
			return new ValidationResponse(v,null);
		}catch(Exception e){
			log(ERROR,EVENT_CERTSTATUS,caller,e,"Error occured when checking certificate status of certificate : %s , message : %eMsg",helper.formatCertificateForLog(certificate));
			return null; // Should never happen.
		}
	}
	
	/**
	 * Method used to revoke a certificate, can be used by RAADMIN and
	 * MAINADMIN, and by regular USER if SELFADMINISTRATION is set to true.
	 * 
	 * A User can only revoke his own certificates.
	 * 
	 * @param certificate certificate to revoke
	 * @param reason revocation reason.
	 * @throws IllegalRequestException if the request contained illegal data.
	 * @throws SignServerException if internal server exception occurred.
	 * @throws AuthorizationDeniedException if the user doesn't have
	 * sufficient privileges to add the user data.
	 */
	@WebMethod
	@AuthorizedRoles({Roles.RAADMIN, Roles.MAINADMIN, Roles.USER})	
	@Transaction
	public void revokeCertificate(@WebParam(name="certificate")Certificate certificate, @WebParam(name="revocationReason")int reason) throws IllegalRequestException, SignServerException, AuthorizationDeniedException{
		log.debug(">revokeCertificate called ");
		UserDataBean caller = initMethod();	
		OrganizationDataBean o = db.om.findOrganization(caller.getOrganizationId());
		helper.checkStatus(caller, o, null, WSRAHelper.ALLOWED_CALLER_STATUSES, WSRAHelper.DEFAULT_ALLOWED_ORGANIZATION_STATUSES, null);

		try{
			ICertificate certToCheck = null;
			try{
				java.security.cert.Certificate c = certificate.getCertificate();
				if(c instanceof java.security.cert.X509Certificate){
					certToCheck = org.signserver.validationservice.common.X509Certificate.getInstance((X509Certificate) c);
				}
			}catch(NoSuchProviderException e){
				throw new IllegalRequestException("Error when decoding certificate, provider couldn't be found.");
			} catch (CertificateException e) {
				throw new SignServerException("Error when decoding certificate : " + e.getMessage(),e);
			} catch (IOException e) {
				throw new SignServerException("Error when decoding certificate : " + e.getMessage(),e);
			}

			if(certToCheck == null){
				throw new IllegalRequestException("Error, unsupported certificate type");
			}

			helper.checkRegularUser(caller, certToCheck);

			getCAConnector(certToCheck.getIssuer()).revokeCertificate(certToCheck, reason);
			log(INFO,EVENT_REVOKECERT,caller,"Certificate : %s revoked successfully",helper.formatCertificateForLog(certificate));
		}catch (Exception e) {
			log(ERROR,EVENT_REVOKECERT,caller,e,"Error occured when revoking certificate : %s , message : %eMsg",helper.formatCertificateForLog(certificate));
		}
        log.debug("<revokeCertificate called ");
	}
	
	/**
	 * Method used to revoke a token, i.e all certificate on a token, can be used by RAADMIN and
	 * MAINADMIN, and by regular USER if SELFADMINISTRATION is set to true.
	 * 
	 * A User can only revoke his own tokens.
	 * 
	 * @param tokenSerialNumber serial number of token to revoke
	 * @param reason revocation reason.
	 * @throws IllegalRequestException if the request contained illegal data.
	 * @throws SignServerException if internal server exception occurred.
	 * @throws AuthorizationDeniedException if the user doesn't have
	 * sufficient privileges to add the user data.
	 */
	@WebMethod
	@AuthorizedRoles({Roles.RAADMIN, Roles.MAINADMIN, Roles.USER, Roles.SMTPADMIN})	
	@Transaction
	public void revokeToken(@WebParam(name="tokenSerialNumber")String tokenSerialNumber, @WebParam(name="revocationReason")int reason) throws IllegalRequestException, SignServerException, AuthorizationDeniedException{
		log.debug(">revokeToken called ");
		UserDataBean caller = initMethod();
		OrganizationDataBean o = db.om.findOrganization(caller.getOrganizationId());
		helper.checkStatus(caller, o, null, WSRAHelper.ALLOWED_CALLER_STATUSES, WSRAHelper.DEFAULT_ALLOWED_ORGANIZATION_STATUSES, null);
		
		try{		
			try{
				TokenDataBean tdb = db.tm.findToken(caller.getOrganizationId(), tokenSerialNumber, false);

				if(tdb == null){
					throw new IllegalRequestException("Error, token serial number couldn't be found in database.");
				}
				
				UserDataBean udb = db.um.findUser(tdb.getUserId());

				helper.checkRegularUser(caller, tdb);
				helper.checkRolesForEdit(udb.getRoles(), caller.getRoles());

				for(CertificateDataBean cdb : tdb.getCertificates()){
					try{
					  getCAConnector(cdb.getIssuerDN()).revokeCertificate(cdb.getCertificate(), reason);
					  log(INFO,EVENT_REVOKECERT,caller,"Certificate : %s revoked successfully",helper.formatCertificateForLog(cdb.getCertificate()));
					}catch(AlreadyRevokedException e){
						log(ERROR,EVENT_REVOKECERT,caller,e,"Error occured when revoking certificate : %s , message : %eMsg",helper.formatCertificateForLog(cdb.getCertificate()));
					}
				}

				log(INFO,EVENT_REVOKETOKEN,caller,"Token : %s revoked successfully.",tokenSerialNumber);
			} catch (CertificateException e) {
				throw new SignServerException("Internal error when decoding certificate from database.");
			} catch (IOException e) {
				throw new SignServerException("Internal error when fetching data from database.");
			}
			log.debug("<revokeToken called ");
		}catch (Exception e) {
			log(ERROR,EVENT_REVOKETOKEN,caller,e,"Error occured when revoking token : %s , message : %eMsg",tokenSerialNumber);
		}
	}
	
	/**
	 * Method used to revoke a users all certificates.
	 * 
	 * 
	 * @param userName to revoke
	 * @param reason revocation reason.
	 * @param newUserStatus one of WSRAConstants.USERSTATUS_ constants
	 * @throws IllegalRequestException if the request contained illegal data.
	 * @throws SignServerException if internal server exception occurred.
	 * @throws AuthorizationDeniedException if the user doesn't have
	 * sufficient privileges to add the user data.
	 */
	@WebMethod
	@AuthorizedRoles({Roles.RAADMIN, Roles.MAINADMIN, Roles.SMTPADMIN})
	@Transaction
	public void revokeUser(@WebParam(name="userName")String userName, @WebParam(name="revocationReason")int reason, @WebParam(name="newUserStatus")UserStatus newUserStatus) throws IllegalRequestException, SignServerException, AuthorizationDeniedException{
		log.debug(">revokeUser called ");
		
		UserDataBean caller = initMethod();
		OrganizationDataBean o = db.om.findOrganization(caller.getOrganizationId());
		helper.checkStatus(caller, o, null, WSRAHelper.ALLOWED_CALLER_STATUSES, WSRAHelper.DEFAULT_ALLOWED_ORGANIZATION_STATUSES, null);
		
		try{
			try{
				UserDataBean udb = db.um.findUser(userName, caller.getOrganizationId());

				if(udb == null){
					throw new IllegalRequestException("Error, user couldn't be found in database.");
				}
				
				helper.checkRolesForEdit(udb.getRoles(), caller.getRoles());

				for(TokenDataBean tdb : udb.getTokens()){
					for(CertificateDataBean cdb : tdb.getCertificates()){
						try{
						  getCAConnector(cdb.getIssuerDN()).revokeCertificate(cdb.getCertificate(), reason);
						  log(INFO,EVENT_REVOKECERT,caller,"Certificate : %s revoked successfully",helper.formatCertificateForLog(cdb.getCertificate()));						  
						}catch(AlreadyRevokedException e){}
					}
				}

				udb.setStatus(newUserStatus);
				db.um.editUser(udb);

				log(INFO,EVENT_REVOKEUSER,caller,"Successfully revoked user : %s , reason : %d",userName,reason);
			} catch (CertificateException e) {
				throw new SignServerException("Internal error when decoding certificate from database.");
			} catch (IOException e) {
				throw new SignServerException("Internal error when fetching data from database.");
			}
			log.debug("<revokeUser called ");
		}catch (Exception e) {
			log(ERROR,EVENT_REVOKEUSER,caller,e,"Error occured when revoking user : %s , message : %eMsg",userName);
		}
	}
	
	/**
	 * Method used to fetch the data of a token in the system.
	 * 
	 * SMTPServers can only fetch tokens with SMTPTokenProfiles
	 * and regular users can only view non-sensitive information
	 * about their own tokens. 
	 * 
	 * @param tokenSerialNumber token serial number
	 * @param includeSensitiveData if sensitive data such as key store for soft tokens or PIN/PUK data 
	 * for hard tokens. 
	 * @throws IllegalRequestException if the request contained illegal data.
	 * @throws SignServerException if internal server exception occurred.
	 * @throws AuthorizationDeniedException if the user doesn't have
	 * sufficient privileges to add the user data.
	 */
	@WebMethod
	@Transaction
	@AuthorizedRoles({Roles.RAADMIN, Roles.MAINADMIN, Roles.SMTPADMIN, Roles.SMTPSERVER, Roles.USER})	
	public TokenDataBean getTokenData(@WebParam(name="tokenSerialNumber")String tokenSerialNumber, @WebParam(name="includeSensitiveData") boolean includeSensitiveData) throws IllegalRequestException, SignServerException, AuthorizationDeniedException{
		log.debug(">getTokenData called ");

		UserDataBean caller = initMethod();
		try{

			TokenDataBean tdb = db.tm.findToken(caller.getOrganizationId(),tokenSerialNumber, includeSensitiveData);
			if(tdb == null){
				throw new IllegalRequestException("token with serial " + tokenSerialNumber + " not found in database");
			}
			
			OrganizationDataBean o = db.om.findOrganization(caller.getOrganizationId());
			UserDataBean user = db.um.findUser(tdb.getUserId());
			helper.checkStatus(caller, o, user, WSRAHelper.ALLOWED_CALLER_STATUSES, WSRAHelper.DEFAULT_ALLOWED_ORGANIZATION_STATUSES, WSRAHelper.ALLOW_ACTIVE_USER_STATUSES);
			helper.checkRolesForView(user.getRoles(),caller.getRoles());
			
			if(helper.isCallerSMTPServer(caller)){
				if(!tdb.getProfile().equals(SMTPTokenProfile.PROFILEID)){
					throw new IllegalRequestException("Error SMTP Servers are only allowed to fetch tokens with SMTPTokenProfile");
				}
			}
			if(helper.isCallerRegularUser(caller)){
				if(includeSensitiveData){
					throw new IllegalRequestException("Regular users aren't allowed to see the sensitive data of token.");
				}
				if(tdb.getUserId() != caller.getId()){
					throw new IllegalRequestException("Regular users can only view their own tokens.");
				}
			}

			if(includeSensitiveData){
			  log(INFO,EVENT_TOKENVIEWED,caller,"Successfully sent token data with serial : %s , containing sensitive information.",tokenSerialNumber);
			}

			log.debug("<getTokenData called ");
			return tdb;
		}catch (Exception e) {			
			log(ERROR,EVENT_TOKENVIEWED,caller,e,"Error occured when viewing token data with serial : %s , message : %eMsg",tokenSerialNumber);
			return null;// Should never happen.
		}
	}
	
	/**
	 * Method to see if a token exists for the
	 * callers organization. 
	 * 
	 * @param tokenSerialNumber token serial number
	 * @return true if the token with serial exists.
	 * @throws IllegalRequestException if the request contained illegal data.
	 * @throws SignServerException if internal server exception occurred.
	 * @throws AuthorizationDeniedException if the user doesn't have
	 * sufficient privileges to add the user data.
	 */
	@WebMethod	
	@Transaction
	public boolean existsToken(@WebParam(name="tokenSerialNumber")String tokenSerialNumber) throws IllegalRequestException, SignServerException, AuthorizationDeniedException{
		log.debug(">existsToken " + tokenSerialNumber + " called ");

		UserDataBean caller = initMethod();
		OrganizationDataBean o = db.om.findOrganization(caller.getOrganizationId());
		helper.checkStatus(caller, o, null, WSRAHelper.ALLOWED_CALLER_STATUSES, WSRAHelper.DEFAULT_ALLOWED_ORGANIZATION_STATUSES, null);
		TokenDataBean tdb = db.tm.findToken(caller.getOrganizationId(),tokenSerialNumber, false);
		
		log.debug("<existsToken  " + tokenSerialNumber + " : " + tdb != null);
		return tdb != null;
	}
	
	/**
	 * Method to retrieve UserData of the caller.
	 * 
	 * @return the UserDataBean of the caller or null if the caller doesn't exist.
	 * @throws IllegalRequestException if the request contained illegal data.
	 * @throws SignServerException if internal server exception occurred.
	 * @throws AuthorizationDeniedException if the user doesn't have
	 * sufficient privileges to add the user data.
	 */
	@WebMethod	
	@Transaction
	public UserDataBean getCallerUserData() throws IllegalRequestException, SignServerException, AuthorizationDeniedException{
		log.debug(">getCallerUserData called ");

		UserDataBean caller = initMethod();
		if(caller.equals(UserManager.NO_USER)){
			return null;
		}
		OrganizationDataBean o = db.om.findOrganization(caller.getOrganizationId());
		helper.checkStatus(caller, o, null, WSRAHelper.ALLOWED_CALLER_STATUSES, WSRAHelper.DEFAULT_ALLOWED_ORGANIZATION_STATUSES, null);
				
		log.debug("<getCallerUserData");
		return db.um.findUser(caller.getId());
	}
	
	/**
	 * Method to retrieve callers organization data
	 * 
	 * @return the OrganizationDataBean (no related users) of the caller or null if the caller doesn't exist.
	 * @throws IllegalRequestException if the request contained illegal data.
	 * @throws SignServerException if internal server exception occurred.
	 * @throws AuthorizationDeniedException if the user doesn't have
	 * sufficient privileges to add the user data.
	 */
	@WebMethod	
	@Transaction
	public OrganizationDataBean getCallerOrganizationData() throws IllegalRequestException, SignServerException, AuthorizationDeniedException{
		log.debug(">getCallerOrganizationData called ");

		UserDataBean caller = initMethod();
		if(caller.equals(UserManager.NO_USER)){
			return null;
		}
		OrganizationDataBean o = db.om.findOrganization(caller.getOrganizationId());
		helper.checkStatus(caller, o, null, WSRAHelper.ALLOWED_CALLER_STATUSES, WSRAHelper.DEFAULT_ALLOWED_ORGANIZATION_STATUSES, null);
		List<DataBankDataBean> related = db.dbm.getRelatedProperies(WSRAConstants.DATABANKTYPE_ORGANIZATION, o.getId());
		if(related != null){
			related.size();
		}
		o.setRelatedData(related);
		if(o.getProducts() != null){
			o.getProducts().size();
		}
		o.setUsers(null);
	
		
		log.debug("<getCallerOrganizationData");
		return o;
	}
	
	
	/**
	 * Method to retrieve and issuers certificate chain (ie CA Chain) 
	 * @return the OrganizationDataBean (no related users) of the caller or null if the caller doesn't exist.
	 * @throws IllegalRequestException if the request contained illegal data.
	 * @throws SignServerException if internal server exception occurred.
	 * @throws AuthorizationDeniedException if the user doesn't have
	 * sufficient privileges to add the user data.
	 */
	@WebMethod	
	@Transaction
	public List<Certificate> getCACertificateChain(String issuerDN) throws IllegalRequestException, SignServerException, AuthorizationDeniedException{
		log.debug(">getCACertificateChain called :" +issuerDN);

		UserDataBean caller = initMethod();
		if(caller.equals(UserManager.NO_USER)){
			return null;
		}
		OrganizationDataBean o = db.om.findOrganization(caller.getOrganizationId());
		helper.checkStatus(caller, o, null, WSRAHelper.ALLOWED_CALLER_STATUSES, WSRAHelper.DEFAULT_ALLOWED_ORGANIZATION_STATUSES, null);
		
		issuerDN = CertTools.stringToBCDNString(issuerDN);
		List<ICertificate> certs = getCAConnector(issuerDN).getCACertificateChain(issuerDN);
		
		List<Certificate> retval = new ArrayList<Certificate>();
		try{
			for(ICertificate ic : certs){
				Certificate cert = new Certificate();
				cert.setCertificateBase64(new String(Base64.encode(ic.getEncoded())));
				retval.add(cert);
			}
		}catch(CertificateEncodingException e){
			throw new SignServerException(e.getMessage());
		}
		
		log.debug("<getCACertificateChain");
		return retval;
	}

	
	/**
	 * Method that must be implement in the beginning of all public
	 * WS methods.
	 * 
	 * The call initializes all managers and checks that
	 * the caller is authorized to the correct roles defined
	 * by the AuthorizedRoles annotation.
	 * 
	 * 
	 * @throws AuthorizationDeniedException
	 * @throws SignServerException if other exception occured
	 * during initialization.
	 */
	protected UserDataBean initMethod() throws AuthorizationDeniedException, SignServerException{
		initManagers();
		String methodName = "Unknown Method";
		// Find Authorized Roles annotation
		String[] requiredRoles = null;
		try
		{
			throw new Exception("");
		}
		catch( Exception e )
		{
			Method[] methods = this.getClass().getMethods();
			for(Method m : methods){
				if(m.getName().equals(e.getStackTrace()[1].getMethodName())){
					methodName = m.getName();
					AuthorizedRoles a = m.getAnnotation(AuthorizedRoles.class);
					if(a != null){
						requiredRoles = a.value();
					}
				}
			}            
		}
		if(requiredRoles != null && requiredRoles.length == 0){
			requiredRoles = null;
		}
		
		UserDataBean caller = db.um.getAutorizedUser(getRequestContext());
		Set<String> callerRoles = caller.getRoles();
		boolean authorized = requiredRoles == null;
		if(!authorized && !caller.equals(UserManager.NO_USER)){
			authorized = callerRoles.contains(Roles.SUPERADMIN);
			if(!authorized){
				for(String role : requiredRoles){
					if(callerRoles.contains(role)){
						authorized = true;
						break;
					}
				}
			}
		}
		
		if(!authorized){
			String rolesString = requiredRoles[0];			
			for(int i =1 ; i<requiredRoles.length; i++){
				rolesString += ", " + requiredRoles[i];
			}
			log(Level.ERROR, EVENT_AUTHORIZATION_DENIED, caller, "Caller not authorized to to perform request : %s", methodName);
			throw new AuthorizationDeniedException("Required roles of user to perform call are : " + rolesString);
		}
		
		return caller;
	}
	
    private void initManagers() throws SignServerException{    	
    	if(db == null){
    		db = new DBManagers(getWorkerConfig(),getWorkerEntityManager(),
    				availableTokenProfileClasses,availableAuthTypeClasses,getCryptoToken(),
    				getWorkerCertificate(),nodeId);
    		helper = new WSRAHelper(getWorkerConfig(),db);
    		helper.insertTestData(getWorkerConfig(), 
  	  	          getWorkerEntityManager(),
  	  	          availableTokenProfileClasses,
  	  	          availableAuthTypeClasses,
  	  	          getCryptoToken(),
  	  	          getWorkerCertificate(),
  	  	          nodeId);
    	}  
    	
    }
    
    private ICAConnector getCAConnector(String issuerDN) throws SignServerException, IllegalRequestException {
    	if(cAConnectionManager == null){
    		cAConnectionManager = new CAConnectionManager(getWorkerId(),getWorkerConfig().getProperties(),getCryptoToken());
    	}
    	
    	return cAConnectionManager.getCAConnector(issuerDN);
    }
    private CAConnectionManager cAConnectionManager = null;
    
    /**
     * Help method that will simply for the WSRA logging by formatting
     * the string.
     * 
     * 
     * @param level on of the INFO,ERROR,WARN,FATAL constants
     * @param event a string indicating the type of event.
     * @param caller the WS request user.
     * @param formatedMessage a 'printf' message. 
     * @param args argument that is inserted into the formated message.
     */
	protected void log(Level level, String event, UserDataBean caller, String formatedMessage, Object... args){		
		String message = WSRAHelper.formatLog(getRequestContext(),event, caller,null,formatedMessage,args);
		log.log(level, message);
	}
	
	/**
     * Help method that will simply for the WSRA logging by formatting
     * the string. Have support for logging an exception
     * 
     * The formatted message is a standard printf message with the
     * extension of '%eMsg' which inserts the supplied exception message
     * into the string.
     * 
     * @see WSRA#log(Level, String, UserDataBean, String, Object...)
     */
	protected void log(Level level, String event, UserDataBean caller, Exception e, String formatedMessage, Object... args) throws IllegalRequestException, AuthorizationDeniedException, SignServerException{
		
		String message = WSRAHelper.formatLog(getRequestContext(),event, caller,e,formatedMessage,args);
		log.log(level, message);
		log.debug("Exception trace : ",e);
		
		if(e instanceof IllegalRequestException){
			throw (IllegalRequestException) e;
		}
		if(e instanceof AuthorizationDeniedException){
			throw (AuthorizationDeniedException) e;
		}
		
		if(e instanceof SignServerException){
			throw (SignServerException) e;
		}
		
	}
	
}
