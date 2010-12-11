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
 
package org.signserver.module.wsra.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;

import org.apache.log4j.Logger;
import org.signserver.common.RequestContext;
import org.signserver.module.wsra.beans.AuthDataBean;
import org.signserver.module.wsra.beans.TokenDataBean;
import org.signserver.module.wsra.beans.UserAliasDataBean;
import org.signserver.module.wsra.beans.UserDataBean;
import org.signserver.module.wsra.common.authtypes.IAuthType;

/**
 * Class in charge of logic concerning authorization
 * of users, this could be to get roles of user,
 * or to manage available administrators.
 * 
 * All manipulation of Authentication Data should go
 * through this class.
 * 
 * 
 * @author Philip Vendil 11 okt 2008
 *
 * @version $Id$
 */

public class UserManager {
	
	private Logger log = Logger.getLogger(this.getClass());
	
	private Set<IAuthType> availableAuthTypes = new HashSet<IAuthType>();
	
	private HashMap<String,UserDataBean> authCache = new HashMap<String,UserDataBean>();
	
	private EntityManager workerEntityManager;
	private TokenManager tm;
	
	public static final UserDataBean NO_USER = new UserDataBean();
	static{
		NO_USER.setRoles(new HashSet<String>());
	}
	
	public UserManager(EntityManager workerEntityManager, Set<Class<?>> availableAuthTypesClasses, TokenManager tm){
		for(Class<?> c: availableAuthTypesClasses){
			if(!c.isInterface()){
				try {
					availableAuthTypes.add((IAuthType) c.newInstance());
				} catch (InstantiationException e) {
					log.error("Error creating IAuthType : " +c.getName(),e );
				} catch (IllegalAccessException e) {
					log.error("Error creating IAuthType : " +c.getName(),e );
				}
			}
		}
		
		this.workerEntityManager = workerEntityManager;
		this.tm = tm;
	}
	
	/**
	 * Method that fetches the current roles authorized to
	 * the request user.
	 * 
	 * @param requestContext sent along with WS call
	 * @return a set of authorized roles, never null but will return
	 * the constant NO_USER if no configured user could be found.
	 * roles, can but must not be one of constants defined in Roles.
	 */
	
	public UserDataBean getAutorizedUser(RequestContext requestContext){
		UserDataBean userData = null;
										
		// 1. check cache
		for(IAuthType authType : availableAuthTypes){
			String matchValue = authType.getMatchValue(requestContext);
			if(matchValue != null){
				userData = authCache.get("AUTHTYPE" + authType.getAuthType() +matchValue);
				if(userData != null){
					break;
				}
			}
		}
		
		if(userData == null){		
			userData = NO_USER;
		// 2. if not in cache calculate from db			
			for(IAuthType authType : availableAuthTypes){
				String matchValue = authType.getMatchValue(requestContext);				
				if(matchValue != null){
					int at = authType.getAuthType();
					try{
						AuthDataBean authDataBean = (AuthDataBean) workerEntityManager.createNamedQuery("AuthDataBean.findByAuthData")
						.setParameter(1, at)
						.setParameter(2, matchValue)
						.getSingleResult();
						if(authDataBean != null){

							UserDataBean ud = workerEntityManager.find(UserDataBean.class, authDataBean.getUserId());
							if(ud != null){
								userData = ud;
								// 3. add to cache
								authCache.put("AUTHTYPE" + at +matchValue, userData);
								break;
							}
						}
					}catch(javax.persistence.NoResultException e){}

				}	
			}

		}
		
		return userData;
	}

	
	/**
	 * Method that lists all users in an organization.
	 * 
	 * @param organizationId of the organization to list.
	 * @param role that the user must have, use null for all roles
	 * @return a list of users that fulfill the requirements, never null
	 */
	public List<UserDataBean> listUsers(int organizationId, String role){
		List<UserDataBean> retval = new ArrayList<UserDataBean>();
		
		try{
			if(role != null){
				
				List<?> result = workerEntityManager.createNamedQuery("UserDataBean.findByRoleAndOrg")
		                                   .setParameter(1, "%" + role + ",%")
		                                   .setParameter(2, organizationId)
		                                   .getResultList();
				for(Object o : result){
					fetchDeepUserData((UserDataBean) o);
					retval.add((UserDataBean) o);
				}
			}else{
				List<?> result = workerEntityManager.createNamedQuery("UserDataBean.findByOrg")
				.setParameter(1, organizationId)
				.getResultList();
				for(Object o : result){
					fetchDeepUserData((UserDataBean) o);
					retval.add((UserDataBean) o);
				}
				
			}
		}catch(NoResultException e){}
						
		return retval;
	}
	
	private void fetchDeepUserData(UserDataBean udb) {
		if(udb.getAliases() != null){
			udb.getAliases().size();
		}
		if(udb.getTokens() != null){
			for(TokenDataBean tdb : udb.getTokens()){
				if(tdb.getCertificates() != null){
				  tdb.getCertificates().size();	
				}
			}					
		}
		if(udb.getAuthData() != null){
		  udb.getAuthData().size();
		}
	}

	private void removeFromCache(int authType, String authValue){
		authCache.remove("AUTHTYPE" + authType +authValue);
	}
	
	/**
	 * Method used to add/edit a user in the system, important
	 * AuthData and Token Data isn't updated with this call, but
	 * aliases are.
	 * userId is auto generated by the database.  
	 * @return the generated user Id
	 */
	public int editUser(UserDataBean userData){
		UserDataBean persistData = findUser(userData.getUserName(),userData.getOrganizationId());
		boolean persist = false;
				
		if(persistData == null){
			persistData = new UserDataBean();
			persist = true;
		}
		persistData.setUserName(userData.getUserName());
		persistData.setDisplayName(userData.getDisplayName());
		persistData.setOrganizationId(userData.getOrganizationId());
		persistData.setStatus(userData.getStatus());
		persistData.setComment(userData.getComment());
		persistData.setRoles(userData.getRoles());
		persistData.setClearPassword(userData.isClearPassword());
		persistData.setPassword(userData.getPassword());
		if(persist){
			workerEntityManager.persist(persistData);
		}
		
		if(!persist){
			for(UserAliasDataBean uad : persistData.getAliases()){
				workerEntityManager.remove(uad);
			} 	
		}
		if(userData.getAliases() != null){
		  for(UserAliasDataBean uad : userData.getAliases()){
			uad.setUserId(persistData.getId());
			editUserAlias(uad);
		  }
		}
		
		if(!persist){
			for(AuthDataBean udb : persistData.getAuthData()){
				workerEntityManager.remove(udb);
			} 	
		}
		if(userData.getAuthData() != null){
		  for(AuthDataBean udb : userData.getAuthData()){
			  udb.setUserId(persistData.getId());
			  editAuthData(udb);
		  }
		}
				
		return persistData.getId();
	}
	

	/**
	 * Method that removes a user along with all
	 * it's auth data and tokens.
	 * 
	 * This method should generally only be called from
	 * test scripts.
	 * 
	 * @param userId the unique id of user.
	 */
	public void removeUser(int userId){
		UserDataBean userData = workerEntityManager.find(UserDataBean.class, userId);				
		if(userData != null){
			
			for(AuthDataBean adb : userData.getAuthData()){
				workerEntityManager.remove(adb);
			}

			for(UserAliasDataBean uadb : userData.getAliases()){
				workerEntityManager.remove(uadb);
			}

			for(TokenDataBean t : userData.getTokens()){
				tm.removeToken(t.getId());	
			}						
			workerEntityManager.remove(userData);		
		}
	}
	
	/**
	 * Method used to find a user from it's unique userName
	 * and organizationId, returns null if no user could be
	 * found
	 */
	public UserDataBean findUser(String userName, int organizationId){
		UserDataBean retval = null;		
		try{
			retval = (UserDataBean) workerEntityManager.createNamedQuery("UserDataBean.findByUserName")
			                            .setParameter(1, userName)
			                            .setParameter(2, organizationId)
			                            .getSingleResult();
			
			if(retval != null){
				fetchDeepUserData(retval);
			}
			
		}catch(NoResultException e){}
		
		return retval;
	}
	
	/**
	 * Method used to find a user from it's unique userId.
	 * Returns null if no user could be found.
	 */
	public UserDataBean findUser(int userId){
		UserDataBean retval = null;
		try{
			retval = (UserDataBean) workerEntityManager.find(UserDataBean.class, userId);
			if(retval != null){
				fetchDeepUserData(retval);
			}
		}catch(NoResultException e){}

		return retval;
	}
	
	/**
	 * Method used to add/edit authentication data to a user.
	 * Id field is ignored since it is generated by database.
	 * 
	 * @param authData authData to add/edit
	 * @return the AuthData id
	 */
	public int editAuthData(AuthDataBean authData){
		AuthDataBean persistData = findAuthData(authData.getAuthType(),authData.getAuthValue());
		boolean persist = false;
				
		if(persistData == null){
			persistData = new AuthDataBean();
			persist = true;
		}else{
			// Remove original values from cache since they might be altered.
			removeFromCache(persistData.getAuthType(), persistData.getAuthValue());
		}
		persistData.setUserId(authData.getUserId());
		persistData.setAuthType(authData.getAuthType());
		persistData.setAuthValue(authData.getAuthValue());
		persistData.setComment(authData.getComment());		
		if(persist){
			workerEntityManager.persist(persistData);
		}
				
		return persistData.getId();
	}
	
	/**
	 * Method used to find auth data from it's authType and
	 * authValue, returns null if no auth data could be
	 * found.
	 */
	public AuthDataBean findAuthData(int authType, String authData){
		AuthDataBean retval = null;		
		try{
			retval = (AuthDataBean) workerEntityManager.createNamedQuery("AuthDataBean.findByAuthData")
			                            .setParameter(1, authType)
			                            .setParameter(2, authData)
			                            .getSingleResult();
		}catch(NoResultException e){}
		
		return retval;
	}
	
	/**
	 * Method that removes a auth data from the system.
	 * 
	 * 
	 * 
	 * @param userId the unique id of user.
	 */
	public void removeAuthData(int authType, String authValue){		
		AuthDataBean data = findAuthData(authType,authValue);
		if(data != null){			              						
			workerEntityManager.remove(data);
			removeFromCache(authType, authValue);
		}
	}
	

	public UserAliasDataBean findUserAlias(int userId, String type, String alias){
		UserAliasDataBean retval = null;		
		
		try{
			return (UserAliasDataBean) workerEntityManager.createNamedQuery("UserAliasDataBean.findByUserAlias")
			.setParameter(1, userId)
			.setParameter(2, type)
			.setParameter(3, alias)
			.getSingleResult();
		}catch(NoResultException e){}

		return retval;
	}
	
	/**
	 * Finds all users that matches the given query.
	 * @param organizationId the organization the user must belong to.
	 * @param type the type of alias
	 * @param alias the alias to search for
	 * @return all users with the specific alias and type in the organization
	 * never null.
	 */
	@SuppressWarnings("unchecked")
	public List<UserDataBean> findUserByAlias(int organizationId, String type, String alias){
		List<UserDataBean> retval = new ArrayList<UserDataBean>();

		try{
			List<UserDataBean> result =  workerEntityManager.createNamedQuery("UserAliasDataBean.findUserByAlias")
			.setParameter(1, organizationId)
			.setParameter(2, type)
			.setParameter(3, alias)
			.getResultList();
			
			for(UserDataBean ud : result){
				ud.getAliases().size();
				ud.getAuthData().size();
				for(TokenDataBean tdb : ud.getTokens()){
					tdb.getCertificates().size();	
				}
				retval.add(ud);
			}
						
		}catch(NoResultException e){}

		return retval;
	}
	
	/**
	 * Finds all users that matches the given query where
	 * the alias should contain the string containAlias
	 * 
	 * @param organizationId the organization the user must belong to.
	 * @param type the type of alias
	 * @param containAlias substring that the alias must have.
	 * @return all users with the specific alias and type in the organization
	 * never null.
	 */
	@SuppressWarnings("unchecked")
	public List<UserDataBean> findUserLikeAlias(int organizationId, String type, String containAlias){
		List<UserDataBean> retval = new ArrayList<UserDataBean>();

		try{
			List<UserDataBean> result = workerEntityManager.createNamedQuery("UserAliasDataBean.findUserLikeAlias")
			.setParameter(1, organizationId)
			.setParameter(2, type)
			.setParameter(3, "%" + containAlias + "%")
			.getResultList();
			
			for(UserDataBean ud : result){
				fetchDeepUserData(ud);
				retval.add(ud);
			}
		}catch(NoResultException e){}

		return retval;
	}
	
	private int editUserAlias(UserAliasDataBean userAlias){
    
    	
		UserAliasDataBean persistData = findUserAlias(userAlias.getUserId(), userAlias.getType(), userAlias.getAlias());				
		boolean persist = false;		
				
		if(persistData == null){
			persistData = new UserAliasDataBean();
			persist = true;
		}
		persistData.setUserId(userAlias.getUserId());
		persistData.setType(userAlias.getType());
		persistData.setAlias(userAlias.getAlias());
		persistData.setComment(userAlias.getComment());		
		if(persist){
			workerEntityManager.persist(persistData);
		}				
		
		return persistData.getId();
	}

	

}
