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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.apache.james.services.User;
import org.apache.james.services.UsersRepository;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.MailSignerUser;

/**
 * Class implementing UserRespository interface specific to use SMTP 
 * AUTH with dynamic configuration using the MailSigner CLI.
 * 
 * Stores the users in the global configuration. using the GLOB.SMTPAUTH.<username>=<password> format.
 * 
 * Important the store stores the user name (but not password) in case insensitive notation.
 * 
 * @author Philip Vendil 24 dec 2007
 *
 * @version $Id: MailSignerUserRepository.java,v 1.1 2007-12-29 10:43:53 herrvendil Exp $
 */

public class MailSignerUserRepository implements UsersRepository {

	public static final String SMTPAUTH_PREFIX = "SMTPAUTH.";
	
	
	NonEJBGlobalConfigurationSession gcSession = NonEJBGlobalConfigurationSession.getInstance();
	
	private static HashMap<String,MailSignerUser> users = null;
	
	/**
	 * Does nothing.
	 * 
	 * @see org.apache.james.services.UsersRepository#addUser(org.apache.james.services.User)
	 */
	public boolean addUser(User username) {		
		return true;
	}

	/**
	 * Adds user name and password to the repository, only a String password
	 * is supported for attribute
	 * 
	 * @see org.apache.james.services.UsersRepository#addUser(java.lang.String, java.lang.Object)
	 */
	public void addUser(String username, Object attributes) {
		gcSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, SMTPAUTH_PREFIX + username, attributes.toString());
		synchronized(this)  {
			users = null;
		}
		
	}

	/**
	 * 
	 * 
	 * @see org.apache.james.services.UsersRepository#addUser(java.lang.String, java.lang.String)
	 */
	public boolean addUser(String username, String password) {
		gcSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, SMTPAUTH_PREFIX + username, password);
		synchronized(this)  {
			users = null;
		}
		return true;
	}

	/**
	 * @see org.apache.james.services.UsersRepository#contains(java.lang.String)
	 */
	public boolean contains(String name) {		
		return getUserHashMap().containsKey(name.toUpperCase());
	}



	/**
	 * Same as contains.
	 * 
	 * @see org.apache.james.services.UsersRepository#containsCaseInsensitive(java.lang.String)
	 */
	public boolean containsCaseInsensitive(String name) {
		return contains(name);
	}

	/**
	 * @see org.apache.james.services.UsersRepository#countUsers()
	 */
	public int countUsers() {
		return getUserHashMap().size();
	}

	/**
	 * @see org.apache.james.services.UsersRepository#getRealName(java.lang.String)
	 */
	public String getRealName(String name) {
		return getUserByNameCaseInsensitive(name).getUserName();
	}

	/**
	 * @see org.apache.james.services.UsersRepository#getUserByName(java.lang.String)
	 */
	public User getUserByName(String username) {
		return getUserHashMap().get(username.toUpperCase());
	}

	/**
	 * @see org.apache.james.services.UsersRepository#getUserByNameCaseInsensitive(java.lang.String)
	 */
	public User getUserByNameCaseInsensitive(String name) {		
		return getUserByName(name);
	}

	/**
	 * @see org.apache.james.services.UsersRepository#list()
	 */
	public Iterator<?> list() {		
		return getUserHashMap().values().iterator();
	}

	/**
	 * @see org.apache.james.services.UsersRepository#removeUser(java.lang.String)
	 */
	public void removeUser(String username) {
		gcSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, SMTPAUTH_PREFIX + username);
		synchronized(this)  {
			users = null;
		}
	}

	/**
	 * @see org.apache.james.services.UsersRepository#test(java.lang.String, java.lang.String)
	 */
	public boolean test(String username, String password) {	
		if(getUserHashMap().get(username.toUpperCase()) != null){
		  return  getUserHashMap().get(username.toUpperCase()).verifyPassword(password);
		}
		
		return false;
	}

	/**
	 * Not supported
	 * @see org.apache.james.services.UsersRepository#updateUser(org.apache.james.services.User)
	 */
	public boolean updateUser(User user) {
		return true;
	}
	
	/**
	 * Method returning a sorted list of users, sorted by username
	 */
	public List<MailSignerUser> getUsersSorted(){
		ArrayList<MailSignerUser> values = new ArrayList<MailSignerUser>();
		values.addAll(getUserHashMap().values());
		Collections.sort(values, new Comparator<MailSignerUser>() {
	        public int compare(MailSignerUser s1, MailSignerUser s2) {
	            return s1.getUserName().compareTo(s2.getUserName());
	        }
	    });
		
		return values;
	}
	
	/**
	 * Returns HashMap of username -> user of existing SMTP authorized users.
	 */
	private HashMap<String,MailSignerUser> getUserHashMap() {
		if(users == null){
			users = new HashMap<String,MailSignerUser>();
			String prefix = GlobalConfiguration.SCOPE_GLOBAL + SMTPAUTH_PREFIX;
            Iterator<String> iter = gcSession.getGlobalConfiguration().getKeyIterator();
            while(iter.hasNext()){
            	String key = iter.next();
            	if(key.startsWith(prefix)){
            		String username = key.substring(prefix.length());
            		users.put(username, new MailSignerUser(username, gcSession.getGlobalConfiguration().getProperty(key)));
            	}
            }
			
			
		}
	
		return users;
	}

}
