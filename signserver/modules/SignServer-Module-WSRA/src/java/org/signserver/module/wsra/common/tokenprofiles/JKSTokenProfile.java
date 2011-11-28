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
 
package org.signserver.module.wsra.common.tokenprofiles;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.KeyStore;

import org.apache.log4j.Logger;
import org.signserver.common.SignServerException;

/**
 * Method that represent a JKS keystore token profile.
 * 
 * It can load the unencrypted sensitive data to a key store
 * and the other way.
 * 
 * 
 * @author Philip Vendil 15 okt 2008
 *
 * @version $Id$
 */

public class JKSTokenProfile implements ITokenProfile {
	
	private static transient Logger log = Logger.getLogger(JKSTokenProfile.class);

	protected String keyStorePwd;

	protected KeyStore keyStore;

	public static final String PROFILEID = "JKSTOKENPROFILE";
	
	
	/**
	 * @see org.signserver.module.wsra.common.tokenprofiles.ITokenProfile#getProfileIdentifier()
	 */
	
	public String getProfileIdentifier() {
		return PROFILEID;
	}

	/**
	 * Transforms the tokens sensitive data into a JKS key store
	 * The keystore and password is then fetched with getKeyStore() 
	 * and getKeyStorePwd()
	 * 
	 * @param data unencrypted byte array
	 * @throws SignServerException if keystore couldn't be loaded. 
	 * 
	 */
	public void init(byte[] data) throws SignServerException{
		try{
			DataInputStream das = new DataInputStream(new ByteArrayInputStream(data));
			int stringLength = das.readInt();
			byte[] pwdData = new byte[stringLength];
			das.read(pwdData, 0, stringLength);
			keyStorePwd = new String(pwdData,"UTF-8");
			keyStore = KeyStore.getInstance("JKS");
			keyStore.load(das, keyStorePwd.toCharArray());
		}catch(Exception e){
           log.error("Error loading JKS key store :" + e.getMessage(),e);
           throw new SignServerException("Error loading JKS key store :" + e.getMessage(),e);
		}
	}
	
	/**
	 * Used to initialize a new JKS keystore.
	 * 
	 * @param keyStorePwd the password to unlock the keystore
	 * @throws SignServerException if keystore couldn't be loaded.
	 * 
	 */
	public void init(String password) throws SignServerException{
		try{			
			keyStore = KeyStore.getInstance("JKS");
			keyStore.load(null, password.toCharArray());			
		}catch(Exception e){
           log.error("Error loading JKS key store :" + e.getMessage(),e);
           throw new SignServerException("Error loading JKS key store :" + e.getMessage(),e);
		}
	}
	
	/**
	 * Static help method used to transform a key store to 
	 * an byte array
	 * @param keyStore the key store to serialize
	 * @param keyStorePwd the password to lock the key store with.
	 * @return byte array representation of the key store.
	 */
	public static byte[] serializeKeyStore(KeyStore keyStore, String keyStorePwd) throws SignServerException{
		try{
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			DataOutputStream dos = new DataOutputStream(baos);
			byte[] keyStorePwdData = keyStorePwd.getBytes("UTF-8");
			dos.writeInt(keyStorePwdData.length);
			dos.write(keyStorePwdData, 0, keyStorePwdData.length);
			keyStore.store(dos, keyStorePwd.toCharArray());
			return baos.toByteArray();
		}catch(Exception e){
			log.error("Error storing JKS key store :" + e.getMessage(),e);
			throw new SignServerException("Error storing JKS key store :" + e.getMessage(),e);
		}
	}

	/**
	 * Returns the password to the keystore loaded by the init() method.
	 * @return the keyStorePwd
	 */
	public String getKeyStorePwd() {
		return keyStorePwd;
	}


	/**
	 * Returns the keystore loaded by the init() method.
	 * @return the keyStore
	 */
	public KeyStore getKeyStore() {
		return keyStore;
	}
	


	/**
	 * Do not store JKS token profile
	 */
	public boolean storeSensitiveData() {
		return false;
	}
		
	


}
