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

package org.signserver.server.signtokens;
 
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.util.KeyTools;
import org.signserver.common.ISignerCertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.SignTokenAuthenticationFailureException;
import org.signserver.common.SignTokenOfflineException;
import org.signserver.common.SignerStatus;


/**
 * Class that uses a p12 file on the filesystem for signing. Only one key and purpose is supported
 * the same key for all purposes will be returned.
 * 
 * loads on activation and releases the keys from memory when deaktivating
 * 
 * Available properties are:
 * KEYSTOREPATH : The full path to the keystore to load. (requred)
 * KEYSTOREPASSWORD : The password that locks the keystore.
 * 
 * @author philip
 * $Id: P12SignToken.java,v 1.6 2007-10-28 12:27:11 herrvendil Exp $
 */
public class P12SignToken implements ISignToken {
	
	private static Logger log = Logger.getLogger(P12SignToken.class);
	
	public static final String KEYSTOREPATH = "KEYSTOREPATH";
	public static final String KEYSTOREPASSWORD = "KEYSTOREPASSWORD";

	
	private String keystorepath = null;
	private String keystorepassword = null;
	
	private PrivateKey privKey = null;
	private X509Certificate cert = null;
	private Collection<Certificate> certChain = null;
	
	
	/**
	 * @see org.signserver.server.signtokens.ISignToken#init(java.util.Properties)
	 */
	public void init(Properties props) {
		keystorepath = props.getProperty(KEYSTOREPATH);
		keystorepassword = props.getProperty(KEYSTOREPASSWORD);  	 
	}

	/**
	 * Returns true if the keystore was properly loaded
	 * 
	 * @see org.signserver.server.signtokens.ISignToken#getSignTokenStatus()
	 */
	public int getSignTokenStatus() {
		if(privKey != null && cert != null){
		  return SignerStatus.STATUS_ACTIVE;
		}
		
		return SignerStatus.STATUS_OFFLINE;
	}

	/**
	 * Loads the keystore into memory
	 * 
	 * @see org.signserver.server.signtokens.ISignToken#activate(java.lang.String)
	 */
	public void activate(String authenticationcode)
			throws SignTokenAuthenticationFailureException,
			SignTokenOfflineException {
           

		try {
			KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
			log.debug("Reading keystore from: "+keystorepath);
			InputStream in = new FileInputStream(keystorepath);
			ks.load(in, authenticationcode.toCharArray());
			in.close();
						
			// Find the key private key entry in the keystore
			Enumeration<String> e = ks.aliases();
			Object o = null;
			PrivateKey keystorePrivKey = null;
			
			while (e.hasMoreElements()) {
				o = e.nextElement();
				
				if (o instanceof String) {
					if ((ks.isKeyEntry((String) o)) &&
							((keystorePrivKey = (PrivateKey) ks.getKey((String) o, authenticationcode.toCharArray())) != null)) {
						log.debug("Aliases " + o + " is KeyEntry.");
						
						break;
					}
				}
			}
			privKey = keystorePrivKey;
			
			//Certificate chain[] = ks.getCertificateChain((String) o);
			Certificate[] chain = KeyTools.getCertChain(ks, (String) o);
			certChain = new ArrayList<Certificate>();
			for(int i=0;i<chain.length;i++){
				certChain.add(chain[i]);
			}
			
			
			log.debug("Loaded certificate chain with length " + chain.length + " from keystore.");
			
			cert = (X509Certificate) chain[0];
			} catch (KeyStoreException e1) {
				log.error("Error :", e1);
				throw new SignTokenAuthenticationFailureException("KeyStoreException " + e1.getMessage());
			} catch (NoSuchProviderException e1) {
				log.error("Error :", e1);
				throw new SignTokenAuthenticationFailureException("NoSuchProviderException " + e1.getMessage());
			} catch (FileNotFoundException e) {
				log.error("Error :", e);
				throw new SignTokenAuthenticationFailureException( "Keystore file not found : " + e.getMessage());
			} catch (NoSuchAlgorithmException e) {
				log.error("Error :", e);
				throw new SignTokenAuthenticationFailureException("NoSuchAlgorithmException " + e.getMessage());
			} catch (CertificateException e) {
				log.error("Error :", e);
				throw new SignTokenAuthenticationFailureException("CertificateException " + e.getMessage());
			} catch (IOException e) {
				log.error("Error :", e);
				throw new SignTokenAuthenticationFailureException("IOException " + e.getMessage());
			} catch (UnrecoverableKeyException e) {
				log.error("Error :", e);
				throw new SignTokenAuthenticationFailureException("UnrecoverableKeyException " + e.getMessage());
			}
            

	}

	/**
	 * Method that clear the keydata from memory.
	 * 
	 * @see org.signserver.server.signtokens.ISignToken#deactivate()
	 */
	public boolean deactivate() {
		privKey = null;
		cert = null;
		return true;
	}

	/**
	 * Returns the same private key for all purposes.
	 * @see org.signserver.server.signtokens.ISignToken#getPrivateKey(int)
	 */
	public PrivateKey getPrivateKey(int purpose)
			throws SignTokenOfflineException {
		
		if(privKey == null){
			if(keystorepassword != null){
				try {
					activate(keystorepassword);
				} catch (SignTokenAuthenticationFailureException e) {
					throw new SignTokenOfflineException("Error trying to autoactivating the keystore, wrong password set? " + e.getMessage());
				} 
			}else{
			  throw new SignTokenOfflineException("Signtoken isn't active.");
			}
		}
		
		return privKey;
	}

	/**
	 * Returns the same public key for all purposes.
	 * @see org.signserver.server.signtokens.ISignToken#getPublicKey(int)
	 */
	public PublicKey getPublicKey(int purpose) throws SignTokenOfflineException {

		if(cert == null){
			if(keystorepassword != null){
				try {
					activate(keystorepassword);
				} catch (SignTokenAuthenticationFailureException e) {
					throw new SignTokenOfflineException("Error trying to autoactivating the keystore, wrong password set? " + e.getMessage());
				} 
			}else{
			  throw new SignTokenOfflineException("Signtoken isn't active.");
			}
		}
		
		
		return cert.getPublicKey();
	}

	/**
	 * Always returns BC
	 * @see org.signserver.server.signtokens.ISignToken#getProvider()
	 */
	public String getProvider(int providerUsage) {
		return "BC";
	}

	public Certificate getCertificate(int purpose) throws SignTokenOfflineException{
		if(cert == null){
			if(keystorepassword != null){
				try {
					activate(keystorepassword);
				} catch (SignTokenAuthenticationFailureException e) {
					throw new SignTokenOfflineException("Error trying to autoactivating the keystore, wrong password set? " + e.getMessage());
				} 
			}else{
			  throw new SignTokenOfflineException("Signtoken isn't active.");
			}
		}
		
		
		return cert;
	}

	public Collection<Certificate> getCertificateChain(int purpose) throws SignTokenOfflineException {
		if(certChain == null){
			if(keystorepassword != null){
				try {
					activate(keystorepassword);
				} catch (SignTokenAuthenticationFailureException e) {
					throw new SignTokenOfflineException("Error trying to autoactivating the keystore, wrong password set? " + e.getMessage());
				} 
			}else{
			  throw new SignTokenOfflineException("Signtoken isn't active.");
			}
		}
		
		
		return certChain;
	}

	/**
	 * Method not supported
	 */
	public ISignerCertReqData genCertificateRequest(ISignerCertReqInfo info) throws SignTokenOfflineException {
		log.error("genCertificateRequest was called, but is not supported for this sign token.");
		return null;
	}
	
	/**
	 * Method not supported
	 */
	public boolean destroyKey(int purpose) {		
		return false;
	}

}
