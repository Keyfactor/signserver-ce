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

package org.signserver.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;

import javax.ejb.EJBException;

import org.ejbca.util.CertTools;

/**
 * 
 * Class used to store signer specific configuration
 * 
 * @author Philip Vendil 2007 jan 23
 *
 * @version $Id: SignerConfig.java,v 1.1 2007-02-27 16:18:11 herrvendil Exp $
 */

public class SignerConfig extends WorkerConfig {

	private static final long serialVersionUID = 1L;

	private static final float LATEST_VERSION = 2;
	
	private static final String AUTHORIZED_CLIENTS = "AUTHORIZED_CLIENTS";
	private static final String SIGNERCERT = "SIGNERCERT";
	private static final String SIGNERCERTCHAIN = "SIGNERCERTCHAIN";
	
	public static final String NAME = "NAME";
	
	 
	public SignerConfig(){
		super();
		data.put(AUTHORIZED_CLIENTS,new HashSet());
		data.put(SIGNERCERT,"");
		data.put(SIGNERCERTCHAIN,"");
		data.put(CLASS, this.getClass().getName());
	}
	
	/**
	 * Adds a Certificate SN to the collection of authorized clients	  
	 * 
	 * @param the AuthorizedClient to add
	 */
	public void addAuthorizedClient(AuthorizedClient client){
		((HashSet) data.get(AUTHORIZED_CLIENTS)).add(client);				
	}

	/**
	 * Removes a Certificate SN from the collection of authorized clients	  
	 * 
	 * @param the AuthorizedClient to remove
	 */

	public boolean removeAuthorizedClient(AuthorizedClient client){
		Iterator iter  = ((HashSet) data.get(AUTHORIZED_CLIENTS)).iterator();
		while(iter.hasNext()){
			AuthorizedClient next = (AuthorizedClient) iter.next();
			if(next.getCertSN().equals(client.getCertSN()) && next.getIssuerDN().equals(client.getIssuerDN())){				
				return ((HashSet) data.get(AUTHORIZED_CLIENTS)).remove(next);				
			}
		}
		return false;
	}
	
	/**
	 * 	  
	 * Gets a collection of authorized client certificates
	 * 
	 * @return a Collection of String containing the certificate serial number.
	 */
	
	public Collection getAuthorizedClients(){
		ArrayList result = new ArrayList();
		Iterator iter = ((HashSet) data.get(AUTHORIZED_CLIENTS)).iterator();
		while(iter.hasNext()){
			result.add(iter.next());
		}
		
		Collections.sort(result);
		return result;
	}
	
	
	/**
	 * Checks if a certificate is in the list of authorized clients
	 * @param clientCertificate
	 * @return true if client is authorized.
	 */
	public boolean isClientAuthorized(X509Certificate clientCertificate){	  
	  AuthorizedClient client = new AuthorizedClient(clientCertificate.getSerialNumber().toString(16),clientCertificate.getIssuerDN().toString()); 
	  
	  return ((HashSet) data.get(AUTHORIZED_CLIENTS)).contains(client);	  
	}

	public float getLatestVersion() {		
		return LATEST_VERSION;
	}

	public void upgrade() {
		if(data.get(CLASS) == null){
			data.put(CLASS, this.getClass().getName());
		}

		data.put(VERSION, new Float(LATEST_VERSION));
	}
	
	/**
	 * Method used to fetch a signers certificate from the config
	 * @return the signer certificate stored or null if no certificate have been uploaded.
	 * 
	 */
	public X509Certificate getSignerCertificate() {
		X509Certificate result = null;
		String stringcert = (String) data.get(SIGNERCERT);
		if(!stringcert.equals("")){
			Collection certs;
			try {
				certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(stringcert.getBytes()));
				if(certs.size() > 0){
					result = (X509Certificate) certs.iterator().next();
				}
			} catch (CertificateException e) {
				throw new EJBException(e); 
			} catch (IOException e) {
				throw new EJBException(e);
			}

		}
		if(result==null){
			// try fetch certificate from certificate chain
			Collection chain = getSignerCertificateChain();
			if(chain != null){
				Iterator iter = chain.iterator();
				while(iter.hasNext()){
					X509Certificate next = (X509Certificate) iter.next();
					if(next.getBasicConstraints() == -1){
						result = next;
					}
				}
			}
		}
		return result;
		
	}

	/**
	 * Method used to store a signers certificate in the config
	 * @param signerCert
	 * 
	 */
	public void setSignerCertificate(X509Certificate signerCert) {
		ArrayList list = new ArrayList();
		list.add(signerCert);
		try {
			String stringcert = new String(CertTools.getPEMFromCerts(list));
			data.put(SIGNERCERT,stringcert);	
		} catch (CertificateException e) {
			throw new EJBException(e);
		}
		
	}
	
	/**
	 * Method used to fetch a signers certificate chain from the config
	 * @return the signer certificate stored or null if no certificates have been uploaded.
	 * 
	 */
	public Collection getSignerCertificateChain() {
		Collection result = null;
		String stringcert = (String) data.get(SIGNERCERTCHAIN);
		if(!stringcert.equals("")){
			try {
				result = CertTools.getCertsFromPEM(new ByteArrayInputStream(stringcert.getBytes()));				
			} catch (CertificateException e) {
				throw new EJBException(e); 
			} catch (IOException e) {
				throw new EJBException(e);
			}

		}
		return result;
		
	}

	/**
	 * Method used to store a signers certificate in the config
	 * @param signerCert
	 * 
	 */
	public void setSignerCertificateChain(Collection signerCertificateChain) {
		try {
			String stringcert = new String(CertTools.getPEMFromCerts(signerCertificateChain));
			data.put(SIGNERCERTCHAIN,stringcert);	
		} catch (CertificateException e) {
			throw new EJBException(e);
		}
		
	}

}
