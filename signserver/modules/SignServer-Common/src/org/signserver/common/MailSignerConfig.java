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
import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;

/**
 * Class used when getting the current status of a specific MailSigner.
 * Contains the configuration of a MailSigner 
 * 
 * @author Philip Vendil
 *
 * $Id$
 */
public class MailSignerConfig {

	public static transient Logger log = Logger.getLogger(MailSignerConfig.class);
	
    public static final String RMI_OBJECT_NAME = "MailSignerCLI";
	
	private static final long serialVersionUID = 1L;
		
	public static final String SIGNERCERT = "SIGNERCERT";
	public static final String SIGNERCERTCHAIN = "SIGNERCERTCHAIN";
	
	public static final String NAME = "NAME";

	private WorkerConfig workerConfig;
	
	 
	public MailSignerConfig(WorkerConfig workerConfig){
		super();
		this.workerConfig = workerConfig;

		if(get(SIGNERCERT) == null){
			put(SIGNERCERT,"");
		}
		if(get(SIGNERCERTCHAIN) == null){
			put(SIGNERCERTCHAIN,"");
		}
			
		put(WorkerConfig.CLASS, this.getClass().getName());
	}
	
	
	private void put(String key, String value){
		workerConfig.setProperty(key, value);
	}
	
	private String get(String key){
		return workerConfig.getProperty(key);
	}

	
	/**
	 * Method used to fetch a signers certificate from the config
	 * @return the signer certificate stored or null if no certificate have been uploaded.
	 * 
	 */
	public X509Certificate getSignerCertificate() {
		X509Certificate result = null;
		String stringcert = (String) get(SIGNERCERT);
		if(stringcert == null || stringcert.equals("")){
			stringcert = (String) get(WorkerConfig.getNodeId() + "." + SIGNERCERT);
		}
		
		
		
		if(stringcert != null && !stringcert.equals("")){
			Collection<?> certs;
			try {
				certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(stringcert.getBytes()));
				if(certs.size() > 0){
					result = (X509Certificate) certs.iterator().next();
				}
			} catch (CertificateException e) {
				log.error(e); 
			} catch (IOException e) {
				log.error(e);
			}

		}
	
		if(result==null){
			// try fetch certificate from certificate chain
			Collection<?> chain = getSignerCertificateChain();

			if(chain != null){
				Iterator<?> iter = chain.iterator();
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
	 * Method used to fetch a signers certificate chain from the config
	 * @return the signer certificate stored or null if no certificates have been uploaded.
	 * 
	 */
	@SuppressWarnings("unchecked")
	public Collection<X509Certificate> getSignerCertificateChain() {
		Collection<X509Certificate> result = null;
		String stringcert = (String) get(SIGNERCERTCHAIN);

		if(stringcert == null || stringcert.equals("")){
			stringcert = (String) get(WorkerConfig.getNodeId() +"."+ SIGNERCERTCHAIN);
		}

		if(stringcert != null && !stringcert.equals("")){
			try {
				result =  CertTools.getCertsFromPEM(new ByteArrayInputStream(stringcert.getBytes()));
			} catch (CertificateException e) {
				log.error(e); 
			} catch (IOException e) {
				log.error(e);
			}
		}

		return result;
		
	}

	/**
	 * Method used to store a signers certificate in the config
	 * @param signerCert
	 * 
	 */
	public void setSignerCertificateChain(Collection<X509Certificate> signerCertificateChain, String scope) {
		if(scope.equals(GlobalConfiguration.SCOPE_GLOBAL)){
			try {
				String stringcert = new String(CertTools.getPEMFromCerts(signerCertificateChain));
				put(SIGNERCERTCHAIN,stringcert);	
			} catch (CertificateException e) {
				log.error(e);
			}
		}else{
			try {
				String stringcert = new String(CertTools.getPEMFromCerts(signerCertificateChain));
				put(WorkerConfig.getNodeId() +"." + SIGNERCERTCHAIN,stringcert);	
			} catch (CertificateException e) {
				log.error(e);
			}			
		}
		
	}

	public WorkerConfig getWorkerConfig() {
		return workerConfig;
	}
	

	/**
	 * Method returning the registry port in a way that works for both test and production environments
	 */
    public static int getRMIRegistryPort(){
	  int retval = 1099;
          final String rmiPort = CompileTimeSettings.getInstance().getProperty(
                  CompileTimeSettings.RMIREGISTRYPORT);
	  if(rmiPort != null){
		  try{
			  retval = Integer.parseInt(rmiPort.trim());
		  }catch(NumberFormatException e){
			  log.error("RMI Registry Port settings is missconfigured, must be a number");
		  }
	  }
	  
	  return retval;
   }
   
	/**
	 * Method returning the server port in a way that works for both test and production environments
	 */
  public static int getRMIServerPort(){
	  int retval = 2099;
          final String rmiPort = CompileTimeSettings.getInstance().getProperty(
                  CompileTimeSettings.RMISERVERPORT);
	  if(rmiPort != null){
		  try{
			  retval = Integer.parseInt(rmiPort.trim());
		  }catch(NumberFormatException e){
			  log.error("RMI Server Port settings is missconfigured, must be a number");
		  }
	  }
	  
	  return retval;
  }
}
