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

package org.signserver.validationservice.server;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.util.CertTools;
import org.signserver.common.SignServerException;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.ValidationServiceConstants;
import org.signserver.validationservice.common.X509Certificate;


/**
 * Base class implementing the base functionality for a validator
 * 
 * 
 * @author Philip Vendil 30 nov 2007
 *
 * @version $Id: BaseValidator.java,v 1.1 2007-12-02 20:35:17 herrvendil Exp $
 */

public abstract class BaseValidator implements IValidator{
	
	private transient Logger log = Logger.getLogger(this.getClass());

	protected int workerId;
	protected int validatorId;
	protected Properties props;
	protected EntityManager em;
	protected ICryptoToken ct;
	
	private HashMap<String, List<ICertificate>> certChainMap = null;
	private HashMap<Integer,Properties> issuerProperties = null;

	/*
	 * certificate chains for all issuers
	 */
	protected HashMap<String, List<ICertificate>> getCertChainMap() {
		
		if(certChainMap == null){
			certChainMap = new HashMap<String, List<ICertificate>>();
			for(Integer issuerId : getIssuerProperties().keySet()){
				Properties issuerProps =  getIssuerProperties().get(issuerId);
				
				List<ICertificate> certChain = getCertChainFromProps(issuerId,issuerProps);
				if(certChain != null){
				  certChainMap.put(certChain.get(0).getSubject(),certChain);
				}
			}						
		}
		
		return certChainMap;
	}
	
	/**
	 * @see org.signserver.validationservice.server.IValidator#init(int, java.util.Properties, javax.persistence.EntityManager, org.signserver.server.cryptotokens.IExtendedCryptoToken)
	 */
	public void init(int workerId, int validatorId, Properties props, EntityManager em,
			ICryptoToken ct) throws SignServerException {
		this.workerId = workerId;
		this.validatorId = validatorId;
		this.props = props;
		this.em = em;
		this.ct = ct;
	}

	/**
	 * @see org.signserver.validationservice.server.IValidator#getCertificateChain(org.signserver.validationservice.common.ICertificate)
	 */
	public List<ICertificate> getCertificateChain(ICertificate cert) {
		
		if( getCertChainMap() == null)
			return null;
		
		// if it is end entity certificate return ful chain as specified in properties
		// if it is CA certificate return "cut off certificate chain"
		X509Certificate x509cert = (X509Certificate)cert;
		if(x509cert.getBasicConstraints() == -1)
			return getCertChainMap().get(cert.getIssuer());
		else
			return getCertificateChainForCACertificate(cert);
	}
	
	/**
	 * Fetches certificate chain.
	 * 
	 * @param issuerProps issuer properties
	 * @return List of CA certificates with the root certificate last or null if no chain is configured.
	 */
	private List<ICertificate> getCertChainFromProps(int issuerId, Properties issuerProps) {
		List<ICertificate> retval = null;
		if(issuerProps.getProperty(ValidationServiceConstants.VALIDATIONSERVICE_ISSUERCERTCHAIN) == null){
			log.error("Error required issuer setting " + ValidationServiceConstants.VALIDATIONSERVICE_ISSUERCERTCHAIN + " is missing for issuer " + 
					  issuerId + ", validator id " + validatorId + ", worker id" + workerId);
		}else{
			try {
				Collection<?> certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(issuerProps.getProperty(ValidationServiceConstants.VALIDATIONSERVICE_ISSUERCERTCHAIN).getBytes()));
				Iterator<?> certiter = certs.iterator();
				ArrayList<ICertificate> icerts = new ArrayList<ICertificate>();
				while(certiter.hasNext()){
					icerts.add(ICertificateManager.genICertificate((Certificate) certiter.next()));
				}
				int initialSize = icerts.size();
				retval = sortCerts(issuerId, icerts);
				if(retval.size() != initialSize){
					retval = null;
				}
				
			} catch (CertificateException e) {
				log.error("Error constructing certificate chain from setting " + ValidationServiceConstants.VALIDATIONSERVICE_ISSUERCERTCHAIN + " is missing for issuer " + 
						  issuerId + ", validator id " + validatorId + ", worker id" + workerId,e);
			} catch (IOException e) {
				log.error("Error constructing certificate chain from setting " + ValidationServiceConstants.VALIDATIONSERVICE_ISSUERCERTCHAIN + " is missing for issuer " + 
						  issuerId + ", validator id " + validatorId + ", worker id" + workerId,e);			}
		}
		
		return retval;
	}

	/**
	 * Method sorting the certificate with the root certificate last.
	 * @param icerts ICertificates
	 * @return
	 */
	ArrayList<ICertificate> sortCerts(int issuerid, ArrayList<ICertificate> icerts) {
		ArrayList<ICertificate> retval = new ArrayList<ICertificate>();
		
		// Start with finding root
		ICertificate currentCert = null;
		for(ICertificate icert : icerts){
          if(icert.getIssuer().equals(icert.getSubject())){
        	  retval.add(0,icert);         	  
        	  currentCert = icert;
        	  break;
          }
		}
		icerts.remove(currentCert);
		
		if(retval.size() == 0){
			log.error("Error in certificate chain, no root certificate for issuer " + issuerid + ", validator " + validatorId + " worker " + workerId);
		}
		
		int tries = 10;
		while(icerts.size() > 0 && tries > 0){
			for(ICertificate icert : icerts){
				if(currentCert.getSubject().equals(icert.getIssuer())){
					retval.add(0,icert); 		        	  
					currentCert = icert;
					break;
				}
			}
			icerts.remove(currentCert);
			tries--;
			if(tries == 0){
				log.error("Error constructing a complete ca certificate chain for issuer " + issuerid + ", validator " + validatorId + " worker " + workerId);
			}
		}
		
		return retval;
	}

	protected HashMap<Integer, Properties> getIssuerProperties(){
		if(issuerProperties == null){
		  issuerProperties = new HashMap<Integer, Properties>();
		  for(int i=1;i< ValidationServiceConstants.NUM_OF_SUPPORTED_ISSUERS;i++){
			  Properties issuerProps = ValidationHelper.getIssuerProperties(i, props);
			  if(issuerProps != null){
				  issuerProperties.put(i, issuerProps);
			  }
		  }
		}
		
	    return issuerProperties;	
	}

	/**
	 * get properties of the issuer that is configured to accept this certificate (through certchain)
	 * have to match using rootCert since in case of the intermediate CA certificate the chain will be cut off.
	 */
	protected Properties getIssuerProperties(ICertificate cert){
		
		if(getCertificateChain(cert) == null)
			return null;
		
		List<ICertificate> certChain = null;
		for(Integer issuerId : getIssuerProperties().keySet())
		{
			certChain= getCertChainFromProps(issuerId, getIssuerProperties().get(issuerId));
			if(certChain != null 
					&& certChain.get(certChain.size() - 1).equals(getCertificateChain(cert).get(getCertificateChain(cert).size() -1)))
				  return getIssuerProperties().get(issuerId);
		}
		
	    return null;	
	}

	/**
	 * Retrieve "cut off certificate chain" for the ca certificate given
	 * Certificate chain will be retrieved from configured certchain properties for issuers 
	 * 
	 * @return  
	 * 
	 * certificates starting from (not included) cACert up to root certificate, if cACert is intermediate CA certificate
	 * null if passed in certificate is not found in any configured chains or if cACert is root certificate
	 *  
	 */
	protected List<ICertificate> getCertificateChainForCACertificate(ICertificate cACert) {
		
		int indx = -1;
		for(String certDN : getCertChainMap().keySet())
		{
			indx = getCertChainMap().get(certDN).indexOf(cACert);
			if(indx != -1 && indx + 1 < getCertChainMap().get(certDN).size())
			{
				// found chain containing cACert
				// return sublist containing chain from this certificate (excluded) to root certificate (included)
				return getCertChainMap().get(certDN).subList(indx + 1, getCertChainMap().get(certDN).size());
			}
		}
		
		return null;
	}
	
	/**
	 * @return true if passed in certificate is found as root certificate in any of configured issuers
	 * 		   false otherwise 
	 */
	protected boolean isTrustAnchor(X509Certificate rootCACert)
	{
		if(getCertChainMap() == null)
			return false;
	
		// is it really a self signed certificate
		if(!rootCACert.getSubjectX500Principal().equals(rootCACert.getIssuerX500Principal()))
			return false;
		
		for(String certDN : getCertChainMap().keySet())
		{
			if(getCertChainMap().get(certDN).contains(rootCACert))
				return true;
		}
		
		return false;
	}
	
}
