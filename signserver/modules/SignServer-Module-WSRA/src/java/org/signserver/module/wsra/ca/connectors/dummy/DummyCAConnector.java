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
 
package org.signserver.module.wsra.ca.connectors.dummy;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.ConnectException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

import org.ejbca.util.CertTools;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.module.wsra.ca.ICertRequestData;
import org.signserver.module.wsra.ca.connectors.AlreadyRevokedException;
import org.signserver.module.wsra.ca.connectors.BaseCAConnector;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.Validation;

/**
 * A dummy implementation that simulates an issuer and generates
 * dummy certificates from a dummy CA. It is stored in a
 * file in USER_HOME/dummyca-<issuercn>.data file.
 * 
 * This connector is supposed to be used in test scripts and
 * demo environments.
 * 
 * 
 * @author Philip Vendil 19 okt 2008
 *
 * @version $Id$
 */

public class DummyCAConnector extends BaseCAConnector {
	
	/**
	 * Prefix setting used for issuer specific settings.
	 * should b constructed like the following
	 * ISSUER<id>.<setting>
	 */
	public static final String ISSUER_PREFIX = "ISSUER";
	/**
	 * Setting indicated the issuer DN of a supported issuer.
	 * This DN should be unique. 
	 * <p>
	 * Important, the CN in DN should also be unique.
	 */
	public static final String DN_SETTING = ".DN";

	HashMap<String,DummyCAData> issuerMap = new HashMap<String,DummyCAData>();
	
	public void init(int workerId, int connectorId, Properties props,
			ICryptoToken ct) throws SignServerException {		
		super.init(workerId, connectorId, props, ct);
		
		for(String issuerDN : getAllSubjectDNs()){
			String fileName = DummyCAData.getStoreFileName(issuerDN);
			File file = new File(fileName);
			DummyCAData ca;
			try{
				if(file.exists()){					
					FileInputStream fis= new FileInputStream(fileName);
					ObjectInputStream ois = new ObjectInputStream(fis);
					ca = (DummyCAData) ois.readObject();
				}else{					
                    ca = new DummyCAData(issuerDN, props);
				}
			  issuerMap.put(issuerDN, ca);
			}catch(FileNotFoundException e){
				throw new SignServerException("Error when initializing dummy CAs : " +e.getMessage(),e);
			} catch (IOException e) {
				throw new SignServerException("Error when initializing dummy CAs : " +e.getMessage(),e);
			} catch (ClassNotFoundException e) {
				throw new SignServerException("Error when initializing dummy CAs : " +e.getMessage(),e);
			}			
		}
		
	}
	
	/**
	 * @see org.signserver.module.wsra.ca.connectors.ICAConnector#getCACertificateChain(java.lang.String)
	 */
	public List<ICertificate> getCACertificateChain(String issuerDN)
			throws SignServerException {		
		return issuerMap.get(issuerDN).getCACertificateChain(); 
	}

	/**
	 * @see org.signserver.module.wsra.ca.connectors.ICAConnector#getCertificateStatus(java.lang.String, java.security.cert.Certificate)
	 */
	public Validation getCertificateStatus(ICertificate certificate) {
		return issuerMap.get(certificate.getIssuer()).getCertificateStatus(certificate);
	}

	/**
	 * @see org.signserver.module.wsra.ca.connectors.ICAConnector#getSupportedIssuerDN()
	 */
	public List<String> getSupportedIssuerDN() {
		return getAllSubjectDNs();
	}

	/**
	 * @see org.signserver.module.wsra.ca.connectors.ICAConnector#requestCertificate(java.lang.String, org.signserver.module.wsra.ca.ICertRequestData)
	 */
	public ICertificate requestCertificate(ICertRequestData certReqData) throws IllegalRequestException,
			SignServerException {
		return issuerMap.get(certReqData.getIssuerDN()).requestCertificate(certReqData);
	}

	/**
	 * 
	 * @see org.signserver.module.wsra.ca.connectors.ICAConnector#revokeCertificate(java.lang.String, java.security.cert.Certificate, int)
	 */
	public void revokeCertificate(ICertificate cert, int reason)
			throws IllegalRequestException, SignServerException, AlreadyRevokedException {
		issuerMap.get(cert.getIssuer()).revokeCertificate(cert, reason);

	}

	/**
	 * @see org.signserver.module.wsra.ca.connectors.ICAConnector#testConnection()
	 */
	public void testConnection() throws ConnectException, SignServerException {
		// Do Nothing
	}


    List<String> getAllSubjectDNs(){
    	List<String> retval = new ArrayList<String>();
    	Enumeration<?> propNames = props.propertyNames();
    	while(propNames.hasMoreElements()){
    		String key = (String) propNames.nextElement();
    		if(key.startsWith(ISSUER_PREFIX) && key.endsWith(DN_SETTING)){
    			retval.add(CertTools.stringToBCDNString(props.getProperty(key)));
    		}
    	}
    	
    	return retval;
    	
    }

  
	
	
}
