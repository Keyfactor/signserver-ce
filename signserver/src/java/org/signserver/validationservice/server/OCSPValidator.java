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

import java.net.ConnectException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.X509Certificate;

/**
 * 
 * OCSP validator used for validating certificates using OCSP only for revocation checking
 * 
 * NOTE : properties introduced in J2SE5 such as : ocsp.enable,ocsp.responderURL and etc..  are not used since they
 * automatically failover to CRL in case OCSP encounters any problem. 
 * 
 * 
 * @author rayback2
 *
 */

public class OCSPValidator extends BaseValidator {
	

	public void testConnection() throws ConnectException, SignServerException {
		// TODO Test Internet connectivity, which is needed to access ocsp servers.
		// throw exception if not online

	}


	public Validation validate(ICertificate cert)
	throws IllegalRequestException, CryptoTokenOfflineException,
	SignServerException {

		//check certificate validity 
		X509Certificate xcert = (X509Certificate) cert;
		try {
			xcert.checkValidity();
		} catch (CertificateExpiredException e1) {
			return new Validation(cert,null,Validation.Status.EXPIRED,"Certificate has expired. " + e1.toString());
		} catch (CertificateNotYetValidException e1) {
			return new Validation(cert,null,Validation.Status.NOTYETVALID,"Certificate is not yet valid. " + e1.toString());
		}

		List<ICertificate> certChain = getCertificateChain(cert);
		// if no chain found for this certificate and if it is not trust anchor (as configured in properties) return null
		// if it is trust anchor return valid
		// NOTE : framework does not support validating trust anchors for now (Talk to Philip) so trust anchor will return issuer not supported instead of processing code below
		if(certChain == null ){
			if(isTrustAnchor(xcert))
				return new Validation(cert,Collections.singletonList(cert),Validation.Status.VALID,"This certificate is defined as Trust Anchor.");
			else
				return null;				
		}
				
		// certStore & certPath construction
		CertPath certPath = null;
		CertStore certStore  = null;
		List<Object> certs = new ArrayList<Object>();  
		CertificateFactory certFactory = null;
		CertPathValidator validator = null;
		PKIXParameters params = null;
		ICertificate rootCert = null;
		List<X509Certificate> certChainWithoutRootCert = new ArrayList<X509Certificate>(); 
		try {

			certFactory = CertificateFactory.getInstance("X509", "BC");

			// Initialize certStore with certificate chain and certificate in question
			certs.addAll(certChain);
			certs.add(cert);
			certStore  = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certs));

			// CertPath Construction
			for(ICertificate currentCACert: certChain)
			{
				X509Certificate x509currentCACert = (X509Certificate)currentCACert;
				if(rootCert == null 
						&& x509currentCACert.getSubjectX500Principal().equals(x509currentCACert.getIssuerX500Principal()))
				{
					rootCert = currentCACert;
				}
				else
				{
					// non root certificate
					certChainWithoutRootCert.add(x509currentCACert);
				}
			}
						
			// add certificate in question to certpath
			certChainWithoutRootCert.add((X509Certificate)cert);
			
			certPath = certFactory.generateCertPath(certChainWithoutRootCert);
			
			// init cerpathvalidator 
			validator = CertPathValidator.getInstance("PKIX", "BC");
			
			// init params
			TrustAnchor trustAnc = new TrustAnchor((X509Certificate)rootCert, null);
			params = new PKIXParameters(Collections.singleton(trustAnc));
			params.addCertStore(certStore);
			params.setDate(new Date());
			
			// disable default crl validaton
			params.setRevocationEnabled(false);
			// add custom ocsp pathchecker
			params.addCertPathChecker(new OCSPPathChecker((X509Certificate)rootCert, this.props));
			
		} catch (Exception e) {
			throw new SignServerException(e.toString());
		}


		//do actual validation
		PKIXCertPathValidatorResult cpv_result = null;
		try {
			cpv_result = (PKIXCertPathValidatorResult)validator.validate(certPath, params);
			//if we are down here then validation is successful
			return new Validation(cert,getCertificateChain(cert),Validation.Status.VALID,"This certificate is valid. Trust anchor for certificate is :" + cpv_result.getTrustAnchor().getTrustedCert().getSubjectDN());

		} catch (CertPathValidatorException e) {
			return new Validation(cert,getCertificateChain(cert),Validation.Status.DONTVERIFY,"Exception on validation. certificate causing exception : " + ((X509Certificate)e.getCertPath().getCertificates().get(e.getIndex())).getSubjectDN() + " " + e.toString());
		} catch (InvalidAlgorithmParameterException e) {
			throw new SignServerException(e.toString());
		}

	}


}
