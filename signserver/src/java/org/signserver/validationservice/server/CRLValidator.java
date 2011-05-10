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
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.X509Certificate;

/**
 * CRL validator used for validating certificates using CRL only for revocation checking
 * 
 * CRL path discovery : look for certificate CRL Distribution points extension first (OID = 2.5.29.31)
 * if extension does not exist then look for  ISSUERX.CRLPATHS property to fetch CRL for issuer
 * 
 * NOTE : com.sun.security.enableCRLDP not used for CertPath validation, since it affects entire jvm.
 *  
 * @author rayback2
 *
 */

public class CRLValidator extends BaseValidator {

	private static final Logger log = Logger.getLogger(CRLValidator.class);
	/**
	 * @see org.signserver.validationservice.server.IValidator#init(int, java.util.Properties, javax.persistence.EntityManager, org.signserver.server.cryptotokens.IExtendedCryptoToken)
	 */
	public void init(int workerId, int validatorId, Properties props, EntityManager em,
			ICryptoToken ct) throws SignServerException {
		super.init(workerId, validatorId, props, em, ct);

	}


	public void testConnection() throws ConnectException, SignServerException {
		// TODO Test Internet connectivity, which is needed to fetch CRLs.
		// throw exception if not online 


	}


	/**
	 * this method is introduced for calling validator from other validators, not defined in config
	 * @param cert
	 * @param props
	 * @return
	 * @throws IllegalRequestException
	 * @throws CryptoTokenOfflineException
	 * @throws SignServerException
	 */
	public Validation validate(ICertificate cert, Properties props) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException
	{
		log.debug("CRL Validator's validate called with explicit properties");
		
		this.props = props;
		return validate(cert);		
	}
	
	public Validation validate(ICertificate cert)
	throws IllegalRequestException, CryptoTokenOfflineException,
	SignServerException {

		log.debug("CRL Validator's validate called with certificate " + cert.getSubject());
		
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
		
		log.debug("***********************");
		log.debug("printing certchain for "+ cert.getSubject());
		for(ICertificate tempcert : certChain)
			log.debug(tempcert.getSubject());
		log.debug("***********************");
		
		// if no chain found for this certificate and if it is not trust anchor (as configured in properties) return null
		// if it is trust anchor return valid
		if(certChain == null ){
			if(isTrustAnchor(xcert))
			{
				return new Validation(cert,Collections.singletonList(cert),Validation.Status.VALID,"This certificate is defined as Trust Anchor.");
			}
			else
			{
				return null;
			}
		}
		
		ICertificate rootCert = null; // represents root Certificate of the certificate in question
		List<X509Certificate> certChainWithoutRootCert = new ArrayList<X509Certificate>(); // chain without root for CertPath construction 
		List<URL> cDPURLs = new ArrayList<URL>(); // list of CDPs obtained from certificates 
		List<URL> CRLPaths = getIssuerCRLPaths(cert); 	// retrieved CRL paths from issuer properties

		// fetch crl's of requested certificate and all certificates in a chain
		URL certURL = null;
		X509Certificate x509CurrentCert = null;
		boolean atLeastOneCDPNotFound = false;
		Iterator<ICertificate> cACerts = certChain.iterator();

		//initialize first iteration with requested certificate and subsequent iterations with certificates from chain
		for(ICertificate currentCert = cert; ;currentCert = cACerts.next())
		{
			x509CurrentCert = (X509Certificate) currentCert; 
			
			// check validity of CA certificate
			if(!x509CurrentCert.equals(xcert))
			{
				try {
					x509CurrentCert.checkValidity();
				} catch (CertificateExpiredException e1) {
					return new Validation(cert,null,Validation.Status.CAEXPIRED,"CA Certificate : " + x509CurrentCert.getSubjectDN() + " has expired. " + e1.toString());
				} catch (CertificateNotYetValidException e1) {
					return new Validation(cert,null,Validation.Status.CANOTYETVALID,"CA Certificate : " + x509CurrentCert.getSubjectDN()+ " is not yet valid. " + e1.toString());
				}
			}
			
			try {

				try {
					certURL = CertTools.getCrlDistributionPoint(x509CurrentCert);
				} catch(CertificateParsingException ex) {
					if(log.isDebugEnabled()) {
						// CertTools.getCrlDistributionPoint throws an exception if it can't find an URL
						log.debug("No CRL distribution point URL found: " + ex.getMessage(), ex);
					}
				}

				if(rootCert == null 
						&& x509CurrentCert.getSubjectX500Principal().equals(x509CurrentCert.getIssuerX500Principal()))
				{
					// root certificate found ! (self signed)
					// assumption : one root certificate per chain. wrong formed chains are not handled
					rootCert = currentCert;
				}
				else
				{
					// non root certificate
					certChainWithoutRootCert.add(x509CurrentCert);
				}

				if(certURL == null)
				{
					if((rootCert == null || !Arrays.equals(rootCert.getEncoded(), currentCert.getEncoded())))
					{
						log.debug("CDP not found for non root certificate " + x509CurrentCert.getSubject());
						// non root certificate
						if(CRLPaths == null)
						{
							// the CDP could not be found for this non root certificate 
							// and the CRLPath property is not present for the issuer of this certificate
							// validation can not proceed
							String msg ="no CRL Distribution point specified for non root certificate : " 
								+ x509CurrentCert.getSubject() + ", and no CRLPath configured for Issuer";
							
							log.error(msg);
							throw new SignServerException(msg);
						}
						else
						{
							log.debug("setting atLeastOneCDPNotFound to true, to signal usage of configured CRLPaths");
							// signal that at least one CDP not found, so validation has to include CRLPaths
							atLeastOneCDPNotFound = true;
						}
					}
				}
				else
					cDPURLs.add(certURL);

			} catch (Exception e) {
				throw new SignServerException(e.toString(), e);
			}

			if(!cACerts.hasNext())
				break;
		}


		// certStore & certPath construction
		CertPath certPath = null;
		CertStore certStore  = null;
		List<Object> certsAndCRLS = new ArrayList<Object>(); // object ?, specified to suppress warnings but is it good way ? 
		CertificateFactory certFactory = null;
		CertPathValidator validator = null;
		PKIXParameters params = null;
		try {
			certFactory = CertificateFactory.getInstance("X509", "BC");

			// Initialize certStore with certificate chain and certificate in question
			certsAndCRLS.addAll(certChain);
			certsAndCRLS.add(cert);

			//fetch CRLs obtained form the CDP extension of certificates
			for(URL url: cDPURLs)
			{
				certsAndCRLS.add(ValidationUtils.fetchCRLFromURL(url,certFactory));
			}
			
			// retrieve and add the crls from CRLPath property of issuer to certStore
			// in case all certificates have CDP extension, CRLPath is ignored
			if(atLeastOneCDPNotFound && CRLPaths != null)
			{
				for(URL url: CRLPaths)
				{
					certsAndCRLS.add(ValidationUtils.fetchCRLFromURL(url,certFactory));
				}
			}

			certStore  = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certsAndCRLS));
			
			log.debug("***********************");
			log.debug("printing certs in certstore");
			Iterator<?> tempIter = certStore.getCertificates(null).iterator();
			while(tempIter.hasNext())
			{
				X509Certificate tempcert = (X509Certificate)tempIter.next();
				log.debug(tempcert.getSubject() + " issuer is " + tempcert.getIssuer());
			}
			log.debug("***********************");
			
			// CertPath Construction
			certPath = certFactory.generateCertPath(certChainWithoutRootCert);
			
			log.debug("***********************");
			log.debug("printing certs in certpath");
			for(Certificate tempcert : certPath.getCertificates())
				log.debug(((X509Certificate)tempcert).getSubject() + " issuer is " + ((X509Certificate)tempcert).getIssuer());
			log.debug("***********************");
			
			// init cerpathvalidator 
			validator = CertPathValidator.getInstance("PKIX", "BC");
			
			// init params
			TrustAnchor trustAnc = new TrustAnchor((X509Certificate)rootCert, null);
			params = new PKIXParameters(Collections.singleton(trustAnc));
			params.addCertStore(certStore);
			params.setDate(new Date());
			
			log.debug("***********************");
			log.debug("printing trust anchor "+ trustAnc.getTrustedCert().getSubjectDN().getName());
			log.debug("***********************");
			
		} catch (Exception e) {
			log.error("Exception on preparing parameters for validation", e);
			throw new SignServerException(e.toString(), e);
		}


		//do actual validation
		PKIXCertPathValidatorResult cpv_result = null;
		try {
			cpv_result = (PKIXCertPathValidatorResult)validator.validate(certPath, params);
			//if we are down here then validation is successful
			return new Validation(cert,certChain,Validation.Status.VALID,"This certificate is valid. Trust anchor for certificate is :" + cpv_result.getTrustAnchor().getTrustedCert().getSubjectDN());

		} catch (CertPathValidatorException e) {
			log.debug("certificate is not valid.", e);
			return new Validation(cert,certChain,Validation.Status.DONTVERIFY,"Exception on validation. certificate causing exception : " + ((X509Certificate)e.getCertPath().getCertificates().get(e.getIndex())).getSubjectDN() + e.toString());
		} catch (InvalidAlgorithmParameterException e) {
			log.error("Exception on validation", e);
			throw new SignServerException("Exception on validation.",e);
		}

	}

}
