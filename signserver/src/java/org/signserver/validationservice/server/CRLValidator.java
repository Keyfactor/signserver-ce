package org.signserver.validationservice.server;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.persistence.EntityManager;

import org.ejbca.util.CertTools;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.ValidationServiceConstants;
import org.signserver.validationservice.common.X509Certificate;

/**
 * CRL validator used for validating certificates using CRL only for revocation checking
 * 
 * CRL path discovery : look for certificate CRL Distribution points extension first (OID = 2.5.29.31)
 * if extension does not exist then look for  ISSUERX.CRLPATHS property to fetch CRL for issuer
 * 
 * NOTE : com.sun.security.enableCRLDP not used for CertPath validation, since the effect is unknown
 *  
 * @author 
 *
 */

public class CRLValidator extends BaseValidator {

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
		
		// if no chain found for this certificate and if it is not trust anchor (as configured in properties) return null
		// if it is trust anchor return valid
		// NOTE : framework does not support validating trust anchors for now (Talk to Philip) so trust anchor will return issuer not supported
		if(getCertificateChain(cert) == null ){
			if(isTrustAnchor(xcert))
				return new Validation(cert,Collections.singletonList(cert),Validation.Status.VALID,"This certificate is defined as Trust Anchor.");
			else
				return null;				
		}
		
		
		ICertificate rootCert = null; // represents root Certificate of the certificate in question
		List<X509Certificate> certChainWithoutRootCert = new ArrayList<X509Certificate>(); // chain without root for CertPath construction 
		List<URL> cDPURLs = new ArrayList<URL>(); // list of CDPs obtained from certificates 
		List<URL> CRLPaths = getIssuerCRLPaths(cert); 	// retrieved CRL paths from issuer properties

		// fetch crl's of requested certificate and all certificates in a chain
		URL certURL = null;
		X509Certificate x509CurrentCert = null;
		boolean atLeastOneCDPNotFound = false;
		Iterator<ICertificate> cACerts = getCertificateChain(cert).iterator();

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

				certURL = CertTools.getCrlDistributionPoint(x509CurrentCert);

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
						// non root certificate
						if(CRLPaths == null)
						{
							// the CDP could not be found for this non root certificate 
							// and the CRLPath property is not present for the issuer of this certificate
							// validation can not proceed
							throw new SignServerException("no CRL Distribution point specified for non root certificate : " 
									+ x509CurrentCert.getSubject() + ", and no CRLPath configured for Issuer");
						}
						else
						{
							// signal that at least one CDP not found, so validation has to include CRLPaths
							atLeastOneCDPNotFound = true;
						}
					}
				}
				else
					cDPURLs.add(certURL);

			} catch (Exception e) {
				throw new SignServerException(e.toString());
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
			certsAndCRLS.addAll(getCertificateChain(cert));
			certsAndCRLS.add(cert);

			//fetch CRLs obtained form the CDP extension of certificates
			for(URL url: cDPURLs)
			{
				certsAndCRLS.add(fetchCRLFromURL(url,certFactory));
			}
			
			// retrieve and add the crls from CRLPath property of issuer to certStore
			// in case all certificates have CDP extension, CRLPath is ignored
			if(atLeastOneCDPNotFound && CRLPaths != null)
			{
				for(URL url: CRLPaths)
				{
					certsAndCRLS.add(fetchCRLFromURL(url,certFactory));
				}
			}

			certStore  = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certsAndCRLS));
			
			// CertPath Construction
			certPath = certFactory.generateCertPath(certChainWithoutRootCert);
			
			// init cerpathvalidator 
			validator = CertPathValidator.getInstance("PKIX", "BC");
			
			// init params
			TrustAnchor trustAnc = new TrustAnchor((X509Certificate)rootCert, null);
			params = new PKIXParameters(Collections.singleton(trustAnc));
			params.addCertStore(certStore);
			params.setDate(new Date());
			
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
//			throw new SignServerException("Exception on validation. certificate causing exception : " + ((X509Certificate)e.getCertPath().getCertificates().get(e.getIndex())).getSubjectDN() + e.toString());
			return new Validation(cert,getCertificateChain(cert),Validation.Status.DONTVERIFY,"Exception on validation. certificate causing exception : " + ((X509Certificate)e.getCertPath().getCertificates().get(e.getIndex())).getSubjectDN() + e.toString());
		} catch (InvalidAlgorithmParameterException e) {
			throw new SignServerException(e.toString());
		}

	}

	/**
	 * retrieve X509CRL from specified URL
	 */
	private X509CRL fetchCRLFromURL(URL url, CertificateFactory certFactory) throws IOException, CRLException {
		URLConnection connection = url.openConnection();
		connection.setDoInput(true);
		connection.setUseCaches(false);
		DataInputStream inStream =
			new DataInputStream(connection.getInputStream());
		X509CRL crl = (X509CRL)certFactory.generateCRL(inStream);
		inStream.close();
		return crl;
	}

	/**
	 * find the issuer of this certificate and get the CRLPaths property which contains ; separated
	 * list of URLs for accessing crls for that specific issuer
	 * and return as List of URLs
	 * @throws SignServerException 
	 */
	private List<URL> getIssuerCRLPaths(ICertificate cert) throws SignServerException { 
		ArrayList<URL> retval = null;
		Properties props = getIssuerProperties(cert);
		if(props == null 
				|| !props.containsKey(ValidationServiceConstants.VALIDATIONSERVICE_ISSUERCRLPATHS))
			return null;
		
		retval = new ArrayList<URL>();
		
		StringTokenizer strTokenizer = new StringTokenizer(props.getProperty(ValidationServiceConstants.VALIDATIONSERVICE_ISSUERCRLPATHS),
				ValidationServiceConstants.VALIDATIONSERVICE_ISSUERCRLPATHSDELIMITER);
		
		while(strTokenizer.hasMoreTokens())
		{
			try {				
				retval.add(new URL(strTokenizer.nextToken()));
			} catch (MalformedURLException e) {
				throw new SignServerException("URL in CRLPATHS property for issuer is not valid. : " + e.toString());
			}	
		}
		
		return retval;
	}

}
