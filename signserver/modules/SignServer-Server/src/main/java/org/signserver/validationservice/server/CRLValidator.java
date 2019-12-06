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
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.validationservice.common.Validation;

/**
 * CRL validator used for validating certificates using CRL only for revocation 
 * checking.
 * 
 * CRL path discovery : look for certificate CRL Distribution points extension first (OID = 2.5.29.31)
 * if extension does not exist then look for  ISSUERX.CRLPATHS property to fetch CRL for issuer
 * 
 * NOTE : com.sun.security.enableCRLDP not used for CertPath validation, since it affects entire jvm.
 *  
 * @author rayback2
 * @version $Id$
 */
public class CRLValidator extends BaseValidator {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CRLValidator.class);

    /**
     * @param workerId
     * @param validatorId
     * @param props
     * @param em
     * @throws org.signserver.common.SignServerException
     * @see org.signserver.validationservice.server.IValidator#init(int, int, java.util.Properties, javax.persistence.EntityManager, org.signserver.server.cryptotokens.ICryptoToken)
     */
    @Override
    public void init(int workerId, int validatorId, Properties props, EntityManager em) throws SignServerException {
        super.init(workerId, validatorId, props, em);

    }

    @Override
    public void testConnection() throws ConnectException, SignServerException {
        // TODO Test Internet connectivity, which is needed to fetch CRLs.
        // throw exception if not online 
    }

    /**
     * this method is introduced for calling validator from other validators, not defined in config
     * @param cert
     * @param props
     * @return the validation result
     * @throws IllegalRequestException
     * @throws CryptoTokenOfflineException
     * @throws SignServerException
     */
    public Validation validate(Certificate cert, Properties props) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        LOG.debug("CRL Validator's validate called with explicit properties");

        this.props = props;
        return validate(cert);
    }

    @Override
    public Validation validate(Certificate cert)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {

        LOG.debug("CRL Validator's validate called with certificate " + CertTools.getSubjectDN(cert));

        //check certificate validity 
        X509Certificate xcert = (X509Certificate) cert;
        try {
            xcert.checkValidity();
        } catch (CertificateExpiredException e1) {
            return new Validation(cert, null, Validation.Status.EXPIRED, "Certificate has expired. " + e1.toString());
        } catch (CertificateNotYetValidException e1) {
            return new Validation(cert, null, Validation.Status.NOTYETVALID, "Certificate is not yet valid. " + e1.toString());
        }

        List<Certificate> certChain = getCertificateChain(cert);
        // if no chain found for this certificate and if it is not trust anchor (as configured in properties) return null
        // if it is trust anchor return valid
        if (certChain == null) {
            if (isTrustAnchor(xcert)) {
                return new Validation(cert, Collections.singletonList(cert), Validation.Status.VALID, "This certificate is defined as Trust Anchor.");
            } else {
                return null;
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("***********************");
            LOG.debug("printing certchain for " + CertTools.getSubjectDN(cert));
            for (Certificate tempcert : certChain) {
                LOG.debug(CertTools.getSubjectDN(tempcert));
            }
            LOG.debug("***********************");
        }
        Certificate rootCert = null; // represents root Certificate of the certificate in question
        List<X509Certificate> certChainWithoutRootCert = new ArrayList<>(); // chain without root for CertPath construction 
        List<URL> cDPURLs = new ArrayList<>(); // list of CDPs obtained from certificates 
        List<URL> CRLPaths = getIssuerCRLPaths(cert); 	// retrieved CRL paths from issuer properties

        // fetch crl's of requested certificate and all certificates in a chain
        URL certURL = null;
        X509Certificate x509CurrentCert;
        boolean atLeastOneCDPNotFound = false;
        Iterator<Certificate> cACerts = certChain.iterator();

        //initialize first iteration with requested certificate and subsequent iterations with certificates from chain
        for (Certificate currentCert = cert;; currentCert = cACerts.next()) {
            x509CurrentCert = (X509Certificate) currentCert;

            // check validity of CA certificate
            if (!x509CurrentCert.equals(xcert)) {
                try {
                    x509CurrentCert.checkValidity();
                } catch (CertificateExpiredException e1) {
                    return new Validation(cert, null, Validation.Status.CAEXPIRED, "CA Certificate : " + x509CurrentCert.getSubjectDN() + " has expired. " + e1.toString());
                } catch (CertificateNotYetValidException e1) {
                    return new Validation(cert, null, Validation.Status.CANOTYETVALID, "CA Certificate : " + x509CurrentCert.getSubjectDN() + " is not yet valid. " + e1.toString());
                }
            }

            try {

                try {
                    certURL = CertTools.getCrlDistributionPoint(x509CurrentCert);
                } catch (Exception ex) {
                    if (LOG.isDebugEnabled()) {
                        // CertTools.getCrlDistributionPoint throws an exception if it can't find an URL
                        LOG.debug("No CRL distribution point URL found: " + ex.getMessage(), ex);
                    }
                }

                if (rootCert == null
                        && x509CurrentCert.getSubjectX500Principal().equals(x509CurrentCert.getIssuerX500Principal())) {
                    // root certificate found ! (self signed)
                    // assumption : one root certificate per chain. wrong formed chains are not handled
                    rootCert = currentCert;
                } else {
                    // non root certificate
                    certChainWithoutRootCert.add(x509CurrentCert);
                }

                if (certURL == null) {
                    if ((rootCert == null || !Arrays.equals(rootCert.getEncoded(), currentCert.getEncoded()))) {
                        LOG.debug("CDP not found for non root certificate " + CertTools.getSubjectDN(x509CurrentCert));
                        // non root certificate
                        if (CRLPaths == null) {
                            // the CDP could not be found for this non root certificate 
                            // and the CRLPath property is not present for the issuer of this certificate
                            // validation can not proceed
                            String msg = "no CRL Distribution point specified for non root certificate : "
                                    + CertTools.getSubjectDN(x509CurrentCert) + ", and no CRLPath configured for Issuer";

                            LOG.error(msg);
                            throw new SignServerException(msg);
                        } else {
                            LOG.debug("setting atLeastOneCDPNotFound to true, to signal usage of configured CRLPaths");
                            // signal that at least one CDP not found, so validation has to include CRLPaths
                            atLeastOneCDPNotFound = true;
                        }
                    }
                } else {
                    cDPURLs.add(certURL);
                }
            } catch (Exception e) {
                throw new SignServerException(e.toString(), e);
            }

            if (!cACerts.hasNext()) {
                break;
            }
        }


        // certStore & certPath construction
        CertPath certPath = null;
        CertStore certStore;
        List<Object> certsAndCRLS = new ArrayList<>(); // object ?, specified to suppress warnings but is it good way ? 
        CertificateFactory certFactory;
        CertPathValidator validator = null;
        PKIXParameters params = null;
        try {
            certFactory = CertificateFactory.getInstance("X509", "BC");

            // Initialize certStore with certificate chain and certificate in question
            certsAndCRLS.addAll(certChain);
            certsAndCRLS.add(cert);

            //fetch CRLs obtained form the CDP extension of certificates
            for (URL url : cDPURLs) {
                certsAndCRLS.add(ValidationUtils.fetchCRLFromURL(url, certFactory));
            }

            // retrieve and add the crls from CRLPath property of issuer to certStore
            // in case all certificates have CDP extension, CRLPath is ignored
            if (atLeastOneCDPNotFound && CRLPaths != null) {
                for (URL url : CRLPaths) {
                    certsAndCRLS.add(ValidationUtils.fetchCRLFromURL(url, certFactory));
                }
            }

            certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certsAndCRLS));

            if (LOG.isDebugEnabled()) {
                LOG.debug("***********************");
                LOG.debug("printing certs in certstore");
                Iterator<?> tempIter = certStore.getCertificates(null).iterator();
                while (tempIter.hasNext()) {
                    X509Certificate tempcert = (X509Certificate) tempIter.next();
                    LOG.debug(CertTools.getSubjectDN(tempcert) + " issuer is " + CertTools.getIssuerDN(tempcert));
                }
                LOG.debug("***********************");
            }

            // CertPath Construction
            certPath = certFactory.generateCertPath(certChainWithoutRootCert);

            if (LOG.isDebugEnabled()) {
                LOG.debug("***********************");
                LOG.debug("printing certs in certpath");
                for (Certificate tempcert : certPath.getCertificates()) {
                    LOG.debug(CertTools.getSubjectDN(((X509Certificate) tempcert)) + " issuer is " + CertTools.getIssuerDN(((X509Certificate) tempcert)));
                }
                LOG.debug("***********************");
            }

            // init cerpathvalidator 
            validator = CertPathValidator.getInstance("PKIX", "BC");

            // init params
            TrustAnchor trustAnc = new TrustAnchor((X509Certificate) rootCert, null);
            params = new PKIXParameters(Collections.singleton(trustAnc));
            params.addCertStore(certStore);
            params.setDate(new Date());

            if (LOG.isDebugEnabled()) {
                LOG.debug("***********************");
                LOG.debug("printing trust anchor " + trustAnc.getTrustedCert().getSubjectDN().getName());
                LOG.debug("***********************");
            }
        } catch (Exception e) {
            LOG.error("Exception on preparing parameters for validation", e);
            throw new SignServerException(e.toString(), e);
        }


        //do actual validation
        PKIXCertPathValidatorResult cpv_result;
        try {
            cpv_result = (PKIXCertPathValidatorResult) validator.validate(certPath, params);
            //if we are down here then validation is successful
            return new Validation(cert, certChain, Validation.Status.VALID, "This certificate is valid. Trust anchor for certificate is :" + cpv_result.getTrustAnchor().getTrustedCert().getSubjectDN());

        } catch (CertPathValidatorException e) {
            LOG.debug("certificate is not valid.", e);
            return new Validation(cert, certChain, Validation.Status.DONTVERIFY, "Exception on validation. certificate causing exception : " + ((X509Certificate) e.getCertPath().getCertificates().get(e.getIndex())).getSubjectDN() + e.toString());
        } catch (InvalidAlgorithmParameterException e) {
            LOG.error("Exception on validation", e);
            throw new SignServerException("Exception on validation.", e);
        }

    }
}
