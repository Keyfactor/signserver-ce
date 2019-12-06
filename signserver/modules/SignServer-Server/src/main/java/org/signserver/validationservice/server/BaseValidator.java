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
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.signserver.common.SignServerException;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.validationservice.common.ValidationServiceConstants;

/**
 * Base class implementing the base functionality for a certificate validator.
 * 
 * @author Philip Vendil 30 nov 2007
 * @version $Id$
 */
public abstract class BaseValidator implements IValidator {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(BaseValidator.class);
    
    protected int workerId;
    protected int validatorId;
    protected Properties props;
    protected EntityManager em;
    private HashMap<String, List<Certificate>> certChainMap;
    private HashMap<Integer, Properties> issuerProperties;

    /*
     * certificate chains for all issuers
     */
    protected HashMap<String, List<Certificate>> getCertChainMap() {
        if (certChainMap == null) {
            certChainMap = new HashMap<>();
            for (Integer issuerId : getIssuerProperties().keySet()) {
                Properties issuerProps = getIssuerProperties().get(issuerId);

                List<Certificate> certChain = getCertChainFromProps(issuerId, issuerProps);
                if (certChain != null) {
                    certChainMap.put(CertTools.getSubjectDN(certChain.get(0)), certChain);
                }
            }
        }

        return certChainMap;
    }

    /**
     * @throws SignServerException
     * @see org.signserver.validationservice.server.IValidator#init(int, int, java.util.Properties, javax.persistence.EntityManager, org.signserver.server.cryptotokens.ICryptoToken)
     */
    @Override
    public void init(int workerId, int validatorId, Properties props, EntityManager em) throws SignServerException {
        this.workerId = workerId;
        this.validatorId = validatorId;
        this.props = props;
        this.em = em;
    }

    /**
     * Retrieves certificate chain for certificate given
     * Certificate chain will be retrieved from configured certchain properties for issuers 
     * 
     * @param cert given certificate
     * @return certificates starting from the CA certificate issuing this end entity cert up to root certificate, if issuer is found in configured chains
     * null if passed in certificate's issuer is not in any of the configured chains
     * 
     */
    @Override
    public List<Certificate> getCertificateChain(Certificate cert) {
        LOG.trace(">getCertificateChain: " + CertTools.getSubjectDN(cert));

        if (getCertChainMap() == null) {
            return null;
        }

        X509Certificate x509Cert = (X509Certificate) cert;

        List<Certificate> retVal;
        //first look if the certificate is directly issued by CA that is in the beginning of the one of configured chains
        //"in the beginning" here means that the issuer of the certificate is at position 0 after sortCerts method is called
        //it is easy to check since the CA Certificate at position 0 is the key to HashMap holding certificate chains
        retVal = getCertChainMap().get(CertTools.getIssuerDN(x509Cert));
        if (retVal == null) {
            //look if cert is issued by some CA that is in the middle of the one of configured chains
            //"in the middle" here means that issuer of this certificate is not at position 0 after sortCerts method is called
            //match is done on issuerDN and authorityKeyIdentifier (if exists)
            X509Certificate issuerCACert = null;
            byte[] aki;
            boolean issuerFound = false;
            for (String certDN : getCertChainMap().keySet()) {
                for (Certificate cACert : getCertChainMap().get(certDN)) {
                    issuerCACert = (X509Certificate) cACert;

                    //check if subject of CA and the issuer of our certificate match
                    if (issuerCACert.getSubjectX500Principal().equals(x509Cert.getIssuerX500Principal())) {
                        //now check if AuthorityKeyIdentifier of our cert (if exists) match the SubjectKeyIdentifier of CA
                        try {
                            if ((aki = CertTools.getAuthorityKeyId(x509Cert)) != null && aki.length > 0) {
                                byte[] ski = CertTools.getSubjectKeyId(issuerCACert);
                                if (ski != null && Arrays.equals(aki, ski)) //if cert contains AKI then CA must contain SKI.
                                {
                                    issuerFound = true;
                                    break;
                                }
                            } else {
                                //authority key identifier extension is not found
                                //so match on SubjectDN is considered good enough
                                issuerFound = true;
                                break;
                            }
                        } catch (IllegalStateException e) {
                            // eat up the exception to continue looping
                            LOG.error(e.getMessage(), e);
                        }
                    }
                }
                if (issuerFound) {
                    break;
                }
            }

            //if issuer is found then IssuerCACert holds our issuer certificate
            //so return certificate chain INCLUDING the issuer and up to root
            if (issuerFound) {
                retVal = getCertificateChainForCACertificate(issuerCACert, true);
            }
        }
        LOG.trace(">getCertificateChain");
        return retVal;
    }

    /**
     * Fetches certificate chain.
     * 
     * @param issuerProps issuer properties
     * @return List of CA certificates with the root certificate last or null if no chain is configured.
     */
    private List<Certificate> getCertChainFromProps(int issuerId, Properties issuerProps) {
        List<Certificate> retval = null;
        if (issuerProps.getProperty(ValidationServiceConstants.VALIDATIONSERVICE_ISSUERCERTCHAIN) == null) {
            LOG.error("Error required issuer setting " + ValidationServiceConstants.VALIDATIONSERVICE_ISSUERCERTCHAIN + " is missing for issuer "
                    + issuerId + ", validator id " + validatorId + ", worker id" + workerId);
        } else {
            try {
                Collection<?> certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(issuerProps.getProperty(ValidationServiceConstants.VALIDATIONSERVICE_ISSUERCERTCHAIN).getBytes()));
                Iterator<?> certiter = certs.iterator();
                ArrayList<Certificate> icerts = new ArrayList<>();
                while (certiter.hasNext()) {
                    icerts.add((Certificate) certiter.next());
                }
                int initialSize = icerts.size();
                retval = sortCerts(issuerId, icerts);
                if (retval.size() != initialSize) {
                    retval = null;
                }

            } catch (CertificateException | IllegalStateException e) {
                LOG.error("Error constructing certificate chain from setting " + ValidationServiceConstants.VALIDATIONSERVICE_ISSUERCERTCHAIN + " is missing for issuer "
                        + issuerId + ", validator id " + validatorId + ", worker id" + workerId, e);
            }
        }

        return retval;
    }

    /**
     * Method sorting the certificate with the root certificate last.
     * @param icerts ICertificates
     * @return
     */
    ArrayList<Certificate> sortCerts(final int issuerid,
            final ArrayList<Certificate> icerts) {
        LOG.trace(">sortCerts");
        final ArrayList<Certificate> retval = new ArrayList<>();

        // Start with finding root
        Certificate currentCert = null;
        for (Certificate icert : icerts) {
            if (CertTools.getIssuerDN(icert).equals(CertTools.getSubjectDN(icert))) {
                retval.add(0, icert);
                currentCert = icert;
                break;
            }
        }
        icerts.remove(currentCert);

        if (retval.isEmpty()) {
            LOG.error("Error in certificate chain, no root certificate for issuer "
                    + issuerid + ", validator " + validatorId + " worker " + workerId);
        }

        int tries = 10;
        while (!icerts.isEmpty() && tries > 0) {
            for (Certificate icert : icerts) {
                if (CertTools.getSubjectDN(currentCert).equals(CertTools.getIssuerDN(icert))) {
                    retval.add(0, icert);
                    currentCert = icert;
                    break;
                }
            }
            icerts.remove(currentCert);
            tries--;
            if (tries == 0) {
                LOG.error("Error constructing a complete ca certificate chain for issuer " + issuerid + ", validator " + validatorId + " worker " + workerId);
            }
        }

        LOG.trace("<sortCerts");
        return retval;
    }

    protected HashMap<Integer, Properties> getIssuerProperties() {
        if (issuerProperties == null) {
            issuerProperties = new HashMap<>();
            for (int i = 1; i < ValidationServiceConstants.NUM_OF_SUPPORTED_ISSUERS; i++) {
                Properties issuerProps = ValidationHelper.getIssuerProperties(i, props);
                if (issuerProps != null) {
                    issuerProperties.put(i, issuerProps);
                }
            }
        }

        return issuerProperties;
    }

    /**
     * Get properties of the issuer that is configured to accept this certificate (through certchain)
     * have to match using rootCert and down the chain, until the chain for cert is exhausted.
     * 
     * @param cert Given certificate
     * @return Properties of the issuer
     */
    protected Properties getIssuerProperties(Certificate cert) {

        List<Certificate> certChain = getCertificateChain(cert);
        if (certChain == null) {
            return null;
        }

        List<Certificate> tempCertChain;

        //first search for exact match
        for (Integer issuerId : getIssuerProperties().keySet()) {
            tempCertChain = getCertChainFromProps(issuerId, getIssuerProperties().get(issuerId));
            if (tempCertChain != null) {
                if (tempCertChain.equals(certChain)) {
                    LOG.debug("issuer ID of certificate " + CertTools.getSubjectDN(cert) + " is " + issuerId + " Exact match");
                    return getIssuerProperties().get(issuerId);
                }
            }
        }

        //exact match not found , find containing
        for (Integer issuerId : getIssuerProperties().keySet()) {
            tempCertChain = getCertChainFromProps(issuerId, getIssuerProperties().get(issuerId));
            if (tempCertChain != null) {
                if (tempCertChain.containsAll(certChain)) {
                    LOG.debug("issuer ID of certificate " + CertTools.getSubjectDN(cert) + " is " + issuerId + " ContainsAll match");
                    return getIssuerProperties().get(issuerId);
                }
            }
        }

        return null;
    }

    /**
     * Retrieve "cut off certificate chain" for the ca certificate given
     * Certificate chain will be retrieved from configured certchain properties for issuers 
     * 
     * @param cACert - CA Certificate whose chain is sought
     * @param includeSelfInReturn - if true cACert is included in returned List of certificates, if false it is excluded
     * @return  
     * 
     * certificates starting from cACert up to root certificate, if cACert is intermediate CA certificate.  
     * null if passed in certificate is not found in any configured chains or if cACert is root certificate and includeSelfInReturn parameter is false
     *  
     */
    protected List<Certificate> getCertificateChainForCACertificate(Certificate cACert, boolean includeSelfInReturn) {

        int indx;
        int fromindex;
        for (String certDN : getCertChainMap().keySet()) {
            indx = getCertChainMap().get(certDN).indexOf(cACert);
            if (indx != -1) {
                if (includeSelfInReturn) {
                    fromindex = indx;
                } else {
                    fromindex = indx + 1;
                }

                if (fromindex < getCertChainMap().get(certDN).size()) {
                    // found chain containing cACert
                    // return sublist containing chain sought
                    return getCertChainMap().get(certDN).subList(fromindex, getCertChainMap().get(certDN).size());
                }
            }
        }

        return null;
    }

    /**
     * @param rootCACert Root CA certificate
     * @return true if passed in certificate is found as root certificate in any of configured issuers
     * 		   false otherwise 
     */
    protected boolean isTrustAnchor(X509Certificate rootCACert) {
        if (getCertChainMap() == null) {
            return false;
        }
        // is it really a self signed CA certificate
        if (rootCACert.getBasicConstraints() == -1 || !rootCACert.getSubjectX500Principal().equals(rootCACert.getIssuerX500Principal())) {
            return false;
        }

        for (String certDN : getCertChainMap().keySet()) {
            if (getCertChainMap().get(certDN).contains(rootCACert)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Find the issuer of this certificate and get the CRLPaths property which contains VALIDATIONSERVICE_ISSUERCRLPATHSDELIMITER separated
     * list of URLs for accessing crls for that specific issuer
     * and return as List of URLs.
     * 
     * @param cert Given certificate
     * @return List of CRL URLs
     * @throws SignServerException 
     */
    protected List<URL> getIssuerCRLPaths(Certificate cert) throws SignServerException {
        ArrayList<URL> retval;
        Properties issuerProps = getIssuerProperties(cert);
        if (issuerProps == null || !issuerProps.containsKey(ValidationServiceConstants.VALIDATIONSERVICE_ISSUERCRLPATHS)) {
            return null;
        }
        retval = new ArrayList<>();

        StringTokenizer strTokenizer = new StringTokenizer(issuerProps.getProperty(ValidationServiceConstants.VALIDATIONSERVICE_ISSUERCRLPATHS),
                ValidationServiceConstants.VALIDATIONSERVICE_ISSUERCRLPATHSDELIMITER);

        // Note that this DEBUG log loop also does some real work!
        LOG.debug("***********************");
        LOG.debug("printing CRLPATHS ");
        while (strTokenizer.hasMoreTokens()) {
            try {
                String nextToken = strTokenizer.nextToken().trim();
                LOG.debug(nextToken);
                retval.add(new URL(nextToken));
            } catch (MalformedURLException e) {
                throw new SignServerException("URL in CRLPATHS property for issuer is not valid. : " + e.toString());
            }
        }
        LOG.debug("***********************");

        return retval;
    }
}
