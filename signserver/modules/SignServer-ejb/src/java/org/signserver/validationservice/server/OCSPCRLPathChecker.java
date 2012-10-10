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
import java.net.URL;
import java.security.NoSuchProviderException;
import java.security.cert.*;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.ejbca.util.CertTools;
import org.signserver.common.SignServerException;

/**
 * Stateful OCSP fail over to CRL PKIX certificate path checker. It does not
 * support forward checking (reverse is must by default) because we want
 * certificates to be presented from trust anchor (not included) to the target
 * certificate
 * 
 * OCSP is tried first, if ocsp is not available (or any other answer than GOOD
 * or REVOKED) received fails over to CRL
 * 
 * NOTE : indirect CRLs are not supported at the moment (i.e. crls are issued by
 * CA issuing certificate) NOTE1 : scopes of crls are not checked
 * 
 * NOTE2 : support for forward checking could be enabled by searching issuer
 * certificate of certificate in question and making it stateless.
 * 
 * @author rayback2
 * @version $Id$
 */
public class OCSPCRLPathChecker extends OCSPPathChecker {

    private List<URL> cRLPaths;

    public void setCRLPaths(List<URL> cRLPaths) {
        this.cRLPaths = cRLPaths;
    }

    public List<URL> getCRLPaths() {
        return cRLPaths;
    }

    public OCSPCRLPathChecker(X509Certificate rootCACert, Properties props,
            List<X509Certificate> authorizedOCSPResponderCerts,
            List<URL> cRLPaths) {
        super(rootCACert, props, authorizedOCSPResponderCerts);
        this.cRLPaths = cRLPaths;
    }

    public void check(Certificate cert, Collection<String> unresolvedCritExts)
            throws CertPathValidatorException {

        String oCSPURLString = null;
        boolean failOverToCRL = false;

        if (!(cert instanceof X509Certificate)) {
            throw new CertPathValidatorException(
                    "Certificate passed to check method of OCSPCRLPathChecker is not of type X509Certificate");
        }

        if (cACert == null) {
            cACert = rootCACert;
        }
        X509Certificate x509Cert = (X509Certificate) cert;

        if (cACert == null) {
            throw new CertPathValidatorException("Issuer of certificate : "
                    + CertTools.getSubjectDN(x509Cert)
                    + " not passed to OCSPCRLPathChecker");
        }
        log.debug("check method called with certificate "
                + CertTools.getSubjectDN(x509Cert));

        // check if OCSP access address exists
        try {
            oCSPURLString = CertTools.getAuthorityInformationAccessOcspUrl(x509Cert);
        } catch (CertificateParsingException e1) {
            // eat exception since we are going to fail over to crl
            log.debug("exception on retrieving OCSP url from certificate, will fail over to CRL");
            failOverToCRL = true;
        }

        if (oCSPURLString == null || oCSPURLString.length() == 0) {
            // OCSP url does not exist
            log.debug("OCSP url is not present in certificate, will fail over to CRL");
            failOverToCRL = true;
        }

        // check using OCSP if ocsp url was found
        if (!failOverToCRL) {
            try {
                // generate ocsp request for current certificate and send to
                // ocsp responder
                OCSPReq req = generateOCSPRequest(cACert, x509Cert);
                byte[] derocspresponse = sendOCSPRequest(req, oCSPURLString);
                parseAndVerifyOCSPResponse(x509Cert, derocspresponse);

            } catch (OCSPStatusNotGoodException e) {
                // if the OCSPStatusNotGood exception is received it means that
                // the ocsp response was successfully received
                // and verified, and that status of our certificate is not good.
                // no need to fail over to crl
                throw new CertPathValidatorException(
                        "Responce for queried certificate is not good. Certificate status returned : "
                        + e.getCertStatus());
            } catch (Exception e) {
                // we got exception when querying ocsp for this certificate
                // no matter whatever happened , we need to fail over to CRL
                failOverToCRL = true;
            }
        }

        if (failOverToCRL) {
            URL crlURL = null;
            boolean useConfiguredCRLPaths = false;
            // either OCSP url not found, or exception occurred when querying
            // the ocsp
            // so we fail over to crl
            try {
                crlURL = CertTools.getCrlDistributionPoint(x509Cert);
            } catch (CertificateParsingException e) {
                // we could not get CDP from certificate
                // eat up exception, and look in the Configured CRLPATHS
                log.debug("exception on retrieving CDP url from certificate, will use preconfigured CRLPATHS");
                useConfiguredCRLPaths = true;
            }

            if (crlURL == null) {
                // OCSP url does not exist
                log.debug("CDP url is not present in certificate, will use preconfigured CRLPATHS");
                useConfiguredCRLPaths = true;
            }

            if (!useConfiguredCRLPaths) {
                // CDP found inside certificate fetch CRL and verify
                try {
                    parseAndVerifyCRL(x509Cert, crlURL);
                } catch (SignServerException e) {
                    // here just re-throw exception
                    throw new CertPathValidatorException(e);
                }
            }

            if (useConfiguredCRLPaths) {
                // so we are going to use preconfigured crl paths
                // fetch each crl and try to parse and verify
                // if found revoked throw CertPathValidatorException
                // if any other exception is thrown , just eat up
                for (URL crlPath : this.cRLPaths) {
                    try {
                        parseAndVerifyCRL(x509Cert, crlPath);
                        // if we are down here then our certificate is valid
                        break;
                    } catch (CRLCertRevokedException e) {
                        // here just re-throw exception
                        throw new CertPathValidatorException(e);
                    } catch (SignServerException e) {
                        // eat up
                    }
                }

                // TODO : throw exception at the end if no crl fits our needs ??
            }
        }

        cACert = x509Cert;
    }

    /**
     * try to get revocation status of the x509Cert using passed in CRL URL
     * 
     * if CRL is accessible , and signed by CA issuing x509Cert , and if
     * x509Cert is not revoked returns otherwise throws exception
     * 
     * @param x509Cert
     *            - certificate whose revocation status is checked
     * @param crlURL
     *            - url of the CRL
     * @throws SignServerException
     *             - if something bad (other than certificate being revoked)
     *             happens
     * @throws CRLCertRevokedException
     *             - if certificate is revoked
     */
    private void parseAndVerifyCRL(X509Certificate x509Cert, URL crlURL)
            throws SignServerException, CRLCertRevokedException {
        X509CRL certCRL = null;
        String msg;

        certCRL = ValidationUtils.fetchCRLFromURL(crlURL);

        try {
            certCRL.verify(cACert.getPublicKey(), "BC");
        } catch (Exception e) {
            msg = "Exception on verifying CRL fetched from url: "
                    + crlURL.toString() + " using CA certificate : "
                    + CertTools.getSubjectDN(cACert);
            log.error(msg, e);
            throw new SignServerException(msg, e);
        }

        // now that crl is verified check getThisUpdate < now, getNextUpdate >
        // now
        // although getNextUpdate is optional RFC 3280 mandates it and does not
        // specify how to interpret the absence of the field
        if (certCRL.getThisUpdate() != null
                && (new Date()).compareTo(certCRL.getThisUpdate()) <= 0) {
            msg = "CRL for certificate : " + CertTools.getSubjectDN(x509Cert)
                    + " reported thisUpdate as : "
                    + certCRL.getThisUpdate().toString()
                    + " which is later than current date.";
            log.debug(msg);
            throw new SignServerException(msg);
        }

        if (certCRL.getNextUpdate() != null
                && (new Date()).compareTo(certCRL.getNextUpdate()) >= 0) {
            msg = "CRL for certificate : " + CertTools.getSubjectDN(x509Cert)
                    + " reported nextUpdate as : "
                    + certCRL.getNextUpdate().toString()
                    + " which is earlier than current date.";
            log.debug(msg);
            throw new SignServerException(msg);
        }

        // check if certificate is revoked
        X509CRLEntry crlEntry = certCRL.getRevokedCertificate(x509Cert);
        if (crlEntry != null) {
            msg = "The certificate " + CertTools.getSubjectDN(x509Cert)
                    + " has been revoked on " + crlEntry.getRevocationDate();

            // TODO : crlEntry extension is OPTIONAL ?? if it is then throw
            // exception if it has no extension
            if (crlEntry.hasExtensions()) {
                int reasonCode = CRLReason.unspecified;
                try {
                    reasonCode = ValidationUtils.getReasonCodeFromCRLEntry(crlEntry);
                } catch (IOException e) {
                    throw new SignServerException(
                            "can not retrieve reason code", e);
                }

                if (reasonCode == CRLReason.removeFromCRL) {
                    // this is tricky, though the certificate is found in CRL it
                    // is not revoked, it is activated back from on-hold
                    // so it is actually not revoked !
                    return;
                } else {
                    // certificate is revoked , append reason code and throw
                    // exception so we stop checking
                    msg = " revocation reason code : " + reasonCode;
                    throw new CRLCertRevokedException(msg, reasonCode);
                }
            }
        }
    }

    public Object clone() {
        try {
            OCSPCRLPathChecker clonedOCSPCRLPathChecker = null;
            X509Certificate clonedPrevCert = null;
            if (cACert != null) {
                CertificateFactory certFact = CertificateFactory.getInstance(
                        "X509", "BC");
                ByteArrayInputStream bis = new ByteArrayInputStream(cACert.getEncoded());
                clonedPrevCert = (X509Certificate) certFact.generateCertificate(bis);
            }

            // do not need to clone other properties since they do not change
            clonedOCSPCRLPathChecker = new OCSPCRLPathChecker(rootCACert,
                    this.props, this.authorizedOCSPResponderCerts,
                    this.cRLPaths);
            clonedOCSPCRLPathChecker.cACert = clonedPrevCert;
            return clonedOCSPCRLPathChecker;

        } catch (CertificateException e) {
            log.error("Exception occured on clone of OCSPCRLPathChecker", e);
        } catch (NoSuchProviderException e) {
            log.error("Exception occured on clone of OCSPCRLPathChecker", e);
        }

        return null;
    }
}
