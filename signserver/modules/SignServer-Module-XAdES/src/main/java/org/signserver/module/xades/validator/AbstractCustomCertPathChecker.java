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
package org.signserver.module.xades.validator;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.ocsp.OCSPRespStatus;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.Store;
import org.ejbca.util.CertTools;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.validationservice.server.CRLCertRevokedException;
import org.signserver.validationservice.server.OCSPResponse;
import org.signserver.validationservice.server.OCSPStatusNotGoodException;
import org.signserver.validationservice.server.ValidationUtils;
import org.signserver.validationservice.server.X509ExtendedKeyUsageExistsCertSelector;

/**
 * CertPathChecker using OCSP with fallback to CRL.
 * 
 * Based on the OCSPCRLPathChecker by rayback2.
 * @version $Id$
 */
public abstract class AbstractCustomCertPathChecker extends PKIXCertPathChecker {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AbstractCustomCertPathChecker.class);
    
    private final List<X509Certificate> certChain;
    private final X509Certificate rootCert;

    public AbstractCustomCertPathChecker(List<X509Certificate> certChain, X509Certificate rootCert) {
        this.certChain = certChain;
        this.rootCert = rootCert;
    }

    @Override
    public void init(boolean forward) throws CertPathValidatorException {
        if (certChain == null || certChain.isEmpty()) {
            throw new CertPathValidatorException("certChain must not be empty");
        }
    }

    @Override
    public boolean isForwardCheckingSupported() {
        return false;
    }

    @Override
    public Set<String> getSupportedExtensions() {
        return Collections.emptySet();
    }

    @Override
    public void check(Certificate cert, Collection<String> unresolvedCritExts) throws CertPathValidatorException {
        if (!(cert instanceof X509Certificate)) {
            throw new CertPathValidatorException("Only X.509 certificates supported");
        }
        final X509Certificate certificate = (X509Certificate) cert;
        final X509Certificate issuerCertificate = findIssuer(certificate);
        boolean failOverToCRL = false;
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Starting certificate check: " + certificate.getSubjectDN().getName());
        }
        
        // Check if OCSP access address exists
        String ocspURLString = null;
        try {
            ocspURLString = CertTools.getAuthorityInformationAccessOcspUrl(certificate);
        } catch (CertificateParsingException ex) {
            if (LOG.isDebugEnabled()) {
               LOG.debug("Could not read AIA OCSP URL: " + ex.getMessage());
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("ocspURLString: " + ocspURLString);
        }

        if (ocspURLString == null || ocspURLString.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No AIA OCSP URL found, will look for CRL instead");
            }
            failOverToCRL = true;
        } else {
            try {
                URL ocspURL = new URL(ocspURLString);
                // generate ocsp request for current certificate and send to
                // ocsp responder
                OCSPReq req = generateOCSPRequest(certificate, issuerCertificate);
                OCSPResponse response = queryOCSPResponder(ocspURL, req);
                if (response.getError() == OCSPResponse.Error.responseSuccess) {
                    parseAndVerifyOCSPResponse(certificate, response.getResp(), issuerCertificate);
                } else {
                    LOG.debug("Unsuccessful response: " + response.getError());
                    failOverToCRL = true;
                }
            } catch (OCSPStatusNotGoodException e) {
                // if the OCSPStatusNotGood exception is received it means that
                // the ocsp response was successfully received
                // and verified, and that status of our certificate is not good.
                // no need to fail over to crl
                throw new CertPathValidatorException(
                        "Responce for queried certificate is not good. Certificate status returned : "
                        + e.getCertStatus());
            } catch (MalformedURLException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Malform AIA OCSP URL found: " + ex.getMessage());
                }
                failOverToCRL = true;
            } catch (IOException ex) {
                LOG.debug("Unable to query OCSP: " + ex.getMessage());
                failOverToCRL = true;
            } catch (Exception ex) {
                LOG.debug("Error querying OCSP", ex);
                throw new CertPathValidatorException("OCSP error", ex);
            }
        }
        
        // Try with CRL instead
        if (failOverToCRL) {
            try {
                URL crlURL = CertTools.getCrlDistributionPoint(certificate);
                if (crlURL == null) {
                    if (cert.equals(rootCert)) {
                        // Don't require revokation information for the Root CA certificate
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("No revocation information for the Root CA certificate");
                        }
                    } else {
                        throw new CertPathValidatorException("CDP URL not present in certificate");
                    }
                } else {
                    // CDP found inside certificate fetch CRL and verify
                    X509CRL crl = fetchCRL(crlURL);
                    verifyCRL(certificate, crl, issuerCertificate, crlURL);
                }
            } catch (CertificateParsingException ex) {
                throw new CertPathValidatorException("Failed to obtain CDP URL: " + ex.getMessage());
            } catch (CertificateException ex) {
                throw new CertPathValidatorException("Failed to fetch CRL: " + ex.getMessage());
            } catch (IOException ex) {
                throw new CertPathValidatorException("Failed to fetch CRL: " + ex.getMessage());
            } catch (SignServerException ex) {
                throw new CertPathValidatorException("CRL verification failed: " + ex.getMessage());
            }
        }
    }

    private OCSPReq generateOCSPRequest(X509Certificate certificate, X509Certificate issuerCertificate) throws OperatorCreationException, CertificateEncodingException, OCSPException, IOException {
        final OCSPReq result;
        final OCSPReqBuilder builder = new OCSPReqBuilder();
        DigestCalculatorProvider digestCalcProv = new BcDigestCalculatorProvider();
        final CertificateID certId = new CertificateID(digestCalcProv.get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)), new X509CertificateHolder(issuerCertificate.getEncoded()), certificate.getSerialNumber());
        
        builder.addRequest(certId);

//        LinkedList<Extension> extensions = new LinkedList<Extension>();
//        if (nonce != null) {
//            extensions.add(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce)));
//        }
//        builder.setRequestExtensions(new Extensions(extensions.toArray(new Extension[extensions.size()])));

        result = builder.build();
        return result;
    }

    protected abstract OCSPResponse queryOCSPResponder(URL url, OCSPReq request) throws IOException, OCSPException;
    
    /**
     * Parses received response bytes to form basic ocsp response object and verifies ocsp response  
     * If returns , ocsp response is successfully verified, otherwise throws exception detailing problem
     * 
     * @param x509Cert - certificate originally passed to validator for validation
     * @param ocspresp - ocsp response received from ocsp responder
     * @throws OCSPException 
     * @throws NoSuchProviderException 
     * @throws IOException 
     * @throws CertStoreException 
     * @throws NoSuchAlgorithmException 
     * @throws SignServerException 
     * @throws CertificateParsingException 
     * @throws CryptoTokenOfflineException 
     * @throws IllegalRequestException 
     */
    protected void parseAndVerifyOCSPResponse(X509Certificate x509Cert, OCSPResp ocspresp, X509Certificate cACert) throws NoSuchProviderException, OCSPException, NoSuchAlgorithmException, CertStoreException, IOException, SignServerException, CertificateParsingException, IllegalRequestException, CryptoTokenOfflineException, OperatorCreationException, CertificateEncodingException {
       
        if (ocspresp.getStatus() != OCSPRespStatus.SUCCESSFUL) {
            throw new SignServerException("Unexpected ocsp response status. Response Status Received : " + ocspresp.getStatus());
        }

        // we currently support only basic ocsp response 
        BasicOCSPResp basicOCSPResponse = (BasicOCSPResp) ocspresp.getResponseObject();

        if (basicOCSPResponse == null) {
            throw new SignServerException("Could not construct BasicOCSPResp object from response. Only BasicOCSPResponse as defined in RFC 2560 is supported.");
        }

        //OCSP response might be signed by CA issuing the certificate or  
        //the Authorized OCSP responder certificate containing the id-kp-OCSPSigning extended key usage extension

        X509Certificate ocspRespSignerCertificate = null;

        //first check if CA issuing certificate signed the response
        //since it is expected to be the most common case
        if (basicOCSPResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(cACert.getPublicKey()))) {
            ocspRespSignerCertificate = cACert;
        }
        //if CA did not sign the ocsp response, look for authorized ocsp responses from properties or from certificate chain received with response
        
        if (ocspRespSignerCertificate == null) {
            //look for existence of Authorized OCSP responder inside the cert chain in ocsp response
            ocspRespSignerCertificate = getAuthorizedOCSPRespondersCertificateFromOCSPResponse(basicOCSPResponse);

            //could not find the certificate signing the OCSP response in the ocsp response
            if (ocspRespSignerCertificate == null) {
                throw new SignServerException("Certificate signing the ocsp response is not found in ocsp response's certificate chain received and is not signed by CA issuing certificate");
            }
        }

        LOG.debug("OCSP response signed by :  " + CertTools.getSubjectDN(ocspRespSignerCertificate));
        // validating ocsp signers certificate
        // Check if responders certificate has id-pkix-ocsp-nocheck extension, in which case we do not validateUsingCRL (perform revocation check on ) ocsp certs for lifetime of certificate
        // using CRL RFC 2560 sect 4.2.2.2.1
        // TODO : RFC States the extension value should be NULL, so maybe bare existence of the extension is not sufficient ??
        if (ocspRespSignerCertificate.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()) != null) {
            //check if lifetime of certificate is ok
            try {
                ocspRespSignerCertificate.checkValidity();
            } catch (CertificateExpiredException e) {
                throw new SignServerException("Certificate signing the ocsp response has expired. OCSP Responder Certificate Subject DN : " + CertTools.getSubjectDN(ocspRespSignerCertificate));
            } catch (CertificateNotYetValidException e) {
                throw new SignServerException("Certificate signing the ocsp response is not yet valid. OCSP Responder Certificate Subject DN : " + CertTools.getSubjectDN(ocspRespSignerCertificate));
            }
        } else if (ocspRespSignerCertificate.equals(cACert)) {
            LOG.debug("Not performing revocation check on issuer certificate");
        } else {
            // TODO: Could try to use CRL if available
            throw new SignServerException("Revokation check of OCSP certificate not yet supported");
        }

        //get the response we requested for 
        for (SingleResp singleResponse : basicOCSPResponse.getResponses()) {
            if (singleResponse.getCertID().getSerialNumber().equals(x509Cert.getSerialNumber())) {
                //found our response
                //check if response is OK, and if not throw OCSPStatusNotGoodException
                if (singleResponse.getCertStatus() != null) {
                    throw new OCSPStatusNotGoodException("Responce for queried certificate is not good. Certificate status returned : " + singleResponse.getCertStatus(), singleResponse.getCertStatus());
                }
                //check the dates ThisUpdate and NextUpdate RFC 2560 sect : 4.2.2.1
                if (singleResponse.getNextUpdate() != null && (new Date()).compareTo(singleResponse.getNextUpdate()) >= 0) {
                    throw new SignServerException("Unreliable response received. Response reported a nextupdate as : " + singleResponse.getNextUpdate().toString() + " which is earlier than current date.");
                }
                if (singleResponse.getThisUpdate() != null && (new Date()).compareTo(singleResponse.getThisUpdate()) <= 0) {
                    throw new SignServerException("Unreliable response received. Response reported a thisupdate as : " + singleResponse.getThisUpdate().toString() + " which is earlier than current date.");
                }

                break;
            }
        }

    }

    protected abstract X509CRL fetchCRL(URL crlURL) throws IOException, CertificateException, SignServerException;

    private void verifyCRL(X509Certificate certificate, X509CRL crl, X509Certificate issuerCertificate, final URL crlURL) throws SignServerException {
        try {
            crl.verify(issuerCertificate.getPublicKey(), "BC");
        } catch (Exception e) {
            final String msg = "Exception on verifying CRL fetched from url: "
                    + crlURL.toString() + " using CA certificate : "
                    + CertTools.getSubjectDN(issuerCertificate);
            if (LOG.isDebugEnabled()) {
                LOG.debug(msg, e);
            }
            throw new SignServerException(msg, e);
        }

        // now that crl is verified check getThisUpdate < now, getNextUpdate >
        // now
        // although getNextUpdate is optional RFC 3280 mandates it and does not
        // specify how to interpret the absence of the field
        if (crl.getThisUpdate() != null
                && (new Date()).compareTo(crl.getThisUpdate()) <= 0) {
            final String msg = "CRL for certificate : " + CertTools.getSubjectDN(certificate)
                    + " reported thisUpdate as : "
                    + crl.getThisUpdate().toString()
                    + " which is later than current date.";
            LOG.debug(msg);
            throw new SignServerException(msg);
        }

        if (crl.getNextUpdate() != null
                && (new Date()).compareTo(crl.getNextUpdate()) >= 0) {
            final String msg = "CRL for certificate : " + CertTools.getSubjectDN(certificate)
                    + " reported nextUpdate as : "
                    + crl.getNextUpdate().toString()
                    + " which is earlier than current date.";
            LOG.debug(msg);
            throw new SignServerException(msg);
        }

        // check if certificate is revoked
        X509CRLEntry crlEntry = crl.getRevokedCertificate(certificate);
        if (crlEntry != null) {
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
                } else {
                    // certificate is revoked , append reason code and throw
                    // exception so we stop checking
                    String msg = " revocation reason code : " + reasonCode;
                    throw new CRLCertRevokedException(msg, reasonCode);
                }
            }
        }
    }

    private X509Certificate findIssuer(X509Certificate certificate) {
        X509Certificate result = null;
        for (X509Certificate cert : certChain) {
            if (certificate.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
                result = cert;
                break;
            }
        }
        return result;
    }

/**
     * 
     * Method that retrieves the Authorized OCSP Responders certificate from basic ocsp response structure
     * the Authorized OCSP responders certificate is identified by OCSPSigner extension
     * Only certificate having this extension and that can verify response's signature is returned 
     * 
     * NOTE : RFC 2560 does not state it should be an end entity certificate ! 
     * 
     * @param basic ocsp response
     * @return Authorized OCSP Responders certificate if found, null if not found
     * @throws OCSPException 
     * @throws NoSuchProviderException 
     * @throws NoSuchAlgorithmException 
     * @throws CertStoreException 
     */
    private X509Certificate getAuthorizedOCSPRespondersCertificateFromOCSPResponse(BasicOCSPResp basicOCSPResponse) throws NoSuchAlgorithmException, NoSuchProviderException, OCSPException, CertStoreException, CertificateEncodingException, OperatorCreationException {
        X509Certificate result = null;
        X509CertificateHolder[] certs = basicOCSPResponse.getCerts();
        Store ocspRespCertStore = new JcaCertStore(Arrays.asList(certs));
        
        //search for certificate having OCSPSigner extension		
        X509ExtendedKeyUsageExistsCertSelector certSel = new X509ExtendedKeyUsageExistsCertSelector(KeyPurposeId.id_kp_OCSPSigning.getId());

        for (X509CertificateHolder cert : (Collection<X509CertificateHolder>) ocspRespCertStore.getMatches(certSel)) {
            try {
                //it might be the case that certchain contains more than one certificate with OCSPSigner extension
                //check if certificate verifies the signature on the response
                if (cert != null && basicOCSPResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(cert))) {
                    result = new JcaX509CertificateConverter().getCertificate(cert);
                    break;
                }
            } catch (CertificateException ignored) {}
        }

        return result;
    }
}
