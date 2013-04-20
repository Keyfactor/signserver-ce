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

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.*;
import java.util.*;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.ocsp.OCSPRespStatus;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.ejbca.util.CertTools;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.validationservice.common.Validation;
//import org.signserver.validationservice.common.X509Certificate;

/**
 * Stateful OCSP PKIX certificate path checker.
 * It does not support forward checking (reverse is must by default) because we want certificates to be presented from
 * trust anchor (not included) to the target certificate
 * 
 * NOTE : support for forward checking could be enabled by searching issuer certificate of certificate in question and making it stateless.
 * 
 * @author rayback2
 * @version $Id$
 */
public class OCSPPathChecker extends PKIXCertPathChecker {
    // cACert holds the previous certificate passed to check method
    // thus if cACert is not null, it will hold the issuer's CA certificate, of the certificate passed in to check method
    // if cACert is null, it means the certificate passed to check method is directly issued by root CA
    // these properties are satisfied in reverse checking (thats why support for forward checking is not present)

    X509Certificate cACert;
    X509Certificate rootCACert;
    Properties props;
    List<X509Certificate> authorizedOCSPResponderCerts;
    protected transient Logger log = Logger.getLogger(this.getClass());

    public OCSPPathChecker(X509Certificate rootCACert, Properties props, List<X509Certificate> authorizedOCSPResponderCerts) {
        this.rootCACert = rootCACert;
        this.props = props;
        this.authorizedOCSPResponderCerts = authorizedOCSPResponderCerts;
    }

    @Override
    public void init(boolean forward) throws CertPathValidatorException {
        // initialize state of the checker
        cACert = null;
        if (rootCACert == null) {
            throw new CertPathValidatorException("Root CA Certificate passed in constructor can not be null");
        }
    }

    @Override
    public void check(Certificate cert, Collection<String> unresolvedCritExts)
            throws CertPathValidatorException {

        if (!(cert instanceof X509Certificate)) {
            throw new CertPathValidatorException("Certificate passed to check method of OCSPPathChecker is not of type X509Certificate");
        }

        if (cACert == null) {
            cACert = rootCACert;
        }
        X509Certificate x509Cert = (X509Certificate) cert;

        log.debug("check method called with certificate " + CertTools.getSubjectDN(x509Cert));

        try {

            //check if url is missing 
            //throw exception (for now, later maybe change to look for predefined ocsp url for each issuer ?)
            String oCSPURLString = CertTools.getAuthorityInformationAccessOcspUrl(x509Cert);
            if (oCSPURLString == null || oCSPURLString.length() == 0) {
                throw new SignServerException("OCSP service locator url missing for certificate " + CertTools.getSubjectDN(x509Cert));
            }

            if (cACert == null) {
                throw new SignServerException("Issuer of certificate : " + CertTools.getSubjectDN(x509Cert) + " not passed to OCSPPathChecker");
            }
            //generate ocsp request for current certificate and send to ocsp responder
            OCSPReq req = generateOCSPRequest(cACert, x509Cert);
            byte[] derocspresponse = sendOCSPRequest(req, oCSPURLString);
            parseAndVerifyOCSPResponse(x509Cert, derocspresponse);

        } catch (Exception e) {
            //re-throw all exceptions received
            log.error("Exception occured on validion of certificate using OCSPPathChecker ", e);
            throw new CertPathValidatorException(e);
        }

        cACert = x509Cert;
    }

    @Override
    public Set<String> getSupportedExtensions() {
        return null;
    }

    @Override
    public boolean isForwardCheckingSupported() {
        return false;
    }

    /**
     * Generates basic ocsp request
     * @param issuerCert certificate of the issuer of the certificate to be queried for status
     * @param cert certificate to be queried for status
     * @return basic ocsp request for single certificate
     * @throws OCSPException
     */
    protected OCSPReq generateOCSPRequest(X509Certificate issuerCert, X509Certificate cert) throws OCSPException, CertificateEncodingException, OperatorCreationException {
        CertificateID idToCheck = new JcaCertificateID(new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1), issuerCert, cert.getSerialNumber());
        OCSPReqBuilder reqgen = new OCSPReqBuilder();
        reqgen.addRequest(idToCheck);
        return reqgen.build();
    }

    /**
     * Sends passed in ocsp request to ocsp responder at url identified by oCSPURLString
     * 
     * @return der encoded ocsp response
     */
    protected byte[] sendOCSPRequest(OCSPReq ocspRequest, String oCSPURLString) throws IOException, SignServerException {
        // get der encoded ocsp request 
        byte[] reqarray = ocspRequest.getEncoded();

        //send request 
        URL url = new URL(oCSPURLString);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();

        con.setAllowUserInteraction(false);
        con.setDoInput(true);
        con.setDoOutput(true);
        con.setUseCaches(false);
        con.setInstanceFollowRedirects(false);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Length", Integer.toString(reqarray.length));
        con.setRequestProperty("Content-Type", "application/ocsp-request");

        con.connect();
        OutputStream os = con.getOutputStream();
        os.write(reqarray);
        os.close();

        //see if we received proper response
        if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new SignServerException("Response code unexpected. Expecting : HTTP_OK(200). Received :  " + con.getResponseCode());
        }

        //see if the response is of proper MIME type
        if ((con.getContentType() == null) || !con.getContentType().equals("application/ocsp-response")) {
            throw new SignServerException("Response type unexpected. Expecting : application/ocsp-response, Received : " + con.getContentType());
        }


        // Read der encoded ocsp response
        byte[] responsearr = null;

        InputStream reader = con.getInputStream();
        int responselen = con.getContentLength();

        if (responselen != -1) {

            //header indicating content-length is present, so go ahead and use it
            responsearr = new byte[responselen];

            int offset = 0;
            int bread;
            while ((responselen > 0) && (bread = reader.read(responsearr, offset, responselen)) != -1) {
                offset += bread;
                responselen -= bread;
            }

            //read.read returned -1 but we expect inputstream to contain more data
            //is it a dreadful unexpected EOF we were afraid of ??
            if (responselen > 0) {
                throw new SignServerException("Unexpected EOF encountered while reading ocsp response from : " + oCSPURLString);
            }
        } else {
            //getContentLength() returns -1. no panic , perfect normal value if header indicating length is missing (javadoc)
            //try to read response manually byte by byte (small response expected , no need to buffer)
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            int b;
            while ((b = reader.read()) != -1) {
                baos.write(b);
            }

            responsearr = baos.toByteArray();
        }

        reader.close();
        con.disconnect();


        return responsearr;
    }

    /**
     * Parses received response bytes to form basic ocsp response object and verifies ocsp response  
     * If returns , ocsp response is successfully verified, otherwise throws exception detailing problem
     * 
     * @param x509Cert - certificate originally passed to validator for validation
     * @param derocspresponse - der formatted ocsp response received from ocsp responder
     * @throws OCSPException 
     * @throws NoSuchProviderException 
     * @throws IOException 
     * @throws CertStoreException 
     * @throws NoSuchAlgorithmException 
     * @throws NoSuchAlgorithmException 
     * @throws SignServerException 
     * @throws CertificateParsingException 
     * @throws CryptoTokenOfflineException 
     * @throws IllegalRequestException 
     */
    protected void parseAndVerifyOCSPResponse(X509Certificate x509Cert, byte[] derocspresponse) throws NoSuchProviderException, OCSPException, NoSuchAlgorithmException, CertStoreException, IOException, SignServerException, CertificateParsingException, IllegalRequestException, CryptoTokenOfflineException, OperatorCreationException, CertificateEncodingException {
        //parse received ocsp response
        OCSPResp ocspresp = new OCSPResp(derocspresponse);
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
            log.debug("OCSP Response is not signed by issuing CA. Looking for authorized responders");
            if (basicOCSPResponse.getCerts() == null) {
                log.debug("OCSP Response does not contain certificate chain, trying to verify response using one of configured authorized ocsp responders");

                //certificate chain is not present in response received 
                //try to verify using one of the configured AuthorizedOCSPResponderCerts
                ocspRespSignerCertificate = getAuthorizedOCSPRespondersCertificateFromProperties(basicOCSPResponse);

                if (ocspRespSignerCertificate == null) {
                    throw new SignServerException("OCSP Response does not contain certificate chain, and response is not signed by any of the configured Authorized OCSP Responders or CA issuing certificate.");
                }
            } else {
                //look for existence of Authorized OCSP responder inside the cert chain in ocsp response
                ocspRespSignerCertificate = getAuthorizedOCSPRespondersCertificateFromOCSPResponse(basicOCSPResponse);

                //could not find the certificate signing the OCSP response in the ocsp response
                if (ocspRespSignerCertificate == null) {
                    throw new SignServerException("Certificate signing the ocsp response is not found in ocsp response's certificate chain received and is not signed by CA issuing certificate");
                }
            }
        }

        log.debug("OCSP response signed by :  " + CertTools.getSubjectDN(ocspRespSignerCertificate));
        // validating ocsp signers certificate
        // Check if responders certificate has id-pkix-ocsp-nocheck extension, in which case we do not validate (perform revocation check on ) ocsp certs for lifetime of certificate
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
        } else {
            // check if CDP exists in ocsp signers certificate
            // TODO : ?? add property for issuer whether to accept the OCSP response if the CDPs are not available (or use preconfigured CRLs) on signing certificate CRL RFC 2560 sect 4.2.2.2.1
            if (CertTools.getCrlDistributionPoint(ocspRespSignerCertificate) == null) {
                throw new SignServerException("CRL Distribution Point extension missing in ocsp signer's certificate.");
            }

            //verify certificate using CRL Validator
            //TODO : refactor Validators to follow factory pattern (discuss)
            CRLValidator crlValidator = new CRLValidator();
            Validation valresult = crlValidator.validate(ocspRespSignerCertificate, this.props);
            if (valresult.getStatus() != Validation.Status.VALID) {
                throw new SignServerException("Validation of ocsp signer's certificate failed. Status message received : " + valresult.getStatusMessage());
            }
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
    protected X509Certificate getAuthorizedOCSPRespondersCertificateFromOCSPResponse(BasicOCSPResp basicOCSPResponse) throws NoSuchAlgorithmException, NoSuchProviderException, OCSPException, CertStoreException, CertificateEncodingException, OperatorCreationException {
        X509Certificate retCert = null;
        X509Certificate tempCert = null;
        X509CertificateHolder[] certs = basicOCSPResponse.getCerts();
        Store ocspRespCertStore = new JcaCertStore(Arrays.asList(certs));
        

        //search for certificate having OCSPSigner extension		
        X509ExtendedKeyUsageExistsCertSelector certSel = new X509ExtendedKeyUsageExistsCertSelector("1.3.6.1.5.5.7.3.9");
        Iterator<?> certsIter = ocspRespCertStore.getMatches(certSel).iterator();

        while (certsIter.hasNext()) {
            try {
                // direct cast to org.signserver.validationservice.common.X509Certificate fails
                tempCert = (java.security.cert.X509Certificate) certsIter.next();
            } catch (Exception e) {
                //eat up exception 
                continue;
            }
            //it might be the case that certchain contains more than one certificate with OCSPSigner extension
            //check if certificate verifies the signature on the response 
            if (tempCert != null && basicOCSPResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(tempCert.getPublicKey()))) {
                retCert = tempCert;
                break;
            }
        }

        return retCert;
    }

    /**
     * Method that traverses all configured AuthorizedOCSPResponderCert properties for the issuer of certficate passed originally to the validators validate() method 
     * and tries to find the one that signed the ocsp response
     * @param basicOCSPResponse - response that is tried to be verified
     * @return - Authorized ocsp responder's certificate, or null if none found that verifies ocsp response received
     * @throws NoSuchProviderException
     * @throws OCSPException
     */
    protected X509Certificate getAuthorizedOCSPRespondersCertificateFromProperties(BasicOCSPResp basicOCSPResponse) throws NoSuchProviderException, OCSPException, OperatorCreationException {
        log.debug("Searching for Authorized OCSP Responder certificate from PROPERTIES");
        if (this.authorizedOCSPResponderCerts == null || this.authorizedOCSPResponderCerts.isEmpty()) {
            return null;
        }
        for (X509Certificate ocspCert : this.authorizedOCSPResponderCerts) {
            if (basicOCSPResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(ocspCert.getPublicKey()))) {
                log.debug("Found Authorized OCSP Responder's certificate, signing ocsp response. found cert : " + CertTools.getSubjectDN(ocspCert));
                return ocspCert;
            }
        }

        log.debug("Authorized OCSP Responder is not found");
        return null;
    }

    /**
     * 
     * Since we are implementing stateful checker we ought to override clone method for proper functionality
     * clone is used by certpath builder to backtrack and try another path when potential certificate path reaches dead end.
     * 
     * @throws SignServerException 
     */
    @Override
    public Object clone() {
        try {
            OCSPPathChecker clonedOCSPPathChecker = null;
            X509Certificate clonedPrevCert = null;
            if (cACert != null) {
                CertificateFactory certFact = CertificateFactory.getInstance("X509", "BC");
                ByteArrayInputStream bis = new ByteArrayInputStream(cACert.getEncoded());
                clonedPrevCert = (X509Certificate) certFact.generateCertificate(bis);
            }

            //do not need to clone other properties since they do not change
            clonedOCSPPathChecker = new OCSPPathChecker(rootCACert, this.props, this.authorizedOCSPResponderCerts);
            clonedOCSPPathChecker.cACert = clonedPrevCert;
            return clonedOCSPPathChecker;

        } catch (CertificateException e) {
            log.error("Exception occured on clone of OCSPPathChecker", e);
        } catch (NoSuchProviderException e) {
            log.error("Exception occured on clone of OCSPPathChecker", e);
        }

        return null;
    }
}
