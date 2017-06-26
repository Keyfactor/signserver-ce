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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.cesecore.util.CertTools;
import org.signserver.common.*;
import org.signserver.common.data.CertificateValidationResponse;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.DocumentValidationRequest;
import org.signserver.common.data.DocumentValidationResponse;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.server.validators.BaseValidator;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.Validation.Status;
import org.signserver.validationservice.server.OCSPResponse;
import org.signserver.validationservice.server.ValidationUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import xades4j.XAdES4jException;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.TimeStampVerificationProvider;
import xades4j.providers.impl.DefaultTimeStampVerificationProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.utils.XadesProfileResolutionException;
import xades4j.verification.SignatureSpecificVerificationOptions;
import xades4j.verification.XAdESVerificationResult;
import xades4j.verification.XadesVerificationProfile;
import xades4j.verification.XadesVerifier;

/**
 * A Validator for XAdES documents.
 *
 * Implements IValidator and have the following properties:
 *  CERTIFICATES
 *  TRUSTANCHORS
 *  REVOCATION_CHECKING
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class XAdESValidator extends BaseValidator {

    /** Logger. */
    private static final Logger LOG = Logger.getLogger(XAdESValidator.class);

    private static final String CERTIFICATES = "CERTIFICATES";
    private static final String TRUSTANCHORS = "TRUSTANCHORS";
    private static final String REVOCATION_CHECKING = "REVOCATION_CHECKING";
    
    private static final String REVOCATION_CHECKING_DEFAULT = Boolean.TRUE.toString();
    
    private CertStore certStore;
    private KeyStore trustAnchors;
    private boolean revocationEnabled;
    
    private LinkedList<String> configErrors;
    
    private Class<? extends TimeStampVerificationProvider> timeStampVerificationImplementation;

    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        configErrors = new LinkedList<>();
        
        revocationEnabled = Boolean.parseBoolean(config.getProperty(REVOCATION_CHECKING, REVOCATION_CHECKING_DEFAULT));

        timeStampVerificationImplementation = DefaultTimeStampVerificationProvider.class;
        
        // CERTIFICATES
        try {
            final Collection<Certificate> certificates = loadCertificatesFromProperty(CERTIFICATES);
            certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certificates));
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | CertificateException | IOException | IllegalStateException ex) {
            logPropertyError(workerId, CERTIFICATES, ex);
        }
        // TRUSTANCHORS
        try {
            final String value = config.getProperty(TRUSTANCHORS);
            if (value == null) {
                logMissingProperty(workerId, TRUSTANCHORS);
            } else {
                final Collection<Certificate> trustedCertificates = CertTools.getCertsFromPEM(new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8)));
                trustAnchors = KeyStore.getInstance("JKS");
                trustAnchors.load(null, null);
                int i = 0;
                final StringBuilder sb = new StringBuilder();
                sb.append("Trusted certificates are:\n");
                for (Certificate cert : trustedCertificates) {
                    if (cert instanceof X509Certificate) {
                        trustAnchors.setCertificateEntry("trusted-" + i++, cert);
                        sb.append(((X509Certificate) cert).getSubjectDN())
                        .append(" SN: ")
                        .append(((X509Certificate) cert).getSerialNumber().toString(16))
                        .append("\n");
                    }
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug(sb.toString());
                }
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | IllegalStateException ex) {
            logPropertyError(workerId, TRUSTANCHORS, ex);
        }
    }
    
    /** Log a property error and add the error message the list of fatal errors. */
    private void logPropertyError(final int workerId, final String property, final Exception ex) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Worker " + workerId + ": Property " + property + " caused an error", ex);
        }
        configErrors.add("Property " + property + " caused error: " + ex.getMessage());
    }
    
    /** Log a missing property and add the error message to the list of fatal errors. */
    private void logMissingProperty(final int workerId, final String property) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Worker " + workerId + ": Missing required property " + property);
        }
        configErrors.add("Missing required property " + property);
    }
    
    private Collection<Certificate> loadCertificatesFromProperty(final String property) throws IOException, CertificateException {
        final Collection<Certificate> results;
        final String value = config.getProperty(property);
        if (value == null) {
            results = Collections.emptyList();
        } else {
            results = CertTools.getCertsFromPEM(new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8)));
        }
        return results;
    }

    @Override
    public Response processData(Request signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {

        // Check that the request contains a valid GenericSignRequest object with a byte[].
        if (!(signRequest instanceof DocumentValidationRequest)) {
            throw new IllegalRequestException(
                    "Received request wasn't an expected GenericValidationRequest.");
        }
        
        final DocumentValidationRequest request = (DocumentValidationRequest) signRequest;
        
        if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }

        DocumentValidationResponse response = validate(request.getRequestID(), request.getRequestData());
        
        // The client can be charged for the request
        requestContext.setRequestFulfilledByWorker(true);
        
        return response;
    }

    private DocumentValidationResponse validate(final int requestId, ReadableData data) throws SignServerException {
        
        // Validation: parse
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc;
        try {
            // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
            // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);

            // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
            // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

            // Xerces 2 only - http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

            doc = dbf.newDocumentBuilder().parse(data.getAsInputStream());
        } catch (ParserConfigurationException | SAXException | IOException ex) {
            throw new SignServerException("Document parsing error", ex);
        }
        
        final XAdESVerificationResult result;
        try {
            CertificateValidationProvider certValidator = new PKIXCertificateValidationProvider(trustAnchors, false, certStore);

            XadesVerificationProfile p = new XadesVerificationProfile(certValidator)
                .withTimeStampTokenVerifier(timeStampVerificationImplementation);
            XadesVerifier verifier = p.newVerifier();
            
            Element node = doc.getDocumentElement();

            result = verifier.verify(node, new SignatureSpecificVerificationOptions());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | XadesProfileResolutionException ex) {
            throw new SignServerException("XML signature validation error", ex);
        } catch (XAdES4jException ex) {
            LOG.info("Request " + requestId + " signature valid: false, " + ex.getMessage());
            return new DocumentValidationResponse(requestId, false);
        }
        
        List<X509Certificate> xchain = result.getValidationData().getCerts();
        List<Certificate> chain = new LinkedList<>();
        for (X509Certificate cert : xchain) {
            chain.add(cert);
        }
        
        
        Validation v;
        if (revocationEnabled) {
            try {
                final Certificate cert = result.getValidationCertificate();
                final List<X509Certificate> certChain = result.getValidationData().getCerts();
                final Certificate rootCert = result.getValidationData().getCerts().get(result.getValidationData().getCerts().size() - 1);
                v = validate(cert, certChain, rootCert);
            } catch (IllegalRequestException ex) {
                LOG.info("Request " + requestId + " signature valid: false, " + ex.getMessage());
                return new DocumentValidationResponse(requestId, false);
            } catch (CryptoTokenOfflineException ex) {
                throw new SignServerException("Certificate validation error", ex);
            }
        } else {            
            // Fill in the certificate validation information.
            // As the XAdES4j has checked the certificate we just fill in the values here
            v = new Validation(result.getValidationCertificate(), chain, Validation.Status.VALID, "Certifiate passed validation");
        }
        LOG.info("Request " + requestId + " signature valid: " + (v.getStatus() == Status.VALID));
        
        CertificateValidationResponse vresponse = new CertificateValidationResponse(v, null);

        return new DocumentValidationResponse(requestId, v.getStatus().equals(Status.VALID), vresponse);
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        final LinkedList<String> errors = new LinkedList<>(super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }

    protected Validation validate(Certificate cert, List<X509Certificate> certChain,  Certificate rootCert)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {

        if (LOG.isDebugEnabled()) {
            final StringBuilder sb = new StringBuilder();
            sb.append("***********************\n");
            sb.append("Printing certchain for ").append(CertTools.getSubjectDN(cert)).append("\n");
            for (final X509Certificate certificate : certChain) {
                sb.append(CertTools.getSubjectDN(certificate)).append("\n");
            }
            sb.append("***********************");
            LOG.debug(sb.toString());
        }

        // certStore & certPath construction
        CertificateFactory certFactory;
        CertPathValidator validator = null;
        PKIXParameters params = null;
        CertPath certPath = null;
        try {
            certFactory = CertificateFactory.getInstance("X509"); // TODO: "BC");

            // CertPath Construction
            certPath = certFactory.generateCertPath(certChain);

            // init cerpathvalidator 
            validator = CertPathValidator.getInstance("PKIX", "BC");

            // init params
            TrustAnchor trustAnc = new TrustAnchor((X509Certificate) rootCert, null);
            params = new PKIXParameters(Collections.singleton(trustAnc));
            params.addCertStore(certStore);
            params.setDate(new Date());         // TODO: Using current date at the moment
            params.setRevocationEnabled(false);
            params.addCertPathChecker(new AbstractCustomCertPathChecker(certChain, (X509Certificate) rootCert) {

                @Override
                protected X509CRL fetchCRL(URL crlURL) throws IOException, CertificateException, SignServerException {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Fetching CRL from " + crlURL + "...");
                    }
                    return ValidationUtils.fetchCRLFromURL(crlURL, CertificateFactory.getInstance("X509"));
                }

                @Override
                protected OCSPResponse queryOCSPResponder(URL url, OCSPReq request) throws IOException, OCSPException {
                    return doQueryOCSPResponder(url, request);
                }
                
            });
            
        } catch (CertificateException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            LOG.error("Exception on preparing parameters for validation", e);
            throw new SignServerException(e.toString(), e);
        }

        //do actual validation
        PKIXCertPathValidatorResult cpv_result;
        try {
            cpv_result = (PKIXCertPathValidatorResult) validator.validate(certPath, params);
            //if we are down here then validation is successful
            return new Validation(cert, toChain(certChain), Validation.Status.VALID, "This certificate is valid. Trust anchor for certificate is :" + cpv_result.getTrustAnchor().getTrustedCert().getSubjectDN());

        } catch (CertPathValidatorException e) {
            LOG.debug("certificate is not valid.", e);
            
            final String subjectDN;
            if (e.getCertPath() != null && e.getIndex() != -1) {
                subjectDN = ((X509Certificate) e.getCertPath().getCertificates().get(e.getIndex())).getSubjectDN().getName();
            } else {
                subjectDN = "";
            }
            return new Validation(cert, toChain(certChain), Validation.Status.DONTVERIFY, "Exception on validation. certificate causing exception : " + subjectDN + e.toString());
        } catch (InvalidAlgorithmParameterException e) {
            LOG.error("Exception on validation", e);
            throw new SignServerException("Exception on validation.", e);
        }

    }

    private List<Certificate> toChain(final List<X509Certificate> xchain) {
        final List<Certificate> chain = new LinkedList<>();
        for (X509Certificate cert : xchain) {
            chain.add(cert);
        }
        return chain;
    }
    
    /**
     * Set the time-stamp verification provider to use. This method can be overridden by unit tests.
     * 
     * @param timeStampVerificationImplementation Verification implementation to use
     **/
    protected void setTimeStampVerificationProviderImplementation(final Class<? extends TimeStampVerificationProvider> timeStampVerificationImplementation) {
        this.timeStampVerificationImplementation = timeStampVerificationImplementation;
    }
    
    /** Query the OCSP responder. This method can be overridden by unit tests.
     * @param url
     * @param request
     * @return 
     * @throws java.io.IOException
     * @throws org.bouncycastle.cert.ocsp.OCSPException **/
    protected OCSPResponse doQueryOCSPResponder(URL url, OCSPReq request) throws IOException, OCSPException {
        return ValidationUtils.queryOCSPResponder(url, request);
    }
    
}