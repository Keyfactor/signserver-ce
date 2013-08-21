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
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.signserver.common.*;
import org.signserver.server.WorkerContext;
import org.signserver.server.validators.BaseValidator;
import org.signserver.validationservice.common.ValidateResponse;
import org.signserver.validationservice.common.Validation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import xades4j.XAdES4jException;
import xades4j.providers.CertificateValidationProvider;
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
    
    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        configErrors = new LinkedList<String>();
        
        revocationEnabled = Boolean.parseBoolean(config.getProperty(REVOCATION_CHECKING, REVOCATION_CHECKING_DEFAULT));

        // CERTIFICATES
        try {
            final Collection<Certificate> certificates = loadCertificatesFromProperty(CERTIFICATES);
            certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certificates));
        } catch (InvalidAlgorithmParameterException ex) {
            logPropertyError(workerId, CERTIFICATES, ex);
        } catch (NoSuchAlgorithmException ex) {
            logPropertyError(workerId, CERTIFICATES, ex);
        } catch (CertificateException ex) {
            logPropertyError(workerId, CERTIFICATES, ex);
        } catch (IOException ex) {
            logPropertyError(workerId, CERTIFICATES, ex);
        }
        
        // TRUSTANCHORS
        try {
            final String value = config.getProperty(TRUSTANCHORS);
            if (value == null) {
                logMissingProperty(workerId, TRUSTANCHORS);
            } else {
                final Collection<Certificate> trustedCertificates = CertTools.getCertsFromPEM(new ByteArrayInputStream(value.getBytes("UTF-8")));
                trustAnchors = KeyStore.getInstance("JKS");
                trustAnchors.load(null, /*"foo123".toCharArray()*/null);
                int i = 0;
                final StringBuilder sb = new StringBuilder();
                sb.append("Trusted certificates are:\n");
                for (Certificate cert : trustedCertificates) {
                    if (cert instanceof X509Certificate) {
                        trustAnchors.setCertificateEntry("trusted-" + i++, cert);
                        sb.append(((X509Certificate) cert).getSubjectDN()).append("\n");
                    }
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug(sb.toString());
                }
            }
        } catch (KeyStoreException ex) {
            logPropertyError(workerId, TRUSTANCHORS, ex);
        } catch (IOException ex) {
            logPropertyError(workerId, TRUSTANCHORS, ex);
        } catch (NoSuchAlgorithmException ex) {
            logPropertyError(workerId, TRUSTANCHORS, ex);
        } catch (CertificateException ex) {
            logPropertyError(workerId, TRUSTANCHORS, ex);
        }        
    }
    
    private void logPropertyError(final int workerId, final String property, final Exception ex) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Worker " + workerId + ": Property " + property + " caused an error", ex);
        }
        configErrors.add("Property " + property + " caused error: " + ex.getMessage());
    }
    
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
            results = CertTools.getCertsFromPEM(new ByteArrayInputStream(value.getBytes("UTF-8")));
        }
        return results;
    }

    @Override
    public ProcessResponse processData(ProcessRequest signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {

        // Check that the request contains a valid GenericSignRequest object with a byte[].
        if (!(signRequest instanceof GenericValidationRequest)) {
            throw new IllegalRequestException("Recieved request wasn't a expected GenericValidationRequest.");
        }
        IValidationRequest sReq = (IValidationRequest) signRequest;

        if (!(sReq.getRequestData() instanceof byte[])) {
            throw new IllegalRequestException("Recieved request data wasn't a expected byte[].");
        }
        
        if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }

        byte[] data = (byte[]) sReq.getRequestData();

        GenericValidationResponse response = validate(sReq.getRequestID(), data);
        return response;
    }

    private GenericValidationResponse validate(final int requestId, byte[] data) throws SignServerException {
        
        // Validation: parse
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc;
        try {
            doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(data));
        } catch (ParserConfigurationException ex) {
            throw new SignServerException("Document parsing error", ex);
        } catch (SAXException ex) {
            throw new SignServerException("Document parsing error", ex);
        } catch (IOException ex) {
            throw new SignServerException("Document parsing error", ex);
        }
        
        final XAdESVerificationResult result;
        try {
            CertificateValidationProvider certValidator = new PKIXCertificateValidationProvider(trustAnchors, revocationEnabled, certStore);

            XadesVerificationProfile p = new XadesVerificationProfile(certValidator);
            XadesVerifier verifier = p.newVerifier();
            
            Element node = doc.getDocumentElement();

            result = verifier.verify(node, new SignatureSpecificVerificationOptions());
        } catch (NoSuchAlgorithmException ex) {
            throw new SignServerException("XML signature validation error", ex);
        } catch (NoSuchProviderException ex) {
            throw new SignServerException("XML signature validation error", ex);
        } catch (XadesProfileResolutionException ex) {
            throw new SignServerException("XML signature validation error", ex);
        } catch (XAdES4jException ex) {
            LOG.info("Request " + requestId + " signature valid: false, " + ex.getMessage());
            return new GenericValidationResponse(requestId, false);
        }
        LOG.info("Request " + requestId + " signature valid: true");

        // Fill in the certificate validation information.
        // XXX: This is a bit awkward...
        // As the XAdES4j has checked the certificate we just fill in the values here
        List<X509Certificate> xchain = result.getValidationData().getCerts();
        List<Certificate> chain = new LinkedList<Certificate>();
        for (X509Certificate cert : xchain) {
            chain.add(cert);
        }
        Validation v = new Validation(result.getValidationCertificate(), chain, Validation.Status.VALID, "Certifiate passed validation");
        ValidateResponse vresponse = new ValidateResponse(v, null);

        return new GenericValidationResponse(requestId, true, vresponse, null);
    }

    @Override
    protected List<String> getFatalErrors() {
        final LinkedList<String> errors = new LinkedList<String>(super.getFatalErrors());
        errors.addAll(configErrors);
        return errors;
    }
}