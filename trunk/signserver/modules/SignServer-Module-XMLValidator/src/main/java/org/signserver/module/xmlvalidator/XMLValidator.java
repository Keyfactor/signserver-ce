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
package org.signserver.module.xmlvalidator;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.common.data.CertificateValidationRequest;
import org.signserver.common.data.CertificateValidationResponse;
import org.signserver.common.data.DocumentValidationRequest;
import org.signserver.common.data.DocumentValidationResponse;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.validators.BaseValidator;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.ValidationServiceConstants;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * A Validator for XML documents.
 *
 * Implements IValidator and have the following properties:
 * VALIDATIONSERVICEWORKER = Name or id of validation service worker for
 *                           handling certificate validation
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class XMLValidator extends BaseValidator {

    /** Logger. */
    private static final Logger LOG = Logger.getLogger(XMLValidator.class);
    
    /** VALIDATIONSERVICEWORKER property. */
    static final String PROP_VALIDATIONSERVICEWORKER =
            "VALIDATIONSERVICEWORKER";

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();
    
    private String validationServiceWorker;

    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        // Required property: VALIDATIONSERVICEWORKER
        validationServiceWorker = config.getProperty(PROP_VALIDATIONSERVICEWORKER);
        if (validationServiceWorker == null || validationServiceWorker.trim().isEmpty()) {
            configErrors.add("Missing required property: " + PROP_VALIDATIONSERVICEWORKER);
        }
    }

    @Override
    public Response processData(Request signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        try {
            if (!configErrors.isEmpty()) {
                throw new SignServerException("Worker is misconfigured");
            }
            
            // Check that the request contains a valid GenericSignRequest object with a byte[].
            if (!(signRequest instanceof DocumentValidationRequest)) {
                throw new IllegalRequestException("Received request wasn't an expected GenericValidationRequest.");
            }
            DocumentValidationRequest sReq = (DocumentValidationRequest) signRequest;
            
            byte[] data = (byte[]) sReq.getRequestData().getAsByteArray();
            
            DocumentValidationResponse response = validate(sReq.getRequestID(), data, requestContext);
            
            // The client can be charged for the request
            requestContext.setRequestFulfilledByWorker(true);
            
            return response;
        } catch (IOException ex) {
            throw new SignServerException("IO error", ex);
        }
    }

    private DocumentValidationResponse validate(final int requestId, byte[] data, RequestContext requestContext) throws SignServerException {

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

            doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(data));
        } catch (ParserConfigurationException | SAXException | IOException ex) {
            throw new SignServerException("Document parsing error", ex);
        }
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            LOG.info("Request " + requestId + ": No signature found");
            return new DocumentValidationResponse(requestId, false);
        }

        String providerName = System.getProperty("jsr105Provider", "org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI");
        XMLSignatureFactory fac;
        try {
            fac = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            throw new SignServerException("Problem with JSR105 provider", e);
        }

        CertificateAndKeySelector certAndKeySelector = new CertificateAndKeySelector(requestId);
        DOMValidateContext valContext = new DOMValidateContext(certAndKeySelector, nl.item(0));

        // enable secure validation
        valContext.setProperty("org.apache.jcp.xml.dsig.secureValidation", Boolean.TRUE);

        boolean validSignature = false;
        try {
            XMLSignature signature = fac.unmarshalXMLSignature(valContext);
            validSignature = signature.validate(valContext);
        } catch (MarshalException ex) {
            throw new SignServerException("XML signature validation error", ex);
        } catch (XMLSignatureException ex) {
            LOG.info("Request " + requestId + ": XML signature validation error", ex);
            return new DocumentValidationResponse(requestId, false);
        }

        LOG.info("Request " + requestId + " signature valid: " + validSignature);

        if (certAndKeySelector.getChoosenCert() == null) {
            throw new RuntimeException("CertificateAndKeySelector.select() does not seem to have been called");
        }
        X509Certificate choosenCert = certAndKeySelector.getChoosenCert();

        // Check certificate
        boolean validCertificate = false;
        CertificateValidationResponse vresponse = null;

        // No need to check certificate if the signature anyway is inconsistent
        if (validSignature) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Request " + requestId + ": validateCertificate:request("
                        + "\"" + choosenCert.getSubjectDN().toString() + "\", "
                        + "\"" + choosenCert.getIssuerDN().toString() + "\", "
                        + "\"" + choosenCert.getNotBefore() + "\", "
                        + "\"" + choosenCert.getNotAfter() + "\")");
            }

            CertificateValidationRequest vr = new CertificateValidationRequest(choosenCert, ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
            Response response;

            try {
                LOG.info("Requesting certificate validation from worker: " + PROP_VALIDATIONSERVICEWORKER);
                response = getProcessSession(requestContext).process(new AdminInfo("Client user", null, null), WorkerIdentifier.createFromIdOrName(validationServiceWorker), vr, new RequestContext());
                LOG.info("ProcessResponse: " + response);

                if (response == null) {
                    throw new SignServerException("Error communicating with validation servers, no server in the cluster seem available.");
                }

                if (!(response instanceof CertificateValidationResponse)) {
                    throw new SignServerException("Unexpected certificate validation response: " + response);
                }
                vresponse = (CertificateValidationResponse) response;

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Request " + requestId + ": validateCertificate:response("
                            + "\"" + vresponse.getValidation().getStatus() + "\", "
                            + "\"" + (vresponse.getValidCertificatePurposes() == null ? "" : vresponse.getValidCertificatePurposes()) + "\")");
                }

                // Check certificate path validation
                if (Validation.Status.VALID.equals(vresponse.getValidation().getStatus())) {
                    validCertificate = true;
                }

            } catch (IllegalRequestException | CryptoTokenOfflineException | SignServerException e) {
                LOG.warn("Error validating certificate", e);
            }
            LOG.info("Request " + requestId + " valid certificate: " + validCertificate);
        }

        return new DocumentValidationResponse(requestId, validSignature && validCertificate, vresponse);
    }

    /**
     * Get process session.
     * 
     * @param requestContext Request context
     * @return The worker session. Can be overridden for instance by unit tests.
     */
    protected InternalProcessSessionLocal getProcessSession(RequestContext requestContext) {
        return requestContext.getServices().get(InternalProcessSessionLocal.class);
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        // Add our errors to the list of errors
        final LinkedList<String> errors = new LinkedList<>(
                super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }
}
