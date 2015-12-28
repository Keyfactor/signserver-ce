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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import javax.naming.NamingException;
import javax.persistence.EntityManager;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.ejb.interfaces.ProcessSessionLocal;
import org.signserver.server.WorkerContext;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.validators.BaseValidator;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.ValidationServiceConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * A Validator for XML documents.
 *
 * Implements IValidator and have the following properties:
 * VALIDATIONSERVICEWORKER = Name or id of validation service worker for
 *                           handling certificate validation
 * RETURNDOCUMENT = True if the response should contain the validated document
 * STRIPSIGNATURE = True if the signature should be removed from the document
 *                  if it is returned
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
    
    /** RETURNDOCUMENT property. */
    static final String PROP_RETURNDOCUMENT = "RETURNDOCUMENT";
    
    /** STRIPSIGNATURE property. */
    static final String PROP_STRIPSIGNATURE = "STRIPSIGNATURE";
    
    /** Worker session. */
    private ProcessSessionLocal processSession;
    
    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<String>();
    
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
    public ProcessResponse processData(ProcessRequest signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }

        // Check that the request contains a valid GenericSignRequest object with a byte[].
        if (!(signRequest instanceof GenericValidationRequest)) {
            throw new IllegalRequestException("Recieved request wasn't a expected GenericValidationRequest.");
        }
        IValidationRequest sReq = (IValidationRequest) signRequest;

        if (!(sReq.getRequestData() instanceof byte[])) {
            throw new IllegalRequestException("Recieved request data wasn't a expected byte[].");
        }

        byte[] data = (byte[]) sReq.getRequestData();

        GenericValidationResponse response = validate(sReq.getRequestID(), data);
        
        // The client can be charged for the request
        requestContext.setRequestFulfilledByWorker(true);
            
        return response;
    }

    private GenericValidationResponse validate(final int requestId, byte[] data) throws SignServerException {

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
        } catch (ParserConfigurationException ex) {
            throw new SignServerException("Document parsing error", ex);
        } catch (SAXException ex) {
            throw new SignServerException("Document parsing error", ex);
        } catch (IOException ex) {
            throw new SignServerException("Document parsing error", ex);
        }
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            LOG.info("Request " + requestId + ": No signature found");
            return new GenericValidationResponse(requestId, false);
        }

        String providerName = System.getProperty("jsr105Provider", "org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI");
        XMLSignatureFactory fac;
        try {
            fac = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());
        } catch (InstantiationException e) {
            throw new SignServerException("Problem with JSR105 provider", e);
        } catch (IllegalAccessException e) {
            throw new SignServerException("Problem with JSR105 provider", e);
        } catch (ClassNotFoundException e) {
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
            return new GenericValidationResponse(requestId, false);
        }

        LOG.info("Request " + requestId + " signature valid: " + validSignature);

        if (certAndKeySelector.getChoosenCert() == null) {
            throw new RuntimeException("CertificateAndKeySelector.select() does not seem to have been called");
        }
        X509Certificate choosenCert = certAndKeySelector.getChoosenCert();

        // Check certificate
        boolean validCertificate = false;
        ValidateResponse vresponse = null;

        // No need to check certificate if the signature anyway is inconsistent
        if (validSignature) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Request " + requestId + ": validateCertificate:request("
                        + "\"" + choosenCert.getSubjectDN().toString() + "\", "
                        + "\"" + choosenCert.getIssuerDN().toString() + "\", "
                        + "\"" + choosenCert.getNotBefore() + "\", "
                        + "\"" + choosenCert.getNotAfter() + "\")");
            }

            ValidateRequest vr;
            ProcessResponse response;
            try {
                vr = new ValidateRequest(choosenCert, ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
            } catch (CertificateEncodingException e) {
                throw new SignServerException("Error validating certificate", e);
            }

            try {
                LOG.info("Requesting certificate validation from worker: " + PROP_VALIDATIONSERVICEWORKER);
                response = getProcessSession().process(new AdminInfo("Client user", null, null), WorkerIdentifier.createFromIdOrName(validationServiceWorker), vr, new RequestContext());
                LOG.info("ProcessResponse: " + response);

                if (response == null) {
                    throw new SignServerException("Error communicating with validation servers, no server in the cluster seem available.");
                }

                if (!(response instanceof ValidateResponse)) {
                    throw new SignServerException("Unexpected certificate validation response: " + response);
                }
                vresponse = (ValidateResponse) response;

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Request " + requestId + ": validateCertificate:response("
                            + "\"" + vresponse.getValidation().getStatus() + "\", "
                            + "\"" + (vresponse.getValidCertificatePurposes() == null ? "" : vresponse.getValidCertificatePurposes()) + "\")");
                }

                // Check certificate path validation
                if (Validation.Status.VALID.equals(vresponse.getValidation().getStatus())) {
                    validCertificate = true;
                }

            } catch (IllegalRequestException e) {
                LOG.warn("Error validating certificate", e);
            } catch (CryptoTokenOfflineException e) {
                LOG.warn("Error validating certificate", e);
            } catch (SignServerException e) {
                LOG.warn("Error validating certificate", e);
            }
            LOG.info("Request " + requestId + " valid certificate: " + validCertificate);
        }

        byte[] processedBytes = null;
        if (Boolean.parseBoolean(config.getProperty(PROP_RETURNDOCUMENT))) {
            if (Boolean.parseBoolean(config.getProperty(PROP_STRIPSIGNATURE))) {
                try {
                    processedBytes = unwrapSignature(doc, "Signature");
                } catch (TransformerConfigurationException ex) {
                    throw new SignServerException("Error stripping Signature tag", ex);
                } catch (TransformerException ex) {
                    throw new SignServerException("Error stripping Signature tag", ex);
                }
            } else {
                processedBytes = data;
            }
        }

        return new GenericValidationResponse(requestId, validSignature && validCertificate, vresponse, processedBytes);
    }

    private byte[] unwrapSignature(Document doc, String tagName) throws TransformerConfigurationException, TransformerException {

        // Remove Signature element
        Node rootNode = doc.getFirstChild();
        NodeList nodeList = rootNode.getChildNodes();
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (tagName.equals(node.getLocalName())) {
                rootNode.removeChild(node);
            }
        }

        // Render the result
        Transformer xformer = TransformerFactory.newInstance().newTransformer();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        xformer.transform(new DOMSource(doc), new StreamResult(out));
        return out.toByteArray();
    }

    /**
     * @return The worker session. Can be overridden for instance by unit tests.
     */
    protected ProcessSessionLocal getProcessSession() {
        if (processSession == null) {
            try {
                processSession = ServiceLocator.getInstance().lookupLocal(
                        ProcessSessionLocal.class);
            } catch (NamingException ne) {
                throw new RuntimeException(ne);
            }
        }
        return processSession;
    }

    @Override
    protected List<String> getFatalErrors() {
        // Add our errors to the list of errors
        final LinkedList<String> errors = new LinkedList<String>(
                super.getFatalErrors());
        errors.addAll(configErrors);
        return errors;
    }
}