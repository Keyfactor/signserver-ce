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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.persistence.EntityManager;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericServletRequest;
import org.signserver.common.GenericValidationRequest;
import org.signserver.common.GenericValidationResponse;
import org.signserver.common.IValidationRequest;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.WorkerContext;
import org.signserver.server.validators.BaseValidator;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.ValidationServiceConstants;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * A Validator for XML documents.
 * 
 * Implements IValidator and have the following properties:
 * VALIDATIONSERVICEWORKER = Name or id of validation service worker for handling certificate validation
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class XMLValidator extends BaseValidator {

	private transient static final Logger log = Logger.getLogger(XMLValidator.class.getName());
	
	transient static final String PROP_VALIDATIONSERVICEWORKER	= "VALIDATIONSERVICEWORKER"; 
	
	private transient IWorkerSession.IRemote workersession;
	private transient int validationServiceWorkerId;
	
	
    @Override
	public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
		super.init(workerId, config, workerContext, workerEM);
		
//		if(config.getProperties().getProperty(PROP_VALIDATIONSERVICEWORKER) == null) {
//			throw new IllegalArgumentException("Error property '" + PROP_VALIDATIONSERVICEWORKER + "' is not set for xmlvalidator worker " + workerId);
//		}
		
		workersession = lookupWorkerSessionBean();
		validationServiceWorkerId = workersession.getWorkerId(config.getProperties().getProperty(PROP_VALIDATIONSERVICEWORKER));
		log.info("XMLValidator will use validation service worker: " + validationServiceWorkerId);
		
		if(validationServiceWorkerId < 1) {
//			throw new IllegalArgumentException("Could not find worker for property " + PROP_VALIDATIONSERVICEWORKER + ": " + config.getProperties().getProperty(PROP_VALIDATIONSERVICEWORKER));
			log.warn("Could not find worker for property " + PROP_VALIDATIONSERVICEWORKER + ": " + config.getProperties().getProperty(PROP_VALIDATIONSERVICEWORKER));
		}
	}

	public ProcessResponse processData(ProcessRequest signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        
		// Check that the request contains a valid GenericSignRequest object with a byte[].
		if(!(signRequest instanceof GenericValidationRequest)) {
			throw new IllegalRequestException("Recieved request wasn't a expected GenericValidationRequest.");
		}
		IValidationRequest sReq = (IValidationRequest) signRequest;
		
		if(!(sReq.getRequestData() instanceof byte[]) ) {
			throw new IllegalRequestException("Recieved request data wasn't a expected byte[].");
		}
		if(signRequest instanceof GenericServletRequest){
        	throw new IllegalArgumentException("GenericServletRequest not yet supported");
        }
		
        byte[] data = (byte[]) sReq.getRequestData();
//        byte[] fpbytes = CertTools.generateSHA1Fingerprint(data);
//		String fp = new String(Hex.encode(fpbytes));
        
		GenericValidationResponse response = validate(sReq.getRequestID(), data);
        return response;
    }
    
	private GenericValidationResponse validate(final int requestId, byte[] data) throws SignServerException {
		
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);

        Document doc;
        try {
        	doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(data));
        } catch(ParserConfigurationException ex) {
        	throw new SignServerException("Document parsing error", ex);
        } catch(SAXException ex) {
        	throw new SignServerException("Document parsing error", ex);
        } catch(IOException ex) {
        	throw new SignServerException("Document parsing error", ex);
        }
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            log.info("Request " + requestId + ": No signature found");
            return new GenericValidationResponse(requestId, false);
        }

        String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
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

        boolean validSignature = false;
        try {
        	XMLSignature signature = fac.unmarshalXMLSignature(valContext);
        	validSignature = signature.validate(valContext);
        } catch (MarshalException ex) {
        	throw new SignServerException("XML signature validation error", ex);
        } catch (XMLSignatureException ex) {
        	log.info("Request " + requestId + ": XML signature validation error", ex);
            return new GenericValidationResponse(requestId, false);
        }

        log.info("Request " + requestId + " signature valid: " + validSignature);
        
        if(certAndKeySelector.getChoosenCert() == null) {
        	throw new RuntimeException("CertificateAndKeySelector.select() does not seem to have been called");
        }
        X509Certificate choosenCert = certAndKeySelector.getChoosenCert();
        
        // Check certificate
        boolean validCertificate = false;
		ValidateResponse vresponse = null;
        
		// No need to check certificate if the signature anyway is inconsistent
        if(validSignature) {
	        if(log.isDebugEnabled()) {
	            log.debug("Request "+requestId +": validateCertificate:request("
	            	+ "\"" + choosenCert.getSubjectDN().toString() + "\", "
	            	+ "\"" + choosenCert.getIssuerDN().toString() + "\", "
	            	+ "\"" + choosenCert.getNotBefore() + "\", "
	            	+ "\"" + choosenCert.getNotAfter() + "\")");
			}
	        
	        ValidateRequest vr;
			ProcessResponse response;
			try {
				vr = new ValidateRequest(org.signserver.validationservice.common.X509Certificate.getInstance(choosenCert), ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
			} catch (CertificateEncodingException e) {
				throw new SignServerException("Error validating certificate", e);
			} catch (CertificateParsingException e) {
				throw new SignServerException("Error validating certificate", e);
			} catch (IOException e) {
				throw new SignServerException("Error validating certificate", e);
			}
			
			try {
				response = workersession.process(validationServiceWorkerId, vr, new RequestContext());
				log.info("ProcessResponse: " + response);
				
				if(response == null){
					throw new SignServerException("Error communicating with validation servers, no server in the cluster seem available.");
				}
				
				if(!(response instanceof ValidateResponse)) {
					throw new SignServerException("Unexpected certificate validation response: " + response);
				}
				vresponse = (ValidateResponse) response;
				
				if(log.isDebugEnabled()) {
		            log.debug("Request "+requestId +": validateCertificate:response("
		            	+ "\"" + vresponse.getValidation().getStatus() + "\", "
		            	+ "\"" + (vresponse.getValidCertificatePurposes() == null ? "" :  vresponse.getValidCertificatePurposes()) + "\")");
				}
				
				// Check certificate path validation
		        if(Validation.Status.VALID.equals(vresponse.getValidation().getStatus())) {
		        	validCertificate = true;
		        }
				
			} catch (IllegalRequestException e) {
				log.warn("Error validating certificate", e);
			} catch (CryptoTokenOfflineException e) {
				log.warn("Error validating certificate", e);
			} catch (SignServerException e) {
				log.warn("Error validating certificate", e);
			}
	        log.info("Request " + requestId + " valid certificate: " + validCertificate);
        }
        
        
        return new GenericValidationResponse(requestId, validSignature && validCertificate, vresponse);
	}
	
	private static IWorkerSession.IRemote lookupWorkerSessionBean() {
        try {
        	Context context = new InitialContext();
    		return (IWorkerSession.IRemote) context.lookup(IWorkerSession.IRemote.JNDI_NAME);
        } catch (NamingException ne) {
            throw new RuntimeException(ne);
        }
    }

//	@Override
//	public WorkerStatus getStatus() {
//		//return new XMLValidatorStatus(workerId, config);
//	}
	
}