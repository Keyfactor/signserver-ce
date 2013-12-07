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
package org.signserver.protocol.validationservice.ws.server;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebService;
import javax.naming.NamingException;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import org.apache.log4j.Logger;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.signserver.common.*;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.healthcheck.HealthCheckUtils;
import org.signserver.protocol.validationservice.ws.IValidationWS;
import org.signserver.protocol.validationservice.ws.ValidationResponse;
import org.signserver.server.nodb.FileBasedDatabaseManager;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;
import org.signserver.validationservice.common.ValidationStatus;
import org.signserver.validationservice.server.ValidationServiceWorker;

/**
 * Implementation of the Validation Service web interface.
 *
 * @version $Id$
 */
@Stateless
@WebService(wsdlLocation = "META-INF/wsdl/ValidationWSService.wsdl",
targetNamespace = "gen.ws.validationservice.protocol.signserver.org")
public class ValidationWS implements IValidationWS {

    private int minimumFreeMemory = 1;
    private String checkDBString = "Select count(*) from signerconfigdata";
    
    @Resource
    private WebServiceContext wsContext;
    private static final Logger log = Logger.getLogger(ValidationWS.class);
    
    @EJB
    private IWorkerSession.ILocal signserversession;
    
    @EJB
    private IGlobalConfigurationSession.ILocal globalconfigsession;
    
    /** EntityManager is conditionally injected from ejb-jar.xml. */
    private EntityManager em;

    /**
     * @see org.signserver.protocol.validationservice.ws.IValidationWS#isValid(String, String, String)
     */
    @WebMethod
    public ValidationResponse isValid(@WebParam(name = "serviceName") String serviceName, @WebParam(name = "base64Cert") String base64Cert, @WebParam(name = "certPurposes") String certPurposes) throws IllegalRequestException, SignServerException {
        Certificate reqCert;
        int workerId = getWorkerId(serviceName);

        if (workerId == 0) {
            throw new IllegalRequestException("Illegal service name : " + serviceName + " no validation service with such name exists");
        }

        if (base64Cert == null) {
            throw new IllegalRequestException("Error base64Cert parameter cannot be empty, it must contain a Base64 encoded DER encoded certificate.");
        } else {
            try {
                reqCert = CertTools.getCertfromByteArray(Base64.decode(base64Cert.getBytes()));
            } catch (CertificateException e) {
                throw new IllegalRequestException("Error base64Cert parameter data have bad encoding, check that it contains supported certificate data");
            }
        }

        if (certPurposes == null) {
            certPurposes = "";
        } else {
            certPurposes = certPurposes.trim();
        }

        ValidateResponse res = null;
        try {
            ValidateRequest req = new ValidateRequest(reqCert, certPurposes);
            res = (ValidateResponse) getWorkerSession().process(workerId, req, genRequestContext());
        } catch (CertificateEncodingException e) {
            throw new IllegalRequestException("Error in request, the requested certificate seem to have a unsupported encoding : " + e.getMessage());
        } catch (CryptoTokenOfflineException e) {
            throw new SignServerException("Error using cryptotoken when validating certificate, it seems to be offline : " + e.getMessage());
        }
        return new ValidationResponse(res.getValidation(), res.getValidCertificatePurposes());
    }

    /**
     * Returning the worker id of the validation service with corresponding name or Id.
     * Otherwise is 0 returned.
     */
    private int getWorkerId(String serviceName) {
        int retval = 0;

        if (serviceName.substring(0, 1).matches("\\d")) {
            retval = Integer.parseInt(serviceName);
        } else {
            retval = getWorkerSession().getWorkerId(serviceName);
        }

        if (retval != 0) {
            String classPath = getGlobalConfigurationSession().getGlobalConfiguration().getProperty(GlobalConfiguration.SCOPE_GLOBAL, GlobalConfiguration.WORKERPROPERTY_BASE + retval + GlobalConfiguration.WORKERPROPERTY_CLASSPATH);
            if (classPath == null || !classPath.trim().equals(ValidationServiceWorker.class.getName())) {
                retval = 0;
            }
        }

        return retval;

    }

    private RequestContext genRequestContext() {
        return new RequestContext(getClientCertificate(), getRequestIP());
    }

    /**
     * @see org.signserver.protocol.validationservice.ws.IValidationWS#getStatus(java.lang.String)
     */
    @WebMethod
    public String getStatus(@WebParam(name = "serviceName") String serviceName) throws IllegalRequestException {

        int workerId = getWorkerId(serviceName);

        if (workerId == 0) {
            throw new IllegalRequestException("Illegal service name : " + serviceName + " no validation service with such name exists");
        }
        final String result;
        final LinkedList<String> errors = new LinkedList<String>();

        if (FileBasedDatabaseManager.getInstance().isUsed()) {
            errors.addAll(FileBasedDatabaseManager.getInstance().getFatalErrors());
        } else {
            errors.addAll(HealthCheckUtils.checkDB(em, getCheckDBString()));
        }
        
        if (errors.isEmpty()) {
            errors.addAll(HealthCheckUtils.checkMemory(getMinimumFreeMemory()));
            
            if (errors.isEmpty()) {
                errors.addAll(checkValidationService(workerId));
            }
        }
        
        // Render result
        if (errors.isEmpty()) {
            result = "ALLOK";
        } else {
            final StringBuilder buff = new StringBuilder();
            for (final String error : errors) {
                buff.append(error).append("\n");
            }
            result = buff.toString();
        }
        return result;
    }

    private List<String> checkValidationService(int workerId) {
        final LinkedList<String> result = new LinkedList<String>();
        try {
            ValidationStatus status = (ValidationStatus) getWorkerSession().getStatus(workerId);
            for (String error : status.getFatalErrors()) {
                result.add("Worker " + status.getWorkerId() + ": " + error + "\n");
            }
        } catch (InvalidWorkerIdException e) {
            log.error("Error invalid worker id " + workerId + "when checking status for validation service");
        }
        return result;
    }

    private int getMinimumFreeMemory() {
        final String minMemory = CompileTimeSettings.getInstance().getProperty(
                CompileTimeSettings.HEALTHECK_MINIMUMFREEMEMORY);
        if (minMemory != null) {
            try {
                minimumFreeMemory = Integer.parseInt(minMemory.trim());
            } catch (NumberFormatException e) {
                log.error("Error: SignServerWS badly configured, setting healthcheck.minimumfreememory should only contain integers");
            }
        }
        return minimumFreeMemory;
    }

    private String getCheckDBString() {
        final String dbString = CompileTimeSettings.getInstance().getProperty(
                CompileTimeSettings.HEALTHECK_CHECKDBSTRING);
        if (dbString != null) {
            checkDBString = dbString;
        }
        return checkDBString;
    }

    private X509Certificate getClientCertificate() {
        MessageContext msgContext = wsContext.getMessageContext();
        HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
        X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

        if (certificates != null) {
            return certificates[0];
        }
        return null;
    }

    private String getRequestIP() {
        MessageContext msgContext = wsContext.getMessageContext();
        HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);

        return request.getRemoteAddr();
    }

    private IWorkerSession.ILocal getWorkerSession() {
        return signserversession;
    }

    private IGlobalConfigurationSession.ILocal getGlobalConfigurationSession() {
        return globalconfigsession;
    }
}
