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

import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.common.data.CertificateValidationRequest;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.server.BaseProcessable;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.validationservice.common.ValidationServiceConstants;

/**
 * Class acting as middle-ware transforming an ISigner to
 * a IValidationService.
 *
 * @author Philip Vendil 16 nov 2007
 * @version $Id$
 */
public class ValidationServiceWorker extends BaseProcessable {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ValidationServiceWorker.class);
    
    private IValidationService validationService;
    private List<String> fatalErrors;
    
    /**
     * Initialization method creating the validation service
     * 
     * @param workerId  Worker ID
     * @param config Worker configuration
     * @param workerContext Worker context
     * @param workerEntityManager Enitity manager
     * @see org.signserver.server.BaseWorker#init(int, org.signserver.common.WorkerConfig, javax.persistence.EntityManager)
     */
    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEntityManager) {
        super.init(workerId, config, workerContext, workerEntityManager);
        fatalErrors = new LinkedList<>();
        
        try {
            validationService = createValidationService(config);
        } catch (SignServerException e) {
            final String error = "Could not get crypto token: " + e.getMessage();
            LOG.error(error);
            fatalErrors.add(error);
        }
    }

    /**
     * Creating a Validation Service depending on the TYPE setting
     * @param config configuration containing the validation service to create
     * @return a non initialized group key service.
     */
    @SuppressWarnings("deprecation") // Need to still use 'em' for backwards compatibility
    private IValidationService createValidationService(WorkerConfig config) throws SignServerException {
        String classPath = config.getProperties().getProperty(ValidationServiceConstants.VALIDATIONSERVICE_TYPE, ValidationServiceConstants.DEFAULT_TYPE);
        IValidationService retval = null;
        String error = null;
        try {
            if (classPath != null) {
                Class<?> implClass = Class.forName(classPath);
                retval = (IValidationService) implClass.newInstance();

                retval.init(workerId, config, em);
            }
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
            error = "Error instatiating Validation Service, check that the TYPE setting of workerid : " + workerId + " have the correct class path.";
            LOG.error(error, e);
        }

        if (error != null) {
            fatalErrors.add(error);
        }
        
        return retval;
    }

    /**
     * Main method of the container calling the appropriate method
     * of the ValidationService depending on the type of request.
     * 
     * @see org.signserver.server.IProcessable#processData(org.signserver.common.ProcessRequest, org.signserver.common.RequestContext) 
     */
    @Override
    public Response processData(Request processRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {

        if (processRequest instanceof CertificateValidationRequest) {
            return validationService.validate((CertificateValidationRequest) processRequest);
        } else {
            throw new IllegalRequestException("The process request sent to validation service with ID " + workerId + " isn't supported");
        }
    }

    /**
     * @return The status
     * @see org.signserver.server.BaseProcessable#getStatus()
     */
    @Override
    public WorkerStatusInfo getStatus(final List<String> additionalFatalErrors, final IServices services) {
        return validationService.getStatus(services);
    }

    @Override
    protected List<String> getFatalErrors(IServices services) {
        final List<String> errors = new LinkedList<>();
        
        errors.addAll(super.getFatalErrors(services));
        errors.addAll(fatalErrors);

        return errors;
    }
}
