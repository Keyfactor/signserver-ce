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

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.server.BaseProcessable;
import org.signserver.server.WorkerContext;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidationServiceConstants;

/**
 * Class acting as middle-ware transforming an ISigner to
 * a IValidationService.
 * 
 * 
 * @author Philip Vendil 16 nov 2007
 *
 * @version $Id$
 */
public class ValidationServiceWorker extends BaseProcessable {
	
	private transient Logger log = Logger.getLogger(this.getClass());

	
	private IValidationService validationService;


	
	/**
	 * Initialization method creating the validation service
	 * @see org.signserver.server.BaseWorker#init(int, org.signserver.common.WorkerConfig, javax.persistence.EntityManager)
	 */
	@Override
	public void init(int workerId, WorkerConfig config, WorkerContext workerContext,EntityManager workerEntityManager) {		
		super.init(workerId, config, workerContext,workerEntityManager);
		
		validationService = createValidationService(config);
	}


    /**
     * Creating a Validation Service depending on the TYPE setting
     * @param config configuration containing the validation service to create
     * @return a non initialized group key service.
     */
	private IValidationService createValidationService(WorkerConfig config) {
		String classPath = config.getProperties().getProperty(ValidationServiceConstants.VALIDATIONSERVICE_TYPE, ValidationServiceConstants.DEFAULT_TYPE);
		IValidationService retval = null;
		try{						
			if(classPath != null){					
				Class<?> implClass = Class.forName(classPath);
				retval = (IValidationService) implClass.newInstance();

				retval.init(workerId, config, em,getCryptoToken());	
			}  
		}catch(ClassNotFoundException e){
			log.error("Error instatiating Validation Service, check that the TYPE setting of workerid : " + workerId + " have the correct class path.",e);
		}
		catch(IllegalAccessException e){
			log.error("Error instatiating Validation Service, check that the TYPE setting of workerid : " + workerId + " have the correct class path.",e);
		}
		catch(InstantiationException e){
			log.error("Error instatiating Validation Service, check that the TYPE setting of workerid : " + workerId + " have the correct class path.",e);
		} 
		
		return retval;
	}


	/**
	 * Main method of the container calling the appropriate method
	 * of the ValidationService depending on the type of request.
	 * 
	 * @see org.signserver.server.signers.IProcessable#processData(org.signserver.common.ProcessRequest, java.security.cert.X509Certificate)
	 */
	public ProcessResponse processData(ProcessRequest processRequest,
			RequestContext requestContext) throws IllegalRequestException,
			CryptoTokenOfflineException, SignServerException {
		
		if(processRequest instanceof ValidateRequest){
			return validationService.validate((ValidateRequest) processRequest);
		}else{
		  throw new IllegalRequestException("The process request sent to validation service with id " + workerId + " isn't supported");
		}
	}


	/**
	 * @see org.signserver.server.signers.BaseProcessable#getStatus()
	 */
	public WorkerStatus getStatus() {		
		return validationService.getStatus();
	}
	
	

}
