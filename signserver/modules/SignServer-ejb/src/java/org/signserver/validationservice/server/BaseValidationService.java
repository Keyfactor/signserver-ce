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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.validationservice.common.ValidationServiceConstants;
import org.signserver.validationservice.common.ValidationStatus;
import org.signserver.validationservice.server.validcache.ValidationCache;

/**
 * Base class of a BaseGroup Key Service taking care of basic functionality
 * such as initializing and creating the extended crypto token.
 *
 * @author Philip Vendil 23 nov 2007
 * @version $Id$
 */
public abstract class BaseValidationService implements IValidationService {

    /** Logger for implementing class. */
    private final transient Logger log = Logger.getLogger(this.getClass());
    
    protected int workerId;
    protected WorkerConfig config;
    protected EntityManager em;
    protected ICryptoToken ct;
    protected HashMap<Integer, IValidator> validators;
    protected ValidationCache validationCache;

    private ICertPurposeChecker certTypeChecker;
    
    /**
     * @throws SignServerException 
     * @see org.signserver.server.IWorker#init(int, org.signserver.common.WorkerConfig,EntityManager)
     */
    public void init(int workerId, WorkerConfig config, EntityManager em, ICryptoToken ct) {
        this.workerId = workerId;
        this.config = config;
        this.em = em;
        this.ct = ct;

        try {
            validators = ValidationHelper.genValidators(workerId, config, em, ct);
        } catch (SignServerException e) {
            log.error(e.getMessage(), e);
        }

        // initialize validation cache
        long cacheTime = Long.parseLong(ValidationServiceConstants.DEFAULT_TIMEINCACHE);
        try {
            cacheTime = Long.parseLong(config.getProperties().getProperty(ValidationServiceConstants.VALIDATIONSERVICE_TIMEINCACHE, ValidationServiceConstants.DEFAULT_TIMEINCACHE));
        } catch (NumberFormatException e) {
            log.error("Error in Validation Service " + workerId + " setting " + ValidationServiceConstants.VALIDATIONSERVICE_TIMEINCACHE + " should only contain numbers, using default value");
        }

        validationCache = new ValidationCache(getCachedIssuers(config.getProperties()), cacheTime * 1000);
    }

    private List<String> getCachedIssuers(Properties props) {
        ArrayList<String> retval = new ArrayList<String>();
        String fullString = props.getProperty(ValidationServiceConstants.VALIDATIONSERVICE_CACHEDISSUERS);
        if (fullString != null) {
            String[] issuerDNs = fullString.split(";");
            for (int i = 0; i < issuerDNs.length; i++) {
                retval.add(CertTools.stringToBCDNString(issuerDNs[i]));
            }
        }

        return retval;
    }

    /**
     * @see org.signserver.validationservice.server.IValidationService#getStatus()
     */
    public WorkerStatus getStatus() {

        HashMap<Integer, String> validatorStatuses = new HashMap<Integer, String>();
        for (Integer validationId : validators.keySet()) {
            try {
                validators.get(validationId).testConnection();
                validatorStatuses.put(validationId, ValidationStatus.CONNECTION_OK);
            } catch (Exception e) {
                validatorStatuses.put(validationId, ValidationStatus.CONNECTION_FAILED);
            }

        }

        return new ValidationStatus(workerId, ct.getCryptoTokenStatus(), config, validatorStatuses);
    }

    /**
     * Method returning the configured cert type checker if it wasn't configured properly.
     */
    protected ICertPurposeChecker getCertPurposeChecker() throws SignServerException {
        if (certTypeChecker == null) {
            String classpath = config.getProperties().getProperty(ValidationServiceConstants.VALIDATIONSERVICE_CERTPURPOSECHECKER, ValidationServiceConstants.DEFAULT_CERTPURPOSECHECKER);
            try {
                Class<?> c = ValidationHelper.class.getClassLoader().loadClass(classpath);
                certTypeChecker = (ICertPurposeChecker) c.newInstance();
                certTypeChecker.init(config);
            } catch (ClassNotFoundException e) {
                throw new SignServerException("Error Validation Service with workerId " + workerId + " have got bad classpath  " + classpath + " for the setting " + ValidationServiceConstants.VALIDATIONSERVICE_CERTPURPOSECHECKER);
            } catch (InstantiationException e) {
                throw new SignServerException("Error Validation Service with workerId " + workerId + " have got bad classpath  " + classpath + " for the setting " + ValidationServiceConstants.VALIDATIONSERVICE_CERTPURPOSECHECKER);
            } catch (IllegalAccessException e) {
                throw new SignServerException("Error Validation Service with workerId " + workerId + " have got bad classpath  " + classpath + " for the setting " + ValidationServiceConstants.VALIDATIONSERVICE_CERTPURPOSECHECKER);
            }
        }
        return certTypeChecker;
    }
}
