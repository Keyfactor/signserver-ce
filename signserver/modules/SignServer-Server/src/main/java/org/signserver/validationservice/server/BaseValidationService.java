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

import java.util.*;

import java.util.Map.Entry;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.signserver.common.SignServerException;
import org.signserver.common.StaticWorkerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.validationservice.common.ValidationServiceConstants;
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
     * @see org.signserver.server.IWorker#init(int, org.signserver.common.WorkerConfig, org.signserver.server.WorkerContext, javax.persistence.EntityManager)
     */
    @Override
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
    @Override
    public WorkerStatus getStatus() {
        final List<WorkerStatusInfo.Entry> briefEntries = new LinkedList<WorkerStatusInfo.Entry>();
        final List<WorkerStatusInfo.Entry> completeEntries = new LinkedList<WorkerStatusInfo.Entry>();

        // Token status
        briefEntries.add(new WorkerStatusInfo.Entry("Token status", ct.getCryptoTokenStatus() == WorkerStatus.STATUS_ACTIVE ? "Active" : "Offline"));

        // Number of validators
        briefEntries.add(new WorkerStatusInfo.Entry("Number of validators", String.valueOf(validators.size())));

        // Properties
        final StringBuilder configValue = new StringBuilder();
        Properties properties = config.getProperties();
        for (String key : properties.stringPropertyNames()) {
            configValue.append("  ").append(key).append("=").append(properties.getProperty(key)).append("\n\n");
        }
        completeEntries.add(new WorkerStatusInfo.Entry("Active Properties are", configValue.toString()));

        // Validators
        final StringBuilder validatorsValue = new StringBuilder();
        for (Entry<Integer, IValidator> entry : validators.entrySet()) {
            validatorsValue.append("  Status validator ").append(entry.getKey()).append(": ");
            try {
                entry.getValue().testConnection();
                validatorsValue.append("OK");
            } catch (Exception e) {
                validatorsValue.append("FAILED");
            }
            validatorsValue.append("\n");
        }
        completeEntries.add(new WorkerStatusInfo.Entry("Validators", validatorsValue.toString()));

        return new StaticWorkerStatus(new WorkerStatusInfo(workerId, config.getProperty("NAME"), "Validation Service", ct.getCryptoTokenStatus(), briefEntries, Collections.<String>emptyList(), completeEntries, config));
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
