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
package org.signserver.module.renewal.timedservice;

import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import javax.ejb.EJB;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericPropertiesRequest;
import org.signserver.common.GenericPropertiesResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerConstants;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.module.renewal.common.RenewalWorkerProperties;
import org.signserver.server.ServiceExecutionFailedException;
import org.signserver.server.WorkerContext;
import org.signserver.server.timedservices.BaseTimedService;

/**
 * TimedService that looks up the status of a number of workers and requests
 * those that needs renewal to be renewed by a RenewalWorker.
 *
 * @author Markus Kilas
 * @version $Id: SignerStatusReportTimedService.java 1218 2010-10-05 20:13:57Z netmackan $
 */
public class AutoRenewalTimedService extends BaseTimedService {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(AutoRenewalTimedService.class);

    /** Property WORKERS. **/
    private static final String PROPERTY_WORKERS = "WORKERS";
    private static final String PROPERTY_DEFAULTRENEWWORKER
            = "DEFAULTRENEWWORKER";

    /**
     * When a signer has less then the number of signings indicated by this
     * property before reaching the key usage limit, it is up for renewal.
     */
    private static final String WORKERPROPERTY_RENEWKEYUSAGESLEFT
            = "RENEWKEYUSAGESLEFT";

    /**
     * When a signer has less then the number of days indicated by this
     * property before ending the signing validity, it is up for renewal.
     */
    private static final String WORKERPROPERTY_RENEWSIGNINGVALIDITYLEFT
            = "RENEWSIGNINGVALIDITYLEFT";

    private static final String WORKERPROPERTY_RENEWWORKER
            = "RENEWWORKER";

    private static final String STATUS_ACTIVE = "ACTIVE";
    private static final String STATUS_OFFLINE = "OFFLINE";

    private static final String SEPARATOR = ", ";

    /** List of worker names. */
    private List<String> workers = Collections.emptyList();

    private String defaultRenewalWorker;

    /** Workersession. */
    @EJB
    private IWorkerSession.ILocal workerSession;

    /**
     * Initializes the worker.
     * @param workerId Id of worker
     * @param config the configuration
     * @param workerContext the context
     * @param workerEntityManager entity manager
     */
    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext,
            final EntityManager workerEntityManager) {
        super.init(workerId, config, workerContext, workerEntityManager);

        workers = new LinkedList<String>();
        final String workersValue = config.getProperty(PROPERTY_WORKERS);
        if (workersValue == null) {
            LOG.error("Worker[" + workerId +"]: " + "Property WORKERS missing!");
        } else {
            for (String worker : workersValue.split(",")) {
                workers.add(worker);
            }
        }
        LOG.info("Worker[" + workerId +"]: " + "Workers: " + workers.size());

        defaultRenewalWorker = config.getProperty(PROPERTY_DEFAULTRENEWWORKER);
        if (defaultRenewalWorker == null) {
            LOG.warn("Worker[" + workerId +"]: " + "Property "
                    + PROPERTY_DEFAULTRENEWWORKER + " not set");
        }

        getWorkerSession();
    }

    /**
     * Called to execute this timed service.
     * @see org.signserver.server.timedservices.ITimedService#work()
     * @throws ServiceExecutionFailedException in case of exception
     */
    public final void work() throws ServiceExecutionFailedException {
        LOG.trace(">work");
        LOG.info("Worker[" + workerId + "]: Service called");

        try {
            for (String signer : workers) {
                int signerId = getWorkerSession().getWorkerId(signer);
                if (signerId == 0) {
                    LOG.warn("No such worker: \"" + signer + "\"");
                } else {
                    LOG.debug("Worker: " + signer);

//                    final String pk = getKeyHash(signerId);
//
//                    // Offline/no certificate at all
//                    if (pk == null) {
//                        LOG.info("Not checking offline worker: " + signerId);
//                    } else {

                        final WorkerConfig workerConfig = getWorkerSession()
                                .getCurrentWorkerConfig(signerId);

                        // Get renewal worker name
                        final String renewalWorker = workerConfig.getProperty(
                                WORKERPROPERTY_RENEWWORKER,
                                defaultRenewalWorker);

                        // Check setting for signing validity left
                        final int minSigningValidityLeft;
                        final String validityLeft = workerConfig.getProperty(
                                WORKERPROPERTY_RENEWSIGNINGVALIDITYLEFT);
                        if (validityLeft == null) {
                            minSigningValidityLeft = 0;
                            // TODO: There could be a property with DEFAULT
                            // value in case the worker does not specify this
                        } else {
                            minSigningValidityLeft
                                    = Integer.parseInt(validityLeft);
                        }

                        // CHeck setting signings left
                        final int minSigningsLeft;
                        final String keyUsagesLeft = workerConfig.getProperty(
                                WORKERPROPERTY_RENEWKEYUSAGESLEFT);
                        if (keyUsagesLeft == null) {
                            minSigningsLeft = 0;
                        } else {
                            minSigningsLeft =
                                    Integer.parseInt(keyUsagesLeft);
                        }

                        // Get key usage counter value
                        final long keyUsageCounter = getWorkerSession()
                                .getKeyUsageCounterValue(signerId);

                        if (isRenewalNeeded(signerId, keyUsageCounter,
                                minSigningsLeft, minSigningValidityLeft)) {
                            LOG.info("Renewal needed for: " + signerId);
                            try {
                                if (renew(signer, renewalWorker)) {
                                    LOG.info("Renewed worker: " + signer);
                                } else {
                                    LOG.error("Renewal failed for worker: "
                                            + signer);
                                }
                            } catch (Exception ex) {
                                LOG.error("Error renewing worker: " + signer);
                            }
                        } else {
                            LOG.info("Renewal not needed: " + signerId);
                        }
//                    }

                }
            }
        } catch (Exception ex) {
            LOG.error("Error executing service: " + workerId, ex);
        }

        LOG.trace("<work");
    }

    private IWorkerSession.ILocal getWorkerSession() {
        if (workerSession == null) {
            try {
                final Context context = getInitialContext();
                workerSession = (IWorkerSession.ILocal)
                        context.lookup(IWorkerSession.ILocal.JNDI_NAME);
            } catch (NamingException ex) {
                throw new RuntimeException("Unable to lookup worker session",
                        ex);
            }
        }
        return workerSession;
    }

    private Context getInitialContext() throws NamingException {
        final Hashtable<String, String> props =
                new Hashtable<String, String>();
        props.put(Context.INITIAL_CONTEXT_FACTORY,
                "org.jnp.interfaces.NamingContextFactory");
        props.put(Context.URL_PKG_PREFIXES,
                "org.jboss.naming:org.jnp.interfaces");
        props.put(Context.PROVIDER_URL, "jnp://localhost:1099");
        return new InitialContext(props);
    }

    private boolean isRenewalNeeded(final int signerId, 
            final long signings, final int minSigningsLeft,
            final int minSigningValidityLeft) {

        final boolean ret;

        // Check validity
        Date notAfter = null;
        final Calendar cal = Calendar.getInstance();

        // Account for the min signing validity left
        cal.add(Calendar.DATE, minSigningValidityLeft);

        try {
            notAfter = workerSession.getSigningValidityNotAfter(
                    signerId);
        } catch (CryptoTokenOfflineException ignored) {}


        final long keyUsageLimit = Long.valueOf(
                    workerSession.getCurrentWorkerConfig(signerId)
                    .getProperty(
                        SignServerConstants.KEYUSAGELIMIT, "-1"));

        if (LOG.isDebugEnabled()) {
            final long timeToRenewal
                = (notAfter.getTime() - cal.getTime().getTime())
                    / (1000 * 60 * 60 * 24);
            final long signingsToRenewal
                    = keyUsageLimit - signings - minSigningsLeft;

            LOG.debug("Service[" + workerId +"]: signer " + signerId
                    + " time to renewal: " + timeToRenewal
                    + ", signings left: " + signingsToRenewal);
        }

        if (notAfter != null && cal.getTime().after(notAfter)) {
            ret = true;
        } else if (keyUsageLimit != -1 
                && signings+minSigningsLeft >= keyUsageLimit) {
            ret = true;
        } else {
            ret = false;
        }

        return ret;
    }

    private boolean renew(final String signer, final String renewalWorker) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        final boolean result;

        if (renewalWorker == null || renewalWorker.isEmpty()) {
            LOG.error("Worker[" + workerId
                    + "]: No renewal worker configured for worker " + signer);
            result = false;
        } else {
            final Properties properties = new Properties();
            properties.setProperty(RenewalWorkerProperties.REQUEST_WORKER,
                    signer);
            final int renewalWorkerId
                    = getWorkerSession().getWorkerId(renewalWorker);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Trying to renew " + signer + " using renewal worker "
                    + renewalWorkerId);
            }
            final ProcessResponse processResp
                    = getWorkerSession().process(renewalWorkerId, 
                        new GenericPropertiesRequest(properties),
                        new RequestContext());
            if (processResp instanceof GenericPropertiesResponse) {
                final Properties response
                        = ((GenericPropertiesResponse) processResp)
                            .getProperties();
                result = RenewalWorkerProperties.RESPONSE_RESULT_OK.equals(
                        response.getProperty(
                            RenewalWorkerProperties.RESPONSE_RESULT));
            } else {
                LOG.error("Worker[" + workerId
                        +"]: Unexpected response type from " + renewalWorkerId);
                result = false;
            }
        }
        return result;
    }
}
