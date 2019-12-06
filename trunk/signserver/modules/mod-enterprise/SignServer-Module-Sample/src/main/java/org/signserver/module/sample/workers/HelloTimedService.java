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
package org.signserver.module.sample.workers;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.ServiceContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.IServices;
import org.signserver.server.ServiceExecutionFailedException;
import org.signserver.server.WorkerContext;
import org.signserver.server.timedservices.BaseTimedService;

/**
 * Sample worker demonstrating a timed service by printing a greeting to the
 * log.
 * <p>
 * The worker has two worker properties:
 * </p>
 * <ul>
 *    <li>
 *        <b>GREETING</b> = The greeting phrase to use, 
 *        ie "Hello at " (Required)
 *    </li>
 *    <li><b>SUFFIX</b> = Characters to add at end of greeting
 *        (Optional, default: "!")
 *    </li>
 * </ul>
 * <p>
 * The worker prints the greeting to the Log4j log:<br>
 * GREETING DATE SUFFIX, ie "Hello at Mon Mar 16 16:28:31 CET 2015!"
 * </p>
 * @author Markus Kilås
 * @version $Id$
 */
public class HelloTimedService extends BaseTimedService {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(HelloWorker.class);

    // Worker properties
    public static final String PROPERTY_GREETING = "GREETING";
    public static final String PROPERTY_SUFFIX = "SUFFIX";

    // Default values
    private static final String DEFAULT_SUFFIX = "!";

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    private String greeting;
    private String suffix;

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        // Required property GREETING
        greeting = config.getProperty(PROPERTY_GREETING);
        if (greeting == null || greeting.trim().isEmpty()) {
            configErrors.add("Missing required property: " + PROPERTY_GREETING);
        }
        
        // Optional property SUFFIX
        suffix = config.getProperty(PROPERTY_SUFFIX, DEFAULT_SUFFIX);
    }

    @Override
    public void work(final ServiceContext context)
            throws ServiceExecutionFailedException {
        if (configErrors.isEmpty()) {
            // Do the work
            LOG.info(greeting + new Date() + suffix);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Service is misconfigured");
            }
        }
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
