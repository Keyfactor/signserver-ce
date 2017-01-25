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
 * Skeleton timed service...
 * log.
 * <p>
 * The worker has the following worker properties:
 * </p>
 * <ul>
 *    <li>
 *        <b>PROPERTY_NAME...</b> = Description...
 *        (Optional/Required, default: ...)
 *    </li>
 * </ul>
 * @author ...
 * @version $Id$
 */
public class SkeletonTimedService extends BaseTimedService {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SkeletonTimedService.class);

    // Worker properties
    //...

    // Default values
    //...

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    //...

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        // Read properties
        //...
    }

    @Override
    public void work(final ServiceContext context)
            throws ServiceExecutionFailedException {
        if (configErrors.isEmpty()) {
            // Do the work
            //...
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
