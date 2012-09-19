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
package org.signserver.test.random.impl;

import org.apache.log4j.Logger;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IWorkerSession;

/**
 * Reads a property value, increments it, and writes it back.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class IncrementProperty implements Runnable {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(IncrementProperty.class);
    
    private final int signerId;
    private final String propertyName;
    private final IWorkerSession.IRemote workerSession;

    public IncrementProperty(int signerId, String propertyName, IWorkerSession.IRemote workerSession) {
        this.signerId = signerId;
        this.propertyName = propertyName;
        this.workerSession = workerSession;
    }
    
    @Override
    public void run() {
        LOG.debug(">run");
        WorkerConfig currentWorkerConfig = workerSession.getCurrentWorkerConfig(signerId);
        String stringValue = currentWorkerConfig.getProperty(propertyName, "0");
        long value = Long.parseLong(stringValue);
        LOG.info("Old WORKER" + signerId + "." + propertyName + "=" + value);
        workerSession.setWorkerProperty(signerId, propertyName, String.valueOf(value + 1));
        workerSession.reloadConfiguration(signerId);
        LOG.debug("<run");
    }
    
}
