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
package org.signserver.server.log;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import org.cesecore.audit.audit.SecurityEventsAuditorSessionLocal;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;

/**
 * Worker logger implementation using CESeCore's SecurityEventsLogger
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */

public class SecurityEventsWorkerLogger implements IWorkerLogger {

    private SecurityEventsLoggerSessionLocal logger;
    
    @Override
    public void init(Properties props) {
        // TODO: add the possibility to filter the fields logged
    }

    @Override
    public void log(Map<String, String> fields) throws WorkerLoggerException {
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        
        // strip out the worker ID from the additionalDetails field (it's put customID)
        for (String key : fields.keySet()) {
            if (!IWorkerLogger.LOG_WORKER_ID.equals(key)) {
                details.put(key, fields.get(key));
            }
        }
        
        logger.log(SignServerEventTypes.PROCESS, EventStatus.SUCCESS, SignServerModuleTypes.SERVICE, SignServerServiceTypes.SIGNSERVER,
                "SecurityEventsWorkerLogger.log", fields.get(IWorkerLogger.LOG_WORKER_ID), null, null, details);
    }

    @Override
    public void setEjbs(Map<Class<?>, ?> ejbs) {
        logger = (SecurityEventsLoggerSessionLocal) ejbs.get(SecurityEventsLoggerSessionLocal.class);
    }

}
