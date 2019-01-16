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

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;

/**
 * Worker logger implementation using CESeCore's SecurityEventsLogger.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class SecurityEventsWorkerLogger extends BaseWorkerLogger implements IWorkerLogger {
    /** Logger for this class. */
    private final Logger LOG = Logger.getLogger(SecurityEventsWorkerLogger.class);

    /** configuration keys for selecting included/excluded fields. */
    private static final String INCLUDE_FIELDS = "LOGINCLUDEFIELDS";
    private static final String EXCLUDE_FIELDS = "LOGEXCLUDEFIELDS";

    private Set<String> includedFields;
    private Set<String> excludedFields;

    @Override
    public void init(final int workerId, final WorkerConfig config, final SignServerContext context) {
        final String include = config.getProperty(INCLUDE_FIELDS);
        final String exclude = config.getProperty(EXCLUDE_FIELDS);

        if (include != null && exclude != null) {
            addFatalError("Can only set one of " + INCLUDE_FIELDS + " and " + EXCLUDE_FIELDS);
        }

        if (include != null) {
            final String[] includes = include.split(",");
            includedFields = new HashSet<>();

            for (final String field : includes) {
                includedFields.add(field.trim());
            }
        }

        if (exclude != null) {
            final String[] excludes = exclude.split(",");
            excludedFields = new HashSet<>();

            for (final String field : excludes) {
                excludedFields.add(field.trim());
            }
        }
    }

    @Override
    public void log(final AdminInfo adminInfo, final Map<String, Object> fields, final RequestContext context) throws WorkerLoggerException {
        final Map<String, Object> details = new LinkedHashMap<>();

        if (hasErrors()) {
            throw new WorkerLoggerException("Can only set one of " + INCLUDE_FIELDS + " and " + EXCLUDE_FIELDS);
        }
        final SecurityEventsLoggerSessionLocal logger = context.getServices().get(SecurityEventsLoggerSessionLocal.class);
        if (logger == null) {
            throw new WorkerLoggerException("Logger unavailable: " + SecurityEventsLoggerSessionLocal.class.getName());
        }

        // strip out the worker ID from the additionalDetails field (it's put customID)
        for (String key : fields.keySet()) {
            if (!IWorkerLogger.LOG_WORKER_ID.equals(key) &&
                (includedFields == null || includedFields.contains(key)) &&
                (excludedFields == null || !excludedFields.contains(key))) {
                details.put(key, String.valueOf(fields.get(key)));
            }
        }
        final String serNo = adminInfo.getCertSerialNumber() != null ? adminInfo.getCertSerialNumber().toString(16) : null;
        final String sucess = String.valueOf(fields.get(IWorkerLogger.LOG_PROCESS_SUCCESS));
        logger.log(SignServerEventTypes.PROCESS,
                Boolean.toString(true).equals(sucess) ? EventStatus.SUCCESS : EventStatus.FAILURE,
                SignServerModuleTypes.WORKER, SignServerServiceTypes.SIGNSERVER, adminInfo.getSubjectDN(),
                adminInfo.getIssuerDN(), serNo, String.valueOf(fields.get(IWorkerLogger.LOG_WORKER_ID)), details);
    }

}
