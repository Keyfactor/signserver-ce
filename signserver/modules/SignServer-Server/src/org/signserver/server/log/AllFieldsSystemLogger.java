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

import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.signserver.server.log.ISystemLogger;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.SystemLoggerException;

/**
 * An IWorkerLogger that renders the log line by appending all the log fields
 * and separating them with semicolons.
 * @author Markus Kilås
 * @version $Id$
 */
public class AllFieldsSystemLogger implements ISystemLogger {

    /** Logger for this class. */
    private static final Logger ACCOUNTLOG =
            Logger.getLogger(ISystemLogger.class);

    public void init(final Properties props) {
        // No configuration for this Logger
    }

    /**
     * Render the log line by putting together all the fields and separating
     * them with semi-colon.
     * @param fields The fields to include.
     * @throws SystemLoggerException
     */
    @Override
    public void log(SignServerEventTypes eventType, SignServerModuleTypes module, String customId, Map<String, String> additionalDetails) throws SystemLoggerException {
        final StringBuilder str = new StringBuilder();
        str.append("EVENT: ").append(eventType.name()).append("; ")
                .append("MODULE: ").append(module.name()).append("; ")
                .append("CUSTOM_ID: ").append(customId).append("; ");
        
        for (Map.Entry<String, String> entry : additionalDetails.entrySet()) {
            str.append(entry.getKey());
            str.append(": ");
            str.append(entry.getValue());
            str.append("; ");
        }
        
        // Last thing: add time for logging
        // TODO: Should probobly be replaced with the time instead
        str.append(IWorkerLogger.LOG_REPLY_TIME);
        str.append(":");
        str.append(String.valueOf(System.currentTimeMillis()));

        // Do log
        ACCOUNTLOG.info(str.toString());
    }
}
