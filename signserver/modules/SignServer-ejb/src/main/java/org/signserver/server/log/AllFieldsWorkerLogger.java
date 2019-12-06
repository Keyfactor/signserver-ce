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

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;

/**
 * An IWorkerLogger that renders the log line by appending all the log fields
 * and separating them with semicolons.
 * @author Markus Kilås
 * @version $Id$
 */
public class AllFieldsWorkerLogger extends BaseWorkerLogger implements IWorkerLogger {

    /** Logger for this class. */
    private static final Logger ACCOUNTLOG =
            Logger.getLogger(IWorkerLogger.class);
    
    private static final String DEFAULT_LOGLEVEL = "INFO";

    private Level logLevel;
    
    @Override
    public void init(final int workerId, final WorkerConfig config, final SignServerContext context) {
        this.logLevel = Level.toLevel(config.getProperty("LOGLEVEL_DEFAULT",
        		DEFAULT_LOGLEVEL), Level.INFO);
    }

    /**
     * Render the log line by putting together all the fields and separating
     * them with semi-colon.
     * @param adminInfo unused
     * @param fields The fields to include.
     * @param context unused
     * @throws WorkerLoggerException
     */
    @Override
    public void log(final AdminInfo adminInfo, final Map<String, Object> fields, final RequestContext context)
            throws WorkerLoggerException {
        final StringBuilder str = new StringBuilder();
        str.append("AllVariablesLogger; ");
        for (Map.Entry<String, Object> entry : fields.entrySet()) {
            str.append(entry.getKey());
            str.append(": ");
            str.append(String.valueOf(entry.getValue()));
            str.append("; ");
        }
        
        // Last thing: add time for logging
        str.append(IWorkerLogger.LOG_REPLY_TIME);
        str.append(":");
        str.append(String.valueOf(System.currentTimeMillis()));
        
        // Do log
        ACCOUNTLOG.log(this.logLevel, str.toString());
    }

}
