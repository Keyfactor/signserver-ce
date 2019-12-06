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

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Map;

import org.apache.log4j.Logger;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;

/**
 * An IWorkerLogger that appends log lines to a separate file.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class FileWorkerLogger extends BaseWorkerLogger implements IWorkerLogger {

    private static final String FILE_PATH_PROPERTY_NAME = "LOG_FILE_PATH";
    
    /** Logger for this class. */
    private static final Logger LOG =
            Logger.getLogger(FileWorkerLogger.class);

    private String logFilePath;

    @Override
    public void init(final int workerId, final WorkerConfig config, final SignServerContext context) {
        logFilePath = config.getProperty(FILE_PATH_PROPERTY_NAME);

        if (logFilePath == null) {
            addFatalError("Log file path not specified");
        }
    }

    @Override
    public void log(final AdminInfo adminInfo, final Map<String, Object> fields, final RequestContext context) throws WorkerLoggerException {
        FileOutputStream fos = null;

        try {
            fos = new FileOutputStream(logFilePath);
        } catch (IOException e) {
            throw new WorkerLoggerException("Could not open log file", e);
        }

        final StringBuilder str = new StringBuilder();

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

        try {
            fos.write(str.toString().getBytes());
        } catch (IOException e) {
            LOG.error("Could not write to log file");
            throw new WorkerLoggerException("Could not write to log file");
        } finally {
            try {
                fos.close();
            } catch (IOException dummy) {} //NOPMD
        }
    }
}
