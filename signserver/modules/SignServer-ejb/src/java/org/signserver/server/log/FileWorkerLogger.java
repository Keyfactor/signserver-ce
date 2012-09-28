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

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;

/**
 * An IWorkerLogger that appends log lines to a separate file.
 * 
 * @author marcus
 * @version $Id$
 */

public class FileWorkerLogger implements IWorkerLogger {

    private static final String FILE_PATH_PROPERTY_NAME = "LOG_FILE_PATH";
    
    /** Logger for this class. */
    private static final Logger LOG =
            Logger.getLogger(FileWorkerLogger.class);

    private FileOutputStream logFileStream;
    
    public void init(final Properties props) {
    	final String logFilePath = props.getProperty(FILE_PATH_PROPERTY_NAME);
    	
    	if (logFilePath == null) {
    		LOG.error("Log file path not specified");
    	}
    	
    	try {
			logFileStream = new FileOutputStream(logFilePath);
		} catch (FileNotFoundException e) {
			LOG.error("Could not initialize log file");
		}
    }

	@Override
	public void log(Map<String, String> fields) throws WorkerLoggerException {
		if (logFileStream == null) {
			LOG.error("Log file was not initialized");
			throw new WorkerLoggerException("Log file was not initialized");
		}
		
        final StringBuilder str = new StringBuilder();

        for (Map.Entry<String, String> entry : fields.entrySet()) {
            str.append(entry.getKey());
            str.append(": ");
            str.append(entry.getValue());
            str.append("; ");
        }
        
        // Last thing: add time for logging
        str.append(IWorkerLogger.LOG_REPLY_TIME);
        str.append(":");
        str.append(String.valueOf(System.currentTimeMillis()));
        
        try {
			logFileStream.write(str.toString().getBytes());
		} catch (IOException e) {
			LOG.error("Could not write to log file");
			throw new WorkerLoggerException("Could not write to log file");
		}
		
	}
    
    
	
}
