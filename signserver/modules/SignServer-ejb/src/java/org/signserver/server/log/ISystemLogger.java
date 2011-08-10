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

/**
 * Logger for system events. System events are all events that are not directly
 * associated with the processing performed by a worker.
 *
 * @see IWorkerLogger
 * @author Markus Kilås
 * @version $Id$
 */
public interface ISystemLogger {

    // Log constants
    String LOG_STARTUP_TIME = "STARTUP_TIME";
    String LOG_REPLY_TIME = "REPLY_TIME";
    String LOG_CLASS_NAME = "CLASS_NAME";
    String LOG_WORKER_ID = "WORKER_ID";
    String LOG_EVENT = "EVENT";
    String LOG_VERSION = "VERSION";

    /**
     * Method called after creation of instance.
     * @param props the signers properties
     */
    void init(Properties props);

    void log(Map<String,String> entries) throws SystemLoggerException;
}
