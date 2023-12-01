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
package org.signserver.cli;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.impl.Log4jContextFactory;
import org.apache.logging.log4j.core.util.DefaultShutdownCallbackRegistry;
import org.apache.logging.log4j.spi.LoggerContextFactory;

/**
 * Class containing helper method for log4j.
 *
 * @author Nima Saboonchi
 */
public class Log4jHelper {

    /**
     * Helper method for disabling the shutdown hook in log4j.
     */
    public static void disableShutdownHook(){
        final LoggerContextFactory loggerContextFactory = LogManager.getFactory();
        if (loggerContextFactory instanceof Log4jContextFactory) {
            Log4jContextFactory contextFactory = (Log4jContextFactory) loggerContextFactory;
            ((DefaultShutdownCallbackRegistry) contextFactory.getShutdownCallbackRegistry()).stop();
        }
    }
}
