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

import org.signserver.server.log.ISystemLogger;
import org.signserver.server.log.AllFieldsSystemLogger;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;

/**
 *
 * @author Markus Kil�s
 * @version $Id$
 */
public class SystemLoggerFactory {

    /** Logger for this class. */
    private static final Logger LOG =
            Logger.getLogger(SystemLoggerFactory.class);

    /** The Singleton instance. */
    private static final SystemLoggerFactory instance =
            new SystemLoggerFactory();

    /** Map of system loggers. */
    private Map<String, ISystemLogger> loggers =
            new HashMap<String, ISystemLogger>();

    /** The default system logger. */
    private ISystemLogger defaultSystemLogger;

    /**
     * Creates an instance of SystemLoggerFactory.
     */
    private SystemLoggerFactory() {
        defaultSystemLogger = new AllFieldsSystemLogger();
        defaultSystemLogger.init(new Properties());

        // TODO: Load loggers here
//        ISystemLogger logger1 = new AllFieldsSystemLogger();
//        logger1.init(new Properties());
//        loggers.put("org.signserver.web.StartServicesServlet", logger1);
//
//        ISystemLogger logger2 = new AllFieldsSystemLogger();
//        logger2.init(new Properties());
//        loggers.put("org.signserver.ejb.WorkerSessionBean", logger2);

        if (LOG.isDebugEnabled()) {
            LOG.debug("defaultSystemLogger: " + defaultSystemLogger);
        }
    }

    /**
     * @return The SystemLoggerFactory instance.
     */
    public static SystemLoggerFactory getInstance() {
        return instance;
    }

    /**
     * Get the logger for the given class.
     * @param clazz Class to get logger for.
     * @return The configured logger.
     */
    public ISystemLogger getLogger(Class<?> clazz) {
        return getLogger(clazz.getName());
    }

    /**
     * Get the logger for the given class name.
     * @param fullClassName Class name to get logger for.
     * @return The configured logger.
     */
    public ISystemLogger getLogger(String fullClassName) {
        ISystemLogger logger = loggers.get(fullClassName);
        if (logger == null) {
            logger = defaultSystemLogger;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("getLogger(" + fullClassName + ") returns "
                    + logger.getClass().getName());
        }
        return logger;
    }

}
