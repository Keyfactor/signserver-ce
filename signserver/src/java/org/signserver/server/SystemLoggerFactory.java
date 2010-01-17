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
package org.signserver.server;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SystemLoggerFactory {

    private static final Logger LOG =
            Logger.getLogger(SystemLoggerFactory.class);

    private static final SystemLoggerFactory instance =
            new SystemLoggerFactory();

    private Map<String, ISystemLogger> loggers =
            new HashMap<String, ISystemLogger>();

    private ISystemLogger defaultSystemLogger;

    
    private SystemLoggerFactory() {
        defaultSystemLogger = new AllFieldsSystemLogger();
        defaultSystemLogger.init(new Properties());

        ISystemLogger logger1 = new AllFieldsSystemLogger();
        logger1.init(new Properties());
        loggers.put("org.signserver.web.StartServicesServlet", logger1);

        ISystemLogger logger2 = new AllFieldsSystemLogger();
        logger2.init(new Properties());
        loggers.put("org.signserver.ejb.WorkerSessionBean", logger2);

        if (LOG.isDebugEnabled()) {
            LOG.debug("defaultSystemLogger: " + defaultSystemLogger);
        }
    }

    public static SystemLoggerFactory getInstance() {
        return instance;
    }

    public ISystemLogger getLogger(Class<?> clazz) {
        return getLogger(clazz.getName());
    }

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
