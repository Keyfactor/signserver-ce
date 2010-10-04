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
package org.signserver.ejb;

import java.util.HashMap;
import java.util.Map;
import javax.ejb.EJBException;
import org.signserver.common.StatusRepositoryData;
import javax.ejb.Stateless;
import org.apache.log4j.Logger;
import org.signserver.ejb.interfaces.IStatusRepositorySession;
import org.signserver.server.log.ISystemLogger;
import org.signserver.server.log.SystemLoggerException;
import org.signserver.server.log.SystemLoggerFactory;

/**
 * Session bean offering an interface towards the status repository.
 *
 * @author Markus Kil�s
 * @version $Id$
 */
@Stateless
public class StatusRepositorySessionBean implements
        IStatusRepositorySession.ILocal, IStatusRepositorySession.IRemote {

    /** Logger for this class. */
    private static final Logger LOG =
            Logger.getLogger(StatusRepositorySessionBean.class);

    /** Audit logger. */
    private static final ISystemLogger AUDITLOG = SystemLoggerFactory
            .getInstance().getLogger(StatusRepository.class);

    /** The repository instance. */
    private final transient StatusRepository repository;

    
    /**
     * Constructs this class.
     */
    public StatusRepositorySessionBean() {
        repository = StatusRepository.getInstance();
    }

    /**
     * Get a property.
     *
     * @param key Key to get the value for
     * @return The value if existing and not expired, otherwise null
     */
    public String getProperty(final String key) {
        final StatusRepositoryData data = repository.get(key);
        final String property;

        final long time = System.currentTimeMillis();

        if (data != null && LOG.isDebugEnabled()) {
            LOG.debug("data.expire=" + data.getExpiration() + ", " + time);
        }

        if (data != null && (data.getExpiration() == 0
                || data.getExpiration() > time)) {
            property = data.getValue();
        } else {
            property = null;
        }
        return property;
    }

    /**
     * Set a property without expiration, the value will live until the
     * application is restarted.
     *
     * @param key The key to set the value for
     * @param value The value to set
     */
    public void setProperty(final String key, final String value) {
        setProperty(key, value, 0L);
    }

     /**
     * Set a property with a given expiration timestamp.
     *
     * After the expiration the get method will return null.
     *
     * @param key The key to set the value for
     * @param value The value to set
     */
    public void setProperty(final String key, final String value,
            final long expiration) {
        repository.put(key, new StatusRepositoryData(value, expiration));
        auditLog("setProperty", key, value, expiration);
    }

    /**
     * Removes a property.
     *
     * @param key The property to remove.
     */
    public void removeProperty(final String key) {
        repository.remove(key);
        auditLog("removeProperty", key, null, null);
    }

    /**
     * @return An unmodifiable map of all properties
     */
    public Map<String, StatusRepositoryData> getProperties() {
        return repository.getProperties();
    }

    private static void auditLog(String operation, String property, 
            String value,
            Long expiration) {
        try {

            final Map<String, String> logMap = new HashMap<String, String>();

            logMap.put(ISystemLogger.LOG_CLASS_NAME,
                    StatusRepositorySessionBean.class.getSimpleName());
            logMap.put(IStatusRepositorySession.LOG_OPERATION,
                    operation);
            logMap.put(IStatusRepositorySession.LOG_PROPERTY,
                    property);
            if (value != null) {
                logMap.put(IStatusRepositorySession.LOG_VALUE,
                        value);
            }
            if (expiration != null) {
                logMap.put(IStatusRepositorySession.LOG_EXPIRATION,
                    value);
            }

            AUDITLOG.log(logMap);
        } catch (SystemLoggerException ex) {
            LOG.error("Audit log failure", ex);
            throw new EJBException("Audit log failure", ex);
        }
    }
}
