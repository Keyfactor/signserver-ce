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

import java.util.Map;
import org.signserver.common.StatusRepositoryData;
import javax.ejb.Stateless;
import org.apache.log4j.Logger;
import org.signserver.ejb.interfaces.IStatusRepositorySession;

/**
 * Session bean offering an interface towards the status repository.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@Stateless
public class StatusRepositorySessionBean implements
        IStatusRepositorySession.ILocal, IStatusRepositorySession.IRemote {

    /** Logger for this class. */
    private static final Logger LOG =
            Logger.getLogger(StatusRepositorySessionBean.class);

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
    public final String getProperty(final String key) {
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
    public final void setProperty(final String key, final String value) {
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
    public final void setProperty(final String key, final String value,
            final long expiration) {
        repository.put(key, new StatusRepositoryData(value, expiration));
    }

    /**
     * Removes a property.
     *
     * @param key The property to remove.
     */
    public final void removeProperty(final String key) {
        repository.remove(key);
    }

    /**
     * @return An unmodifiable map of all properties
     */
    public final Map<String, StatusRepositoryData> getProperties() {
        return repository.getProperties();
    }

}
