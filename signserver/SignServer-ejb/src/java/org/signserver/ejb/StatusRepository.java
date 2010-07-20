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

import org.signserver.common.StatusRepositoryData;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.apache.log4j.Logger;

/**
 * Singleton holding non-persistant status information.
 *
 * @author Markus Kilås
 * @version $Id$
 */
final class StatusRepository {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(StatusRepository.class);

    /** The instance. */
    private static StatusRepository instance = new StatusRepository();

    /** Map of the data. */
    private final transient Map<String, StatusRepositoryData> datas =
            new HashMap<String, StatusRepositoryData>();

    /** Creates the instance of this class. */
    private StatusRepository() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Created new instance: " + this.toString());
        }
    }

    /**
     * @return The instance of this class
     */
    public static StatusRepository getInstance() {
        if (LOG.isDebugEnabled()) {
            LOG.info("Returning instance: " + instance);
        }
        return instance;
    }

    /**
     * @param key The key to get value for
     * @return The value associated with the given key
     */
    public StatusRepositoryData get(final String key) {
        return datas.get(key);
    }

    /**
     * @param key Key to store the data on
     * @param data The data to store
     */
    public void put(final String key, final StatusRepositoryData data) {
        datas.put(key, data);
    }

    /**
     * @param key The key for which the data should be removed
     * @return The old data (can be null)
     */
    public StatusRepositoryData remove(final String key) {
        return datas.remove(key);
    }

    /**
     * @return An read-only view of the underlaying properties
     */
    public Map<String, StatusRepositoryData> getProperties() {
        return Collections.unmodifiableMap(datas);
    }

}
