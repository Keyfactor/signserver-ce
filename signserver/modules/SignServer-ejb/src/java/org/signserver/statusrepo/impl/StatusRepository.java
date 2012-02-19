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
package org.signserver.statusrepo.impl;

import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;
import org.apache.log4j.Logger;
import org.signserver.statusrepo.common.NoSuchPropertyException;
import org.signserver.statusrepo.common.StatusEntry;
import org.signserver.statusrepo.common.StatusName;

/**
 * Singleton holding non-persistent status information.
 * 
 * All properties should be initialized in the constructor.
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
    private Map<StatusName, EntryHolder> datas = new EnumMap<StatusName, EntryHolder>(StatusName.class);

    /** Creates the instance of this class. */
    private StatusRepository() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Created new instance: " + this.toString());
        }
        
        // Pre-populate with all keys as adding keys on the fly is not thread-safe
        for (StatusName name : StatusName.values()) {
            datas.put(name, new EntryHolder());
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
    public StatusEntry get(final StatusName key) throws NoSuchPropertyException {
        final StatusEntry result;
        final EntryHolder holder = datas.get(key);
        if (holder == null) {
            throw new NoSuchPropertyException(key.name());
        } else {
            result = holder.getEntry();
        }
        return result;
    }

    /**
     * @param key Key to store the data on
     * @param entry The data to store
     */
    public void set(final StatusName key, final StatusEntry entry) throws NoSuchPropertyException {
        final EntryHolder holder = datas.get(key);
        if (holder == null) {
            throw new NoSuchPropertyException(key.name());
        }
        holder.setEntry(entry);
    }

    /**
     * @return An read-only view of the underlying properties
     */
    public Map<String, StatusEntry> getEntries() {
        Map<String, StatusEntry> result = new HashMap<String, StatusEntry>();
        for (Map.Entry<StatusName, EntryHolder> entry : datas.entrySet()) {
            result.put(entry.getKey().name(), entry.getValue().getEntry());
        }
        return result;
    }

    private static class EntryHolder {
        private volatile StatusEntry entry;

        public StatusEntry getEntry() {
            return entry;
        }

        public void setEntry(StatusEntry entry) {
            this.entry = entry;
        }
        
    }
}
