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

import java.util.LinkedHashMap;
import java.util.Map;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.signserver.common.CompileTimeSettings;
import org.signserver.server.log.SignServerEventTypes;
import org.signserver.server.log.SignServerModuleTypes;
import org.signserver.server.log.SignServerServiceTypes;
import org.signserver.statusrepo.IStatusRepositorySession;
import org.signserver.statusrepo.common.NoSuchPropertyException;
import org.signserver.statusrepo.common.StatusEntry;
import org.signserver.statusrepo.common.StatusName;

/**
 * Session bean offering an interface towards the status repository.
 *
 * @version $Id$
 * @author Markus Kilås
 */
@Stateless
public class StatusRepositorySessionBean implements
        IStatusRepositorySession.ILocal, IStatusRepositorySession.IRemote {

    /** Logger for this class. */
    private static final Logger LOG =
            Logger.getLogger(StatusRepositorySessionBean.class);
   
    /** The repository instance. */
    private static final StatusRepository repository = StatusRepository.getInstance();

    @EJB
    private SecurityEventsLoggerSessionLocal logSession;
    
    private LogUpdates logUpdates;

    public StatusRepositorySessionBean() {
        String logTypes = CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.STATUSREPOSITORY_LOG);
        if (logTypes == null) {
            logTypes = LogUpdates.ALL.name();
        }
        logUpdates = LogUpdates.valueOf(logTypes);
    }
        
    /**
     * Get a property.
     *
     * @param key Key to get the value for
     * @return The value if existing and not expired, otherwise null
     */
    @Override
    public StatusEntry getValidEntry(String key) throws NoSuchPropertyException {
        try {
            final StatusEntry result;
            final StatusEntry data = repository.get(StatusName.valueOf(key));

            final long time = System.currentTimeMillis();

            if (data != null && LOG.isDebugEnabled()) {
                LOG.debug("data.expire=" + data.getExpirationTime() + ", " + time);
            }

            // First check the expiration and then read the value
            if (data != null && (data.getExpirationTime() == 0  || data.getExpirationTime() > time)) {
                result = data;
            } else {
                result = null;
            }
            return result;
        } catch (IllegalArgumentException ex) {
            throw new NoSuchPropertyException(key);
        }
    }

    /**
     * Set a property without expiration, the value will live until the
     * application is restarted.
     *
     * @param key The key to set the value for
     * @param value The value to set
     */
    @Override
    public void update(final String key, final String value) throws NoSuchPropertyException {
        update(key, value, 0L);
    }

     /**
     * Set a property with a given expiration timestamp.
     *
     * After the expiration the get method will return null.
     *
     * @param key The key to set the value for
     * @param newValue The value to set
     */
    @Override
    public void update(final String key, final String newValue,
            final long expiration) throws NoSuchPropertyException {
        try {
            final long currentTime = System.currentTimeMillis();
            final StatusName name = StatusName.valueOf(key);
            final StatusEntry oldEntry;
            
            synchronized (repository) { // Synchronization only for writes so we can detect changes
                // Get the old value
                oldEntry = repository.get(name);
                // Set the new value
                repository.set(name, new StatusEntry(currentTime, newValue, expiration));
            }
            
            if (shouldLog(logUpdates, oldEntry, newValue)) {
                auditLog(key, newValue, expiration);
            }
        } catch (IllegalArgumentException ex) {
            throw new NoSuchPropertyException(key);
        }
    }
    
    /**
     * @return if the change should be logged or not
     */
    private static boolean shouldLog(final LogUpdates logUpdates, final StatusEntry oldEntry, final String newValue) {
        final boolean result;
        switch (logUpdates) {
            // Log all
            case ALL: {
                result = true;
            } break;
                
            // Only log changes
            case CHANGES: {
                if (oldEntry == null) {
                   // Log change (new entry)
                    result = true;
                } else if (oldEntry.getValue() == null) {
                    if (newValue == null) {
                        // No change as both are null
                        result = false;
                    } else {
                        // Log change as new value is not null
                        result = true;
                    }
                } else if (!oldEntry.getValue().equals(newValue)) {
                    // Log change of existing entry
                    result = true;
                } else {
                    // No change
                    result = false;
                }
            } break;
                
            // No log as LogUpdates.NONE
            default: {
                result = false;
            }
        }
        return result;
    }

    /**
     * @return An unmodifiable map of all properties
     */
    @Override
    public Map<String, StatusEntry> getAllEntries() {
        return repository.getEntries();
    }
    
    private void auditLog(String property, String value, Long expiration) {
        try {
            final Map<String, Object> details = new LinkedHashMap<String, Object>();

            details.put(IStatusRepositorySession.LOG_PROPERTY, property);

            if (value != null) {
                details.put(IStatusRepositorySession.LOG_VALUE, value);
            }
            if (expiration != null) {
                details.put(IStatusRepositorySession.LOG_EXPIRATION, String.valueOf(expiration));
            }

            logSession.log(SignServerEventTypes.SET_STATUS_PROPERTY, EventStatus.SUCCESS, SignServerModuleTypes.STATUS_REPOSITORY,
                    SignServerServiceTypes.SIGNSERVER, "StatusRepositorySessionBean.auditLog", null, null, null, details);
        } catch (AuditRecordStorageException ex) {
            LOG.error("Audit log failure", ex);
            throw new EJBException("Audit log failure", ex);
        }
    }
}
