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
package org.signserver.common;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.signserver.server.IServices;

/**
 * Object containing extra information about a service.
 *
 * @version $Id$
 */
public class ServiceContext implements Serializable {

    private static final long serialVersionUID = 1L;
    
    /**
     * The worker ID (Integer).
     */
    public static final String WORKER_ID = "WORKER_ID";
    public static final String LOGMAP = "LOGMAP";
    
    private final HashMap<String, Object> context = new HashMap<>();
    
    private final transient IServices services;
    
    public ServiceContext(final IServices services) {
        this.services = services;
    }

    /**
     * Retrieves specified field from the context, this could be a custom value or
     * one of the specified constants.
     * 
     * @param field Field to get value of
     * @return The value of the field
     */
    public Object get(String field) {
        return context.get(field);
    }

    /**
     * Sets specified field from the context, this could be a custom value or
     * one of the specified constants.
     * 
     * @param field The field to update the value of
     * @param data The value to set
     */
    public void put(String field, Object data) {
        context.put(field, data);
    }

    /**
     * Removes specified field from the context, this could be a custom value or
     * one of the specified constants.
     * 
     * @param field The field to remove
     */
    public void remove(String field) {
        context.remove(field);
    }

    public Map<String, Object> asUnmodifiableMap() {
        return Collections.unmodifiableMap(context);
    }

    public IServices getServices() {
        return services;
    }
    
    /**
     * Make a copy of the context with a deep-copied log map to avoid
     * passing on a reference for dispatcher workers.
     * 
     * @return A new request context 
     */
    public ServiceContext copyWithNewLogMap() {
        final ServiceContext newContext = new ServiceContext(services);
        
        for (final String key : context.keySet()) {
            final Object value = context.get(key);
            if (LOGMAP.equals(key)) {
                /* take a deep-copy of the log map, the map contains strings,
                   so cloning each entry is enough */
                final HashMap<String, String> logMap =
                        (HashMap<String, String>) value;
                newContext.context.put(LOGMAP, logMap.clone());
            } else {
                newContext.context.put(key, value);
            }
        }
        
        return newContext;
    }
}
