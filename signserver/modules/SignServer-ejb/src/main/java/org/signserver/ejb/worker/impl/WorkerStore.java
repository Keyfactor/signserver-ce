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
package org.signserver.ejb.worker.impl;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import org.apache.log4j.Logger;
import org.signserver.common.util.PropertiesConstants;
import org.signserver.common.WorkerIdentifier;
import org.signserver.server.IWorker;

/**
 * Holder for loaded workers and workers+components as well as the mapping from
 * worker name to worker ID.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class WorkerStore {
    
    /** Logger for this class. */
    private final Logger LOG = Logger.getLogger(WorkerStore.class);
    
    private final Map<Integer, WorkerWithComponents> workersWithComponents = new HashMap<>();
    private final Map<Integer, IWorker> workersOnly = new HashMap<>();
    private final Map<String, Integer> nameToIdMap = new HashMap<>();
    
    protected WorkerStore() {
        
    }
    
    public IWorker getWorkerOnly(WorkerIdentifier wi) {
        IWorker result = null;
        if (wi.hasId()) {
            result = workersOnly.get(wi.getId());
        } else if (wi.hasName()) {
            final Integer workerId = nameToIdMap.get(wi.getName().toUpperCase(Locale.ENGLISH));
            if (workerId != null) {
                result = workersOnly.get(workerId);
            }
        }
        return result;
    }
    
    public WorkerWithComponents getWorkerWithComponents(WorkerIdentifier wi) {
        WorkerWithComponents result = null;
        if (wi.hasId()) {
            result = workersWithComponents.get(wi.getId());
        } else if (wi.hasName()) {
            final Integer workerId = nameToIdMap.get(wi.getName().toUpperCase(Locale.ENGLISH));
            if (workerId != null) {
                result = workersWithComponents.get(workerId);
            }
        }
        return result;
    }
    
    public Integer getWorkerId(String name) {
        return nameToIdMap.get(name.toUpperCase(Locale.ENGLISH));
    }

    public void putWorkerOnly(int workerId, IWorker worker) {
        workersOnly.put(workerId, worker);
        workersWithComponents.remove(workerId);
        cacheName(workerId, worker);
    }

    public void putWorkerWithComponents(int workerId, WorkerWithComponents workerWithComponents) {
        workersOnly.put(workerId, workerWithComponents.getWorker());
        workersWithComponents.put(workerId, workerWithComponents);
        cacheName(workerId, workerWithComponents.getWorker());
    }
    
    private void cacheName(int workerId, IWorker worker) {
        final String name = getName(worker);
        if (LOG.isTraceEnabled()) {
            LOG.trace("cacheName(" + workerId + "): " + name);
        }
        if (name != null) {
            nameToIdMap.put(name, workerId);
        }
    }
    
    private String getName(int workerId) {
        String result = null;
        WorkerWithComponents w = workersWithComponents.get(workerId);
        if (w != null) {
            IWorker worker = w.getWorker();
            result = getName(worker);
        }
        return result;
    }
    
    private String getName(IWorker worker) {
        String result = null;
        if (worker.getConfig() != null) {
            if (worker.getConfig().getProperty(PropertiesConstants.NAME) != null) {
                result = worker.getConfig().getProperty(PropertiesConstants.NAME).toUpperCase(Locale.ENGLISH);
            }
        }
        return result;
    }

    public void clearAll() {
        workersWithComponents.clear();
        workersOnly.clear();
        nameToIdMap.clear();
    }

    public void clear(WorkerIdentifier id) {
        Integer workerId;
        if (id.hasId()) {
            workerId = id.getId();
        } else {
            workerId = getWorkerId(id.getName());
        }
        if (workerId != null) {
            workersOnly.remove(workerId);
            workersWithComponents.remove(workerId);
            removeEntriesMappingToId(nameToIdMap, workerId);
        }
    }

    public Collection<Integer> keySet() {
        return workersOnly.keySet();
    }

    /**
     * Remove all entries that map to the specified integer value.
     * @param nameToIdMap map to remove entries from
     * @param workerId id to remove mapping for
     */
    private static void removeEntriesMappingToId(Map<String, Integer> nameToIdMap, Integer workerId) {
        final Iterator<Map.Entry<String, Integer>> iterator = nameToIdMap.entrySet().iterator();
        while (iterator.hasNext()) {
            final Entry entry = iterator.next();
            if (workerId.equals(entry.getValue())) {
                iterator.remove();
            }
        }
    }
}
