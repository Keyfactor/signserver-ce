/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.ejb.worker.impl;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import org.signserver.common.util.PropertiesConstants;
import org.signserver.common.WorkerIdentifier;
import org.signserver.server.IWorker;

/**
 *
 * @author user
 */
public class WorkerStore {
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
            final Integer workerId = nameToIdMap.get(wi.getName().toUpperCase());
            if (workerId != null) {
                result = workersOnly.get(workerId);
            }
        }
        return result;
    }
    
    /*public IWorker getWorkerOnly(int workerId) {
        return workersOnly.get(workerId);
    }
    
    public IWorker getWorkerOnly(String workerName) {
        IWorker result = null;
        final Integer workerId = nameToIdMap.get(workerName);
        if (workerId != null) {
            result = workersOnly.get(workerId);
        }
        return result;
    }*/
    
    public WorkerWithComponents getWorkerWithComponents(WorkerIdentifier wi) {
        WorkerWithComponents result = null;
        if (wi.hasId()) {
            result = workersWithComponents.get(wi.getId());
        } else if (wi.hasName()) {
            final Integer workerId = nameToIdMap.get(wi.getName().toUpperCase());
            if (workerId != null) {
                result = workersWithComponents.get(workerId);
            }
        }
        return result;
    }
    
    /*public WorkerWithComponents getWorkerWithComponents(int workerId) {
        return workersWithComponents.get(workerId);
    }
    
    public WorkerWithComponents getWorkerWithComponents(String workerName) {
        WorkerWithComponents result = null;
        final Integer workerId = nameToIdMap.get(workerName);
        if (workerId != null) {
            result = workersWithComponents.get(workerId);
        }
        return result;
    }*/
    
    public Integer getWorkerId(String name) {
        return nameToIdMap.get(name.toUpperCase());
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
        final String name = getName(workerId);
        if (name != null) {
            nameToIdMap.put(name, workerId);
        }
    }
    
    private String getName(int workerId) {
        String result = null;
        WorkerWithComponents w = workersWithComponents.get(workerId);
        if (w != null) {
            IWorker worker = w.getWorker();
            if (worker.getConfig() != null) {
                if (worker.getConfig().getProperty(PropertiesConstants.NAME) != null) {
                    result = worker.getConfig().getProperty(PropertiesConstants.NAME).toUpperCase();
                }
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
            nameToIdMap.remove(getName(workerId));
        }
    }

    public Collection<Integer> keySet() {
        return workersOnly.keySet();
    }
}
