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
package org.signserver.server.config.entities;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.log4j.Logger;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.WorkerType;

/**
 * In memory indexing of the WorkerConfigData columns except the signer
 * configuration.
 *
 * Makes it efficient to also query by name or type.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class FileBasedWorkerConfigDataIndex {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(FileBasedWorkerConfigDataIndex.class);

    private final Map<Integer, Entry> idToEntry;
    private final Map<String, Entry> nameToEntry;
    private final Map<Integer, Set<Integer>> typeToSetOfIDs;

    public FileBasedWorkerConfigDataIndex(int initialSize) {
        idToEntry = new HashMap<>(initialSize + 10);
        nameToEntry = new HashMap<>(initialSize + 10);
        typeToSetOfIDs = new HashMap<>(WorkerType.values().length + 10);
    }
    
    private Entry getEntry(int id) throws NoSuchWorkerException {
        final Entry result = idToEntry.get(id);
        if (result == null) {
            throw new NoSuchWorkerException(String.valueOf(id));
        }
        return result;
    }
    
    private Entry getEntry(String name) throws NoSuchWorkerException {
        final Entry result = nameToEntry.get(name);
        if (result == null) {
            throw new NoSuchWorkerException(name);
        }
        return result;
    }
    
    public String getName(int workerId) throws NoSuchWorkerException {
        return getEntry(workerId).getName();
    }

    public Integer getType(int workerId) throws NoSuchWorkerException {
        return getEntry(workerId).getType();
    }
    
    public int getWorkerId(String workerName) throws NoSuchWorkerException {
        return getEntry(workerName).getId();
    }
    
    public boolean isExistingName(String workerName) {
        return nameToEntry.containsKey(workerName);
    }
    
    public boolean isExistingId(int workerId) {
        return idToEntry.containsKey(workerId);
    }

    public List<Integer> findAllWorkerIds() {
        return new ArrayList<>(idToEntry.keySet());
    }
    
    public List<String> findAllWorkerNames() {
        return new ArrayList<>(nameToEntry.keySet());
    }

    public List<Integer> findAllWorkerIds(int workerType) {
        List<Integer> results;
        Set<Integer> workersOfType = typeToSetOfIDs.get(workerType);
        if (workersOfType == null) {
            results = Collections.emptyList();
        } else {
            results = new ArrayList<>(workersOfType);
        }
        return results;
    }

    /**
     * Update all indices with the new data.
     *
     * @param workerId of worker
     * @param newName for the worker
     * @param newType for the worker
     */
    public void update(int workerId, String newName, Integer newType) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("update(" + workerId + ", " + newName + ", " + newType + ")");
        }
        Entry entry = idToEntry.get(workerId);
        if (entry == null) {
            if (isExistingName(newName)) {
                LOG.warn("Duplicated name: \"" + newName + "\"");
            }
            // New entry
            entry = new Entry(workerId);
            entry.setName(newName);
            entry.setType(newType);
            idToEntry.put(workerId, entry);
            nameToEntry.put(newName, entry);
        } else {
            // Existing entry so rename
            String oldName = entry.getName();
            if (!oldName.equals(newName)) {
                if (isExistingName(newName)) {
                    LOG.warn("Duplicated name: \"" + newName + "\"");
                }
            }
            entry.setName(newName);
            
            // Existing entry so change type
            Integer oldType = entry.getType();
            if (oldType != null) {
                Set<Integer> workersOfOldType = typeToSetOfIDs.get(oldType);
                if (workersOfOldType != null) {
                    workersOfOldType.remove(workerId);
                }
            }
            
            entry.setType(newType);
            nameToEntry.remove(oldName);
            nameToEntry.put(newName, entry);
        }
        
        // Put type
        Set<Integer> workersOfType = typeToSetOfIDs.get(newType);
        if (workersOfType == null) {
            workersOfType = new HashSet<>(10);
            typeToSetOfIDs.put(newType, workersOfType);
        }
        workersOfType.add(workerId);
    }
    
    /**
     * Removes a worker entry from all 3 indices.
     * @param workerId to remove
     */
    public void remove(int workerId) {
        Entry entry = idToEntry.remove(workerId);
        if (entry != null) { // Quietly remove
            nameToEntry.remove(entry.getName());
            Set<Integer> workersOfOldType = typeToSetOfIDs.get(entry.getType());
            if (workersOfOldType != null) {
                workersOfOldType.remove(workerId);
            }
        }
    }

    /**
     * Holder for an entry.
     */
    private static class Entry {
        private final int id;
        private String name;
        private Integer type;

        public Entry(int id) {
            this.id = id;
        }

        public int getId() {
            return id;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public Integer getType() {
            return type;
        }

        public void setType(Integer type) {
            this.type = type;
        }

        @Override
        public String toString() {
            return "Entry{" + "id=" + id + ", name=" + name + ", type=" + type + '}';
        }
    }
}
