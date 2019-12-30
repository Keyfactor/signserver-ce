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

import java.beans.XMLEncoder;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.signserver.common.FileBasedDatabaseException;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;
import org.signserver.common.util.SecureXMLDecoder;
import org.signserver.server.nodb.FileBasedDatabaseManager;

/**
 * Entity Service class that acts as migration layer for
 * the old Home Interface for the Worker Config Entity Bean
 * 
 * Contains about the same methods as the EJB 2 entity beans home interface.
 *
 * @version $Id$
 */
public class FileBasedWorkerConfigDataService implements IWorkerConfigDataService {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(FileBasedWorkerConfigDataService.class);
    
    private final FileBasedDatabaseManager manager;
    private final File folder;
    private static final String DATA_PREFIX = "signerdata-";
    private static final String SUFFIX = ".dat";
    private static final int EXPECTED_SCHEMA_VERSION = 1;
    private static final int TABLE_VERSION_10 = 10;
    private static final int EXPECTED_TABLE_VERSION = TABLE_VERSION_10;
    private static final String TABLE_VERSION_PROPERTY = "FileBasedWorkerConfigDataService.version";
    
    private static FileBasedWorkerConfigDataIndex index;

    public FileBasedWorkerConfigDataService(FileBasedDatabaseManager manager) {
        this.manager = manager;
        this.folder = manager.getDataFolder();
    }

    private FileBasedWorkerConfigDataIndex getIndex() {
        assert Thread.holdsLock(manager);
        if (index == null) {
            LOG.info("Loading all worker configurations");
            List<Integer> ids = findAllIdsFromDisk();
            LOG.info("Available worker configurations: " + ids.size());
            index = new FileBasedWorkerConfigDataIndex(ids.size());
            for (Integer id : ids) {
                try {
                    WorkerConfig config = getWorkerConfig(id, true);
                    index.update(id, config.getProperty("NAME"), WorkerType.valueOf(config.getProperty("TYPE")).getType());
                } catch (FileBasedDatabaseException ex) {
                    LOG.error("Failed to load worker configuration " + id + ": " + ex.getLocalizedMessage(), ex);
                }
            }
        }
        return index;
    }

    @Override
    public void create(int workerId, String configClassName) {
        if (LOG.isDebugEnabled()) {
            LOG.debug(">create(" + workerId + ", " + configClassName + ")");
        }
        try {
            setWorkerConfig(workerId, (WorkerConfig) this.getClass().getClassLoader().loadClass(configClassName).newInstance());
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | FileBasedDatabaseException e) {
            LOG.error(e);
        }
    }

    private WorkerConfig getWorkerConfig(int workerId)  throws FileBasedDatabaseException {
        return getWorkerConfig(workerId, true);
    }
    
    /**
     * Returns the value object containing the information of the entity bean.
     * This is the method that should be used to worker config correctly
     * correctly.
     *
     */
    @SuppressWarnings("unchecked")
    private WorkerConfig getWorkerConfig(int workerId, boolean fixNameAndType)  throws FileBasedDatabaseException {
        if (LOG.isDebugEnabled()) {
            LOG.debug(">getWorkerConfig(" + workerId + ")");
        }
        WorkerConfig result = null;
        WorkerConfigDataBean wcdb;
        
        try {
            synchronized (manager) {
                wcdb = loadData(workerId);

                if (wcdb != null) {
                    HashMap h;
                    try (SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(wcdb.getSignerConfigData().getBytes(StandardCharsets.UTF_8)))) {
                        h = (HashMap) decoder.readObject();
                    }
                    // Handle Base64 encoded string values
                    HashMap data = new Base64GetHashMap(h);
                    result = new WorkerConfig();
                    try {
                        result.loadData(data);
                        result.upgrade();
                    } catch (Exception e) {
                        LOG.error(e);
                    }
                    
                    if (fixNameAndType) {
                        String name = result.getProperty("NAME");
                        if (name == null || name.trim().isEmpty()) {
                            name = "UnamedWorker" + workerId;
                        }
                        wcdb.setSignerName(name);
                        result.setProperty("NAME", wcdb.getSignerName());
                        
                        String typeValue = result.getProperty("TYPE");
                        if (typeValue == null || typeValue.trim().isEmpty()) {
                            result.setProperty("TYPE", WorkerType.UNKNOWN.name());
                        } else {
                            try {
                                int signerType = WorkerType.valueOf(typeValue).getType();
                                wcdb.setSignerType(signerType);
                            } catch (IllegalArgumentException ex) {
                                LOG.error("Unsupported worker type: " + typeValue + ": " + ex.getLocalizedMessage());
                                result.setProperty("TYPE", WorkerType.UNKNOWN.name());
                            }
                        }
                    }

                    getIndex().update(workerId, wcdb.getSignerName(), wcdb.getSignerType());
                }
            }
        } catch (IOException ex) {
            throw new FileBasedDatabaseException("Could not load from or write data to file based database", ex);
        }

        return result;
    }

    @Override
    public void setWorkerConfig(int workerId, WorkerConfig signconf) throws FileBasedDatabaseException {
        synchronized (manager) {
            // We must base64 encode string for UTF safety
            @SuppressWarnings("unchecked")
            HashMap<Object, Object> a = new Base64PutHashMap();
            final Object o = signconf.saveData();
            if (o instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<Object, Object> data = (Map) o;
                a.putAll(data);
            } else {
                throw new IllegalArgumentException("WorkerConfig should return a Map");
            }

            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (XMLEncoder encoder = new XMLEncoder(baos)) {
                encoder.writeObject(a);
            }

            try {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("WorkerConfig data: \n" + baos.toString(StandardCharsets.UTF_8.name()));
                }
                WorkerConfigDataBean wcdb = new WorkerConfigDataBean();
                wcdb.setSignerId(workerId);
                wcdb.setSignerConfigData(baos.toString(StandardCharsets.UTF_8.name()));
                
                // Update name if needed
                String newName = signconf.getProperty("NAME");
                if (newName == null || newName.trim().isEmpty()) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("No name in config");
                    }
                    newName = "UnamedWorker" + workerId;
                }
                wcdb.setSignerName(newName);

                // Update type if needed
                final String newTypeValue = signconf.getProperty("TYPE");
                WorkerType wt;
                if (newTypeValue == null || newTypeValue.trim().isEmpty()) {
                    wt = WorkerType.UNKNOWN;
                } else {
                    try {
                        wt = WorkerType.valueOf(newTypeValue);
                    } catch (IllegalArgumentException ex) {
                        LOG.error("Unable to set worker type: " + ex.getLocalizedMessage());
                        wt = WorkerType.UNKNOWN;
                    }
                }
                final int newType = wt.getType();
                wcdb.setSignerType(wt.getType());
    
                writeData(workerId, wcdb);
                getIndex().update(workerId, newName, newType);
            } catch (IOException ex) {
                throw new FileBasedDatabaseException("Could not load from or write data to file based database", ex);
            }
        }
    }

    /**
     * Method that removes a worker config
     * 
     * @return true if the removal was successful
     */
    @Override
    public boolean removeWorkerConfig(int workerId) throws FileBasedDatabaseException {
        boolean retval = false;
        
        try {
            synchronized (manager) {
                removeData(workerId);
                getIndex().remove(workerId);
                retval = loadData(workerId) == null;
            }
        } catch (IOException ex) {
            throw new FileBasedDatabaseException("Could not load from or write data to file based database", ex);
        }

        return retval;
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.IWorkerConfigDataService#getWorkerProperties(int)
     */
    @Override
    public WorkerConfig getWorkerProperties(int workerId, boolean create) {
        WorkerConfig workerConfig;
        
        synchronized (manager) {
            workerConfig = getWorkerConfig(workerId);
            if (workerConfig == null && create) { // XXX remove 'create' parameter and instead let caller do the 'new'
                workerConfig = new WorkerConfig();
            }
        }
        
        return workerConfig;
    }

    private WorkerConfigDataBean loadData(final int workerId) throws IOException {
        assert Thread.holdsLock(manager);
        if (LOG.isDebugEnabled()) {
            LOG.debug(">loadData(" + workerId + ")");
        }
        checkSchemaVersion();
        
        WorkerConfigDataBean result;
        final File file = new File(folder, DATA_PREFIX + workerId + SUFFIX);
        
        try {
            final String data = FileUtils.readFileToString(file, StandardCharsets.UTF_8.name());
            result = new WorkerConfigDataBean();
            result.setSignerId(workerId);
            result.setSignerConfigData(data);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Read from file: " + file.getName());
            }
        } catch (FileNotFoundException ex) {
            result = null;
            if (LOG.isDebugEnabled()) {
                LOG.debug("No such file: " + file.getName());
            }
        }
        return result;
    }

    private void writeData(int workerId, WorkerConfigDataBean dataStore) throws IOException {
        assert Thread.holdsLock(manager);
        if (LOG.isDebugEnabled()) {
            LOG.debug(">writeData(" + workerId + ")");
        }
        checkSchemaVersion();
        
        final File file = new File(folder, DATA_PREFIX + workerId + SUFFIX);
        
        OutputStream out = null;
        FileOutputStream fout = null;
        try {
            if (!file.exists()) {
                file.createNewFile();
            }
            fout = new FileOutputStream(file);
            out = new BufferedOutputStream(fout);
            out.write(dataStore.getSignerConfigData().getBytes(StandardCharsets.UTF_8));
            out.flush();
            fout.getFD().sync();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Wrote file: " + file.getName());
            }
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException ignored) {} // NOPMD
            } else if (fout != null) {
                try {
                    fout.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }
    
    private void removeData(int workerId) throws IOException {
        assert Thread.holdsLock(manager);
        if (LOG.isDebugEnabled()) {
            LOG.debug(">removeData(" + workerId + ")");
        }
        final File file = new File(folder, DATA_PREFIX + workerId + SUFFIX);
        if (!file.delete() && file.exists()) {
            LOG.error("File not removed: " + file.getAbsolutePath());
        }
    }
    
    private void checkSchemaVersion() {
        if (manager.getSchemaVersion() != EXPECTED_SCHEMA_VERSION) {
            throw new FileBasedDatabaseException("Unsupported schema version: " + manager.getSchemaVersion());
        }
    }
    
    private List<Integer> findAllIdsFromDisk() {
        synchronized (manager) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(">findAllIdsFromDisk()");
            }
            final LinkedList<Integer> result = new LinkedList<>();

            try (DirectoryStream<Path> stream = Files.newDirectoryStream(folder.toPath(), DATA_PREFIX + "*" + SUFFIX)) {
                Iterator<Path> iterator = stream.iterator();
                while (iterator.hasNext()) {
                    final String fileName = iterator.next().toFile().getName();
                    final String id = fileName.substring(DATA_PREFIX.length(), fileName.length() - SUFFIX.length());
                    result.add(Integer.parseInt(id));
                }
            } catch (IOException ex) {
                LOG.error("Querying all workers failed", ex);
            }
            return result;
        }
    }
    
    @Override
    public List<Integer> findAllIds() {
        synchronized (manager) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(">findAllIds()");
            }
            return getIndex().findAllWorkerIds();
        }
    }
    
    @Override
    public List<Integer> findAllIds(WorkerType workerType) {
        synchronized (manager) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(">findAllIds(" + workerType + ")");
            }
            if (workerType == null) {
                workerType = WorkerType.UNKNOWN;
            }
            return getIndex().findAllWorkerIds(workerType.getType());
        }
    }
    
    @Override
    public void populateNameColumn() {
        // Unused, we populate it on every start anyway
    }

    @Override
    public int findId(String workerName) throws NoSuchWorkerException {
        synchronized (manager) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(">findId(" + workerName + ")");
            }
            
            return getIndex().getWorkerId(workerName);
        }
    }
    
    public void upgrade() {
        synchronized (manager) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(">upgrade()");
            }
            if (manager.getSchemaVersion() != EXPECTED_SCHEMA_VERSION) {
                throw new FileBasedDatabaseException("Unsupported schema version: " + manager.getSchemaVersion());
            }
            final int currentTableVersion = Integer.parseInt(manager.getMetadata().getProperty(TABLE_VERSION_PROPERTY, "0"));
            if (currentTableVersion > EXPECTED_TABLE_VERSION) {
                throw new FileBasedDatabaseException("Unsupported table version: " + manager.getSchemaVersion());
            } else if (currentTableVersion < TABLE_VERSION_10) { // Upgrade for version 10
                // Upgrade for TABLE_VERSION_10: DSS-1121
                // We need to set the signerType to UNKNOWN for all workers
                
                // Upgrade is performed implicitly when the index is built so
                // just do it now
                List<Integer> allIDs = getIndex().findAllWorkerIds();
                LOG.info("Processed worker configs: " + allIDs.size());

                // Store the new version that we have upgraded to
                manager.getMetadata().setProperty(TABLE_VERSION_PROPERTY, String.valueOf(TABLE_VERSION_10));
                manager.storeMetadata();
                LOG.info("Finished table upgrade");
            }
        }
    }

    @Override
    public List<String> findAllNames() {
        synchronized (manager) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(">findAllWorkerNames()");
            }
            return getIndex().findAllWorkerNames();
        }
    }
}
