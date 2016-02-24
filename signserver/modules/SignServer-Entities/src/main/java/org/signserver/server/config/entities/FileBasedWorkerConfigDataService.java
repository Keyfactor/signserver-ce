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

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.*;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.ejb.EJBException;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.signserver.common.FileBasedDatabaseException;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;
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
    private static final String NAME_PREFIX = "signername-";
    private static final String ID_PREFIX = "signerid-";
    private static final String SUFFIX = ".dat";
    private static final String TYPE_FOLDER_PREFIX = "signertypes-";
    private static final String TYPE_PREFIX = "signertype-";
    private static final int EXPECTED_SCHEMA_VERSION = 1;
    private static final int TABLE_VERSION_10 = 10;
    private static final int EXPECTED_TABLE_VERSION = TABLE_VERSION_10;
    private static final String TABLE_VERSION_PROPERTY = "FileBasedWorkerConfigDataService.version";

    public FileBasedWorkerConfigDataService(FileBasedDatabaseManager manager) {
        this.manager = manager;
        this.folder = manager.getDataFolder();
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
    private WorkerConfig getWorkerConfig(int workerId, boolean fixName)  throws FileBasedDatabaseException {
        if (LOG.isDebugEnabled()) {
            LOG.debug(">getWorkerConfig(" + workerId + ")");
        }
        WorkerConfig result = null;
        WorkerConfigDataBean wcdb;
        
        try {
            synchronized (manager) {
                wcdb = loadData(workerId);
                if (wcdb != null) {
                    final File nameFile = getNameFile(workerId);
                    final String name;
                    if (nameFile.exists()) {
                        name = FileUtils.readFileToString(nameFile);
                        wcdb.setSignerName(name);
                    } else if (fixName) {
                        name = "UnamedWorker" + workerId;
                        wcdb.setSignerName(name);
                    }
                    
                    final File typeFile = getTypeFile(workerId);
                    if (typeFile.exists()) {
                        final String type = FileUtils.readFileToString(typeFile);
                        try {
                            wcdb.setSignerType(WorkerType.valueOf(type));
                        } catch (IllegalArgumentException ex) {
                            LOG.error("Unsupported worker type: " + type + ": " + ex.getLocalizedMessage());
                            wcdb.setSignerType(WorkerType.UNKNOWN);
                        }
                    } else {
                        LOG.warn("No type file for worker " + workerId);
                    }
                }
            }

            if (wcdb != null) {
                XMLDecoder decoder;
                try {
                    decoder = new XMLDecoder(new ByteArrayInputStream(wcdb.getSignerConfigData().getBytes("UTF8")));
                } catch (UnsupportedEncodingException e) {
                    throw new EJBException(e);
                }
                HashMap h = (HashMap) decoder.readObject();
                decoder.close();
                // Handle Base64 encoded string values
                HashMap data = new Base64GetHashMap(h);
                result = new WorkerConfig();
                try {
                    result.loadData(data);
                    result.upgrade();
                } catch (Exception e) {
                    LOG.error(e);
                }
                
                if (wcdb.getSignerName() != null) {
                    result.setProperty("NAME", wcdb.getSignerName());
                }
                
                if (wcdb.getSignerType() != null) {
                   result.setProperty("TYPE", wcdb.getSignerType().name());
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
                    LOG.trace("WorkerConfig data: \n" + baos.toString("UTF8"));
                }
                WorkerConfigDataBean wcdb = new WorkerConfigDataBean();
                wcdb.setSignerId(workerId);
                wcdb.setSignerConfigData(baos.toString("UTF8"));
                
                // Update name if needed
                String newName = signconf.getProperty("NAME");
                if (newName == null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("No name in config");
                    }
                    newName = "UnamedWorker" + workerId;
                }
                    
                final File oldNameFile = getNameFile(workerId);
                if (oldNameFile.exists()) {
                    String oldName = FileUtils.readFileToString(oldNameFile);

                    if (!newName.equals(oldName)) {
                        final File newIdFile = getIdFile(newName);
                        if (newIdFile.exists()) {
                            throw new FileBasedDatabaseException("Duplicated name: \"" + newName + "\"");
                        }
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("New name: " + newName + ", oldName: " + oldName);
                        }

                        wcdb.setSignerName(newName);
                        final File oldIdFile = getIdFile(oldName);
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Rename from " + oldIdFile.getName() + " to " + newIdFile.getName());
                        }
                        if (!oldIdFile.renameTo(newIdFile)) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Old ID file " + oldIdFile.getAbsolutePath() + " exists: " + oldIdFile.exists());
                                LOG.debug("New ID file " + newIdFile.getAbsolutePath() + " exists: " + newIdFile.exists());
                            }
                            throw new FileBasedDatabaseException("Could not rename from " + oldName + " to " + newName);
                        }
                        writeName(workerId, newName);
                    }
                } else {
                    final File newIdFile = getIdFile(newName);
                    if (newIdFile.exists()) {
                        throw new FileBasedDatabaseException("Duplicated name: \"" + newName + "\"");
                    }
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("New name: " + newName);
                    }
                    wcdb.setSignerName(newName);
                    writeName(workerId, newName);
                    writeID(newName, workerId);
                }
                
                // Update type if needed
                String newType = signconf.getProperty("TYPE");
                if (newType == null) {
                    newType = WorkerType.UNKNOWN.name();
                }
                try {
                    WorkerType.valueOf(newType);
                } catch (IllegalArgumentException ex) {
                    LOG.error("Unable to set worker type: " + ex.getLocalizedMessage());
                    newType = WorkerType.UNKNOWN.name();
                }
                WorkerType wt = WorkerType.valueOf(newType);
                    
                final File oldTypeFile = getTypeFile(workerId);
                if (oldTypeFile.exists()) {
                    String oldType = FileUtils.readFileToString(oldTypeFile);

                    if (!newType.equals(oldType)) {
                        final File typeFolder = getTypeFolder(wt);
                        createFolder(typeFolder);
                        
                        final File newTypeFile = new File(typeFolder, TYPE_PREFIX + workerId + SUFFIX);
                        if (newTypeFile.exists()) {
                            LOG.warn("Type file already existed: " + newTypeFile.getAbsolutePath());
                        } else {
                            if (!newTypeFile.createNewFile()) {
                                throw new FileBasedDatabaseException("Could not create new type file: " + newTypeFile.getAbsolutePath());
                            }
                        }
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("New type: " + newType + ", oldType: " + oldType);
                        }

                        wcdb.setSignerType(wt);

                        final File oldTypeFolder = getTypeFolder(WorkerType.valueOf(oldType));
                        final File oldTypeTypeFile = new File(oldTypeFolder, TYPE_PREFIX + workerId + SUFFIX);
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Removing old type type file " + oldTypeTypeFile.getName());
                        }
                        if (!oldTypeTypeFile.delete()) {
                            throw new FileBasedDatabaseException("Could not delete old type type file: " + oldTypeTypeFile.getAbsolutePath());
                        }
                        writeType(workerId, newType);
                    }
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("New type: " + newType);
                    }
                    wcdb.setSignerType(wt);
                    writeType(workerId, newType);
                    
                    final File typeFolder = getTypeFolder(wt);
                    createFolder(typeFolder);

                    final File newTypeFile = new File(typeFolder, TYPE_PREFIX + workerId + SUFFIX);
                    if (newTypeFile.exists()) {
                        LOG.warn("Type file already existed: " + newTypeFile.getAbsolutePath());
                    } else {
                        if (!newTypeFile.createNewFile()) {
                            throw new FileBasedDatabaseException("Could not create new type file: " + newTypeFile.getAbsolutePath());
                        }
                    }
                }

                writeData(workerId, wcdb);
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
                
                File nameFile = getNameFile(workerId);
                if (nameFile.exists()) {
                    String name = FileUtils.readFileToString(nameFile);
                    File idFile = getIdFile(name);
                    if (!idFile.delete()) {
                        LOG.error("File could not be removed: " + idFile.getAbsolutePath());
                    }
                    if (!nameFile.delete()) {
                        LOG.error("File could not be removed: " + idFile.getAbsolutePath());
                    }
                }
                
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
            final String data = FileUtils.readFileToString(file, "UTF-8");
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
            out.write(dataStore.getSignerConfigData().getBytes("UTF-8"));
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

    @Override
    public List<Integer> findAllIds() {
        synchronized (manager) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(">findAllIds()");
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
    public List<Integer> findAllIds(WorkerType workerType) {
        synchronized (manager) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(">findAllIds(" + workerType + ")");
            }
            final LinkedList<Integer> result = new LinkedList<>();

            if (workerType == null) {
                workerType = WorkerType.UNKNOWN;
            }
            
            File typeFolder = getTypeFolder(workerType);
            if (typeFolder.exists()) {
                try (DirectoryStream<Path> stream = Files.newDirectoryStream(typeFolder.toPath(), TYPE_PREFIX + "*" + SUFFIX)) {
                    Iterator<Path> iterator = stream.iterator();
                    while (iterator.hasNext()) {
                        final String fileName = iterator.next().toFile().getName();
                        final String id = fileName.substring(TYPE_PREFIX.length(), fileName.length() - SUFFIX.length());
                        result.add(Integer.parseInt(id));
                    }
                } catch (IOException ex) {
                    LOG.error("Querying all workers failed", ex);
                }
            }
            return result;
        }
    }

    @Override
    public void populateNameColumn() { // TODO Check schema.version etc
        synchronized (manager) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(">populateNameColumn()");
            }
            List<Integer> list = findAllWithoutName();

            if (list.isEmpty()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Found no worker configurations without name column");
                }
            } else {
                LOG.info("Found " + list.size() + " worker configurations without name column");
                for (Integer id : list) {
                    WorkerConfig config = getWorkerConfig(id, false);

                    String name = config.getProperty("NAME");
                    if (name == null) {
                        name = "UpgradedWorker-" + id;
                    }
                    LOG.info("Upgrading worker configuration " + id + " with name " + name);
                    try {
                        writeName(id, name);
                        writeID(name, id);
                    } catch (IOException ex) {
                        LOG.error("Adding name file failed for worker configuration " + id, ex);
                    }
                }
            }
        }
    }
    
    private void writeName(int id, String name) throws IOException {
        final File file = getNameFile(id);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Write name \"" + name + "\" for ID " + id + " to " + file.getName());
        }
        FileUtils.writeStringToFile(file, name, "UTF-8"); // TODO: Replace with one that fd.sync()
    }
    
    private void writeID(String name, int id) throws IOException {
        final File file = getIdFile(name);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Write ID " + id + " for name \"" + name + "\" to " + file.getName());
        }
        FileUtils.writeStringToFile(file, String.valueOf(id), "UTF-8");  // TODO: Replace with one that fd.sync()
    }
    
    private void writeType(int id, String type) throws IOException {
        final File file = getTypeFile(id);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Write type \"" + type + "\" for ID " + id + " to " + file.getName());
        }
        FileUtils.writeStringToFile(file, type, "UTF-8"); // TODO: Replace with one that fd.sync()
    }

    private List<Integer> findAllWithoutName() {
        assert Thread.holdsLock(manager);
        if (LOG.isDebugEnabled()) {
            LOG.debug(">findAllWithoutName()");
        }
        final LinkedList<Integer> result = new LinkedList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(folder.toPath(), DATA_PREFIX + "*" + SUFFIX)) {
            Iterator<Path> iterator = stream.iterator();
            while (iterator.hasNext()) {
                final String fileName = iterator.next().toFile().getName();
                final int id = Integer.parseInt(fileName.substring(DATA_PREFIX.length(), fileName.length() - SUFFIX.length()));
                final File nameFile = getNameFile(id);
                
                if (!nameFile.exists()) {
                    result.add(id);
                }
                
            }
        } catch (IOException ex) {
            LOG.error("Querying all workers failed", ex);
        }
        return result;
    }
    
    @Override
    public int findId(String workerName) throws NoSuchWorkerException {
        synchronized (manager) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(">findId(" + workerName + ")");
            }
            final int result;
            final File idFile = getIdFile(workerName);
            if (idFile.exists()) {
                try {
                    result = Integer.parseInt(FileUtils.readFileToString(idFile, "UTF-8"));
                } catch (IOException ex) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Unable to read " + idFile.getAbsolutePath() + ": " + ex.getMessage());
                    }
                    throw new NoSuchWorkerException(workerName);
                }
            } else {
                throw new NoSuchWorkerException(workerName);
            }
            return result;
        }
    }

    private File getNameFile(final int workerId) {
        return new File(folder, NAME_PREFIX + String.valueOf(workerId) + SUFFIX);
    }

    private File getIdFile(final String name) {
        try {
            return new File(folder, ID_PREFIX + Base64.toBase64String(name.getBytes("UTF-8")) + SUFFIX);
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException("Unable to UTF-8 encode", ex);
        }
    }
    
    private File getTypeFile(final int workerId) {
        return new File(folder, TYPE_PREFIX + String.valueOf(workerId) + SUFFIX);
    }
    
    private File getTypeFolder(final WorkerType workerType) {
        return new File(folder, TYPE_FOLDER_PREFIX + workerType.name());
    }
    private void createFolder(final File folder) throws FileBasedDatabaseException {
        if (!folder.exists() && !folder.mkdir()) {
            throw new FileBasedDatabaseException("Unable to create folder " + folder.getAbsolutePath());
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

                // Create folder for the type
                final File folderUnknown = getTypeFolder(WorkerType.UNKNOWN);
                createFolder(folderUnknown);

                // Put a marker file in the "signertype-UNKNOWN" folder for all existing worker
                // If this fails for a worker then it will not be available in queries for WorkerType.UNKNOWN
                // but will still be in the list of all workers so not fatal but manual upgrade for that worker
                // will be needed (i.e. setting TYPE=something).
                List<Integer> allIds = findAllIds();
                for (Integer id : allIds) {
                    File file = new File(folderUnknown, TYPE_PREFIX + String.valueOf(id) + SUFFIX);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Setting worker type to " + WorkerType.UNKNOWN + " for worker ID " + id);
                    }
                    try {
                        if (!file.createNewFile() && !file.exists()) {
                            LOG.error("Unable to create file " + file + ". This worker will not be upgraded.");
                        }
                        try {
                            writeType(id, WorkerType.UNKNOWN.name());
                        } catch (IOException ex) {
                            LOG.error("Adding type file failed for worker configuration " + id, ex);
                        }
                    } catch (IOException ex) {
                        LOG.error("Unable to create file " + file + ". This worker will not be upgraded: " + ex.getMessage(), ex);
                    }
                }

                // Store the new version that we have upgraded to
                manager.getMetadata().setProperty(TABLE_VERSION_PROPERTY, String.valueOf(TABLE_VERSION_10));
                manager.storeMetadata();
                LOG.info("Finished table upgrade");
            }
        }
    }
}
