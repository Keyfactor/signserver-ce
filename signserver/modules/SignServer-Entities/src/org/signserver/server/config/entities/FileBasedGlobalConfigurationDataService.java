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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Map.Entry;
import java.util.*;
import org.apache.log4j.Logger;
import org.signserver.common.FileBasedDatabaseException;
import org.signserver.server.nodb.FileBasedDatabaseManager;

/**
 * Entity Service class that acts as migration layer for
 * the old Home Interface for the GlobalConfigurationData Entity Bean
 * 
 * Contains about the same methods as the EJB 2 entity beans home interface.
 *
 * @version $Id$
 */
public class FileBasedGlobalConfigurationDataService implements IGlobalConfigurationDataService {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(FileBasedGlobalConfigurationDataService.class);

    private final FileBasedDatabaseManager manager;
    private File file;
    
    private static final int SCHEMA_VERSION = 1;

    public FileBasedGlobalConfigurationDataService(FileBasedDatabaseManager manager) {
        this.manager = manager;
        this.file = new File(manager.getDataFolder(), "globalconfigdata.dat");
    }

    @Override
    public void setGlobalProperty(String completekey, String value) throws FileBasedDatabaseException {
        try {
            synchronized (manager) {
                Map<String, GlobalConfigurationDataBean> dataStore = loadData();
                GlobalConfigurationDataBean data = dataStore.get(completekey);
                if (data == null) {
                    data = new GlobalConfigurationDataBean();
                    data.setPropertyKey(completekey);
                    data.setPropertyValue(value);
                    dataStore.put(completekey, data);
                } else {
                    data.setPropertyValue(value);
                }
                writeData(dataStore);
            }
        } catch (IOException ex) {
            throw new FileBasedDatabaseException("Could not load from or write data to file based database", ex);
        }
    }

    @Override
    public boolean removeGlobalProperty(String completekey) {
        boolean retval = false;
        try {
            synchronized (manager) {
                Map<String, GlobalConfigurationDataBean> dataStore = loadData();
                GlobalConfigurationDataBean data = dataStore.remove(completekey);
                if (data != null) {
                    writeData(dataStore);
                    retval = true;
                }
            }
        } catch (IOException ex) {
            throw new FileBasedDatabaseException("Could not load from or write data to file based database", ex);
        }
        return retval;
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<GlobalConfigurationDataBean> findAll() {
        try {
            Map<String, GlobalConfigurationDataBean> dataStore;
            synchronized (manager) {
                dataStore = loadData();
            }
            return new LinkedList<GlobalConfigurationDataBean>(dataStore.values());
        } catch (IOException ex) {
            LOG.error("Could not load data from file based database: " + ex.getMessage());
            return Collections.emptyList();
        }
    }
    
    private Map<String, GlobalConfigurationDataBean> loadData() throws IOException {
        assert Thread.holdsLock(manager);
        checkSchemaVersion();
        
        final HashMap<String, GlobalConfigurationDataBean> result = new HashMap<String, GlobalConfigurationDataBean>();
        if (file.length() != 0) {
            final Properties properties = new Properties();
            FileInputStream in = null;
            try {
                in = new FileInputStream(file);
                properties.loadFromXML(in);
                for (String key : properties.stringPropertyNames()) {
                    final GlobalConfigurationDataBean bean = new GlobalConfigurationDataBean();
                    bean.setPropertyKey(key);
                    bean.setPropertyValue(properties.getProperty(key));
                    result.put(key, bean);
                }
            } finally {
                if (in != null) {
                    try {
                        in.close();
                    } catch (IOException ignored) {} // NOPMD
                }
            }
        }
        return result;
    }

    private void writeData(Map<String, GlobalConfigurationDataBean> dataStore) throws IOException {
        assert Thread.holdsLock(manager);
        checkSchemaVersion();
        
        final Properties properties = new Properties();
        for (Entry<String, GlobalConfigurationDataBean> entry : dataStore.entrySet()) {
            properties.setProperty(entry.getValue().getPropertyKey(), entry.getValue().getPropertyValue());
        }
        
        FileOutputStream out = null;
        try {
            out = new FileOutputStream(file);
            properties.storeToXML(out, "DO NOT EDIT THIS FILE MANUALLY (while SignServer is running)", "UTF-8");
            out.flush();
            out.getFD().sync();
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }

    private void checkSchemaVersion() {
        if (manager.getSchemaVersion() != SCHEMA_VERSION) {
            throw new FileBasedDatabaseException("Unsupported schema version: " + manager.getSchemaVersion());
        }
    }
}
