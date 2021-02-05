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
package org.signserver.server.nodb;

import java.io.File;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.signserver.common.CompileTimeSettings;
import org.signserver.common.FileBasedDatabaseException;

/**
 * Manages the file based database.
 *
 * The only instance of this class can be used for synchronizing access to the 
 * file based database.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class FileBasedDatabaseManager {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(FileBasedDatabaseManager.class);
    
    private static final FileBasedDatabaseManager instance = new FileBasedDatabaseManager(new File(CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.FILEBASED_DB_FOLDER)));
    
    /** Name used for this database as database.name in signserver_deploy.properties. */
    private static final String DATABASE_NAME = "nodb";
    
    private static final int CURRENT_SCHEMA_VERSION = 1;
    private static final String SCHEMA_VERSION = "schema.version";
    
    private File dataFolder;
    
    private Properties metadata;
    private MetaDataService dataService;
    private boolean initialized;
    
    private FileBasedDatabaseManager(File dataFolder) {
        this.dataFolder = dataFolder;
        this.dataService = new MetaDataService(this);
    }

    public static FileBasedDatabaseManager getInstance() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Returning instance: " + instance);
        }
        return instance;
    }

    public File getDataFolder() {
        return dataFolder;
    }
    
    public Properties getMetadata() {
        if (metadata == null) {
            metadata = dataService.getProperties();
        }
        return metadata;
    }

    /**
     * Write out the meta data to disk.
     */
    public void storeMetadata() {
        synchronized (this) {
            final Properties properties = getMetadata();
            dataService.setProperties(properties);
        }
    }
    
    private Properties getMetadataTemplate() {
        final Properties result = new Properties();
        result.setProperty(SCHEMA_VERSION, String.valueOf(CURRENT_SCHEMA_VERSION));
        return result;
    }
    
    public void initialize() throws FileBasedDatabaseException {
        synchronized (this) {
            LOG.debug(">initialize");
            
            // If we don't have any metadata, create initial database structure
            // Currently just an empty folder except for the metadata file
            // Fail if there are other files in the folder as that could be 
            // database files with a different schema version that we would not
            // be able to parse correctly
            Properties meta = getMetadata();
            if (meta == null || meta.isEmpty()) {
                LOG.debug("No existing metadata");
                String[] files = dataFolder.list();
                if (files == null || files.length != 0) {
                    throw new FileBasedDatabaseException("Refusing to create initial database structure as the folder is not empty: " + dataFolder.getAbsolutePath());
                }
                dataService.setProperties(getMetadataTemplate());
            } else {
                LOG.debug("Found metadata: " + meta);
            }
            initialized = true;
        }
    }
    
    public int getSchemaVersion() throws FileBasedDatabaseException {
        if (!initialized) {
            initialize();
        }
        return Integer.parseInt(getMetadata().getProperty(SCHEMA_VERSION, "0"));
    }

    /**
     * @return True if SignServer is configured to run without database
     */
    public boolean isUsed() {
        return DATABASE_NAME.equalsIgnoreCase(CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.DATABASE_NAME));
    }

    /**
     * @return List of errors preventing the file based database from functioning
     */
    public List<String> getFatalErrors() {
        final LinkedList<String> result = new LinkedList<>();
        if (!initialized) {
            result.add("File based database not initialized. See servlet log for error during startup.");
        }
        if (!dataFolder.isDirectory()) {
            result.add("Location configured as database.nodb.location is not a folder");
        }
        final File[] files = dataFolder.listFiles();
        if (files == null || files.length < 1) {
            result.add("File based database folder is empty");
        }
        return result;
    }
}
