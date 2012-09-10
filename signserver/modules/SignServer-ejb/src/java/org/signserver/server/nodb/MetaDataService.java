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

import java.io.*;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.signserver.common.FileBasedDatabaseException;

/**
 * Responsible of loading meta data about the file based database.
 *
 * @version $Id$
 */
public class MetaDataService {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(MetaDataService.class);

    private final FileBasedDatabaseManager manager;
    private File file;

    public MetaDataService(FileBasedDatabaseManager manager) {
        this.manager = manager;
        this.file = new File(manager.getDataFolder(), "metadata.dat");
    }
    
    /**
     * @return properties in the file or null if no file
     * @throws FileBasedDatabaseException 
     */
    public Properties getProperties() throws FileBasedDatabaseException {
        Properties result;
        try {
            synchronized (manager) {
                result = loadData();
            }
        } catch (IOException ex) {
            throw new FileBasedDatabaseException("Could not metadata from file based database", ex);
        }
        return result;
    }

    public void setProperties(final Properties properties) throws FileBasedDatabaseException {
        try {
            synchronized (manager) {
                writeData(properties);
            }
        } catch (IOException ex) {
            throw new FileBasedDatabaseException("Could not write metadata to file based database", ex);
        }
    }
    
    private Properties loadData() throws IOException {
        assert Thread.holdsLock(manager);
        Properties result = new Properties();
        
        FileInputStream in = null;
        try {
            in = new FileInputStream(file);
            result.loadFromXML(in);
        } catch (FileNotFoundException ex) {
            result = null;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
        
        return result;
    }

    private void writeData(Properties properties) throws IOException {
        assert Thread.holdsLock(manager);
        
        FileOutputStream out = null;
        try {
            out = new FileOutputStream(file);
            properties.storeToXML(out, null, "UTF-8");
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }
}
